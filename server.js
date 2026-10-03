
// ============================================================
// VENERA · VIDNOE — server
// ============================================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || 'database.db';

let db = null;
let SQL = null;

function saveDb(){
  try {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  } catch(e){ console.error('DB save error:', e.message); }
}

function run(sql, params){
  const stmt = db.prepare(sql);
  stmt.bind(params || []);
  stmt.step();
  stmt.free();
  saveDb();
}
function get(sql, params){
  const stmt = db.prepare(sql);
  stmt.bind(params || []);
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  return row;
}
function all(sql, params){
  const stmt = db.prepare(sql);
  stmt.bind(params || []);
  const rows = [];
  while(stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

async function initDatabase(){
  SQL = await initSqlJs();

  if(fs.existsSync(DB_FILE)){
    const buf = fs.readFileSync(DB_FILE);
    db = new SQL.Database(new Uint8Array(buf));
    console.log('DB loaded from file');
  } else {
    db = new SQL.Database();
    console.log('New DB created');
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL,
      name TEXT NOT NULL,
      surname TEXT,
      phone TEXT NOT NULL UNIQUE,
      email TEXT,
      telegram TEXT,
      pin_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS slots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      available INTEGER DEFAULT 1,
      UNIQUE(date, time)
    );
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      service TEXT NOT NULL,
      note TEXT,
      status TEXT DEFAULT 'pending',
      price INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_target TEXT NOT NULL,
      title TEXT NOT NULL,
      text TEXT NOT NULL,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
  saveDb();
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'venera-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const DEFAULT_TIMES = ['10:00','12:30','15:00','18:00','20:00','22:00'];
const PROMO_CODE = '162635';

function isWeekend(dateStr){
  const d = new Date(dateStr + 'T00:00:00');
  return d.getDay() === 0 || d.getDay() === 6;
}
function normalizePhone(p){ return String(p).replace(/\D/g,''); }
function requireAuth(role){
  return (req, res, next) => {
    if(!req.session.user) return res.status(401).json({ error: 'Not authorized' });
    if(role && req.session.user.role !== role) return res.status(403).json({ error: 'No access' });
    next();
  };
}
function addNotif(target, title, text){
  run('INSERT INTO notifications (user_target, title, text) VALUES (?,?,?)',
    [target, title, text]);
}

// AUTH
app.get('/api/state', (req, res) => {
  const admin = get("SELECT id, name, phone FROM users WHERE role='admin' LIMIT 1");
  const lockRaw = get("SELECT value FROM settings WHERE key='promo_lock'");
  const lock = lockRaw ? JSON.parse(lockRaw.value) : { attempts: 0, lockedUntil: null };
  res.json({ hasAdmin: !!admin, promoLock: lock, currentUser: req.session.user || null });
});

app.post('/api/promo', (req, res) => {
  const { code } = req.body;
  const lockRaw = get("SELECT value FROM settings WHERE key='promo_lock'");
  const lock = lockRaw ? JSON.parse(lockRaw.value) : { attempts: 0, lockedUntil: null };

  if(lock.lockedUntil && lock.lockedUntil > Date.now()){
    return res.status(429).json({ error: 'locked', lockedUntil: lock.lockedUntil });
  }
  if(code === PROMO_CODE){
    run("INSERT OR REPLACE INTO settings (key,value) VALUES ('promo_lock',?)",
      [JSON.stringify({ attempts: 0, lockedUntil: null })]);
    const admin = get("SELECT id FROM users WHERE role='admin' LIMIT 1");
    return res.json({ ok: true, hasAdmin: !!admin });
  }
  lock.attempts = (lock.attempts || 0) + 1;
  if(lock.attempts >= 6){
    lock.lockedUntil = Date.now() + 10 * 60 * 1000;
    lock.attempts = 0;
  }
  run("INSERT OR REPLACE INTO settings (key,value) VALUES ('promo_lock',?)", [JSON.stringify(lock)]);
  res.status(400).json({ error: 'wrong', left: 6 - lock.attempts, lockedUntil: lock.lockedUntil });
});

app.post('/api/register', async (req, res) => {
  const { role, name, surname, phone, email, telegram, pin } = req.body;
  if(!name || !phone || !pin) return res.status(400).json({ error: 'Fill all fields' });
  if(!/^\d{6}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 6 digits' });

  const norm = normalizePhone(phone);
  const exists = get('SELECT id FROM users WHERE phone = ?', [norm]);
  if(exists) return res.status(400).json({ error: 'Phone already registered' });

  if(role === 'admin'){
    const admin = get("SELECT id FROM users WHERE role='admin' LIMIT 1");
    if(admin) return res.status(400).json({ error: 'Admin already exists' });
  }

  const hash = await bcrypt.hash(pin, 10);
  run('INSERT INTO users (role,name,surname,phone,email,telegram,pin_hash) VALUES (?,?,?,?,?,?,?)',
    [role, name, surname || null, norm, email || null, telegram || null, hash]);

  const user = get('SELECT id FROM users WHERE phone = ?', [norm]);
  req.session.user = { id: user.id, role, name };

  if(role === 'admin'){
    addNotif('admin', 'Вы — новый админ', 'Теперь вы управляете студией');
  } else {
    addNotif('admin', 'Новый клиент', `${name} (${norm}) зарегистрировался`);
  }
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/login', async (req, res) => {
  const { phone, pin } = req.body;
  if(!phone || !pin) return res.status(400).json({ error: 'Enter phone and PIN' });
  if(!/^\d{6}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 6 digits' });

  const norm = normalizePhone(phone);
  const user = get('SELECT * FROM users WHERE phone = ?', [norm]);
  if(!user) return res.status(404).json({ error: 'Account not found' });

  const ok = await bcrypt.compare(pin, user.pin_hash);
  if(!ok) return res.status(400).json({ error: 'Wrong PIN' });

  req.session.user = { id: user.id, role: user.role, name: user.name };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/admin-login', async (req, res) => {
  const { pin } = req.body;
  const admin = get("SELECT * FROM users WHERE role='admin' LIMIT 1");
  if(!admin) return res.status(404).json({ error: 'No admin' });
  const ok = await bcrypt.compare(pin, admin.pin_hash);
  if(!ok) return res.status(400).json({ error: 'Wrong PIN' });
  req.session.user = { id: admin.id, role: 'admin', name: admin.name };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// SLOTS
function ensureSlotsForDate(date){
  if(isWeekend(date)) return;
  const existing = get('SELECT COUNT(*) as c FROM slots WHERE date = ?', [date]);
  if(existing && existing.c === 0){
    DEFAULT_TIMES.forEach(t => {
      run('INSERT OR IGNORE INTO slots (date,time,available) VALUES (?,?,1)', [date, t]);
    });
  }
}

app.get('/api/slots/:date', requireAuth(), (req, res) => {
  const { date } = req.params;
  if(isWeekend(date)) return res.json({ slots: [] });
  ensureSlotsForDate(date);
  const slots = all('SELECT * FROM slots WHERE date = ? ORDER BY time', [date]);
  const bookings = all("SELECT time FROM bookings WHERE date = ? AND status != 'cancelled'", [date]);
  const busyTimes = bookings.map(b => b.time);
  res.json({ slots: slots.map(s => ({
    time: s.time,
    status: !s.available ? 'closed' : busyTimes.includes(s.time) ? 'busy' : 'free'
  })) });
});

// BOOKINGS
app.post('/api/bookings', requireAuth('client'), (req, res) => {
  const { date, time, service, note } = req.body;
  const clientId = req.session.user.id;

  const existing = get("SELECT id FROM bookings WHERE date=? AND time=? AND status!='cancelled'", [date, time]);
  if(existing) return res.status(400).json({ error: 'Time already taken' });

  const slot = get('SELECT * FROM slots WHERE date=? AND time=?', [date, time]);
  if(!slot || !slot.available) return res.status(400).json({ error: 'Slot closed' });

  run('INSERT INTO bookings (client_id,date,time,service,note,status) VALUES (?,?,?,?,?,?)',
    [clientId, date, time, service, note || null, 'pending']);

  addNotif('admin', 'Новая запись', `${req.session.user.name} — ${date} в ${time}, ${service}`);
  addNotif('client:' + clientId, 'Запись создана', `${date} в ${time} — ${service}`);
  res.json({ ok: true });
});

app.get('/api/bookings/my', requireAuth('client'), (req, res) => {
  const list = all('SELECT * FROM bookings WHERE client_id = ? ORDER BY date DESC, time DESC',
    [req.session.user.id]);
  res.json({ bookings: list });
});

app.post('/api/bookings/:id/cancel', requireAuth(), (req, res) => {
  const { id } = req.params;
  const b = get('SELECT * FROM bookings WHERE id = ?', [id]);
  if(!b) return res.status(404).json({ error: 'Not found' });

  if(req.session.user.role === 'client' && b.client_id !== req.session.user.id){
    return res.status(403).json({ error: 'No access' });
  }
  run("UPDATE bookings SET status='cancelled' WHERE id = ?", [id]);

  if(req.session.user.role === 'client'){
    addNotif('admin', 'Клиент отменил запись', `${b.date} в ${b.time}`);
  } else {
    addNotif('client:' + b.client_id, 'Мастер отменил вашу запись',
      `${b.date} в ${b.time}. Свяжитесь с мастером.`);
  }
  res.json({ ok: true });
});

app.get('/api/admin/bookings/:date', requireAuth('admin'), (req, res) => {
  const { date } = req.params;
  const list = all(`
    SELECT b.*, u.name AS client_name, u.phone AS client_phone
    FROM bookings b JOIN users u ON u.id = b.client_id
    WHERE b.date = ? AND b.status != 'cancelled'
    ORDER BY b.time
  `, [date]);
  res.json({ bookings: list });
});

app.get('/api/admin/counts/:year/:month', requireAuth('admin'), (req, res) => {
  const { year, month } = req.params;
  const prefix = `${year}-${String(month).padStart(2,'0')}`;
  const rows = all(`
    SELECT date, COUNT(*) as c FROM bookings
    WHERE date LIKE ? AND status != 'cancelled'
    GROUP BY date
  `, [prefix + '%']);
  const counts = {};
  rows.forEach(r => counts[r.date] = r.c);
  res.json({ counts });
});

app.post('/api/admin/bookings/:id/done', requireAuth('admin'), (req, res) => {
  const { id } = req.params;
  const { price } = req.body;
  const b = get('SELECT * FROM bookings WHERE id = ?', [id]);
  if(!b) return res.status(404).json({ error: 'Not found' });

  run("UPDATE bookings SET status='done', price=? WHERE id=?", [parseInt(price) || 0, id]);
  addNotif('client:' + b.client_id, 'Спасибо за визит!', `Сумма: ${price} ₽. Ждём вас снова!`);
  res.json({ ok: true });
});

app.post('/api/admin/bookings/:id/move', requireAuth('admin'), (req, res) => {
  const { id } = req.params;
  const { date, time } = req.body;
  const b = get('SELECT * FROM bookings WHERE id = ?', [id]);
  if(!b) return res.status(404).json({ error: 'Not found' });

  run('UPDATE bookings SET date=?, time=? WHERE id=?', [date, time, id]);
  addNotif('client:' + b.client_id, 'Запись перенесена', `Новое время: ${date} в ${time}`);
  res.json({ ok: true });
});

app.post('/api/admin/bookings/:id/cancel', requireAuth('admin'), (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  const b = get('SELECT * FROM bookings WHERE id = ?', [id]);
  if(!b) return res.status(404).json({ error: 'Not found' });

  run("UPDATE bookings SET status='cancelled' WHERE id=?", [id]);
  const text = message
    ? `Запись на ${b.date} в ${b.time} отменена. Сообщение мастера: ${message}`
    : `Запись на ${b.date} в ${b.time} отменена. Свяжитесь с мастером.`;
  addNotif('client:' + b.client_id, 'Мастер отменил вашу запись', text);
  res.json({ ok: true });
});

app.post('/api/admin/bookings/manual', requireAuth('admin'), (req, res) => {
  const { client_id, date, time, service } = req.body;
  run('INSERT INTO bookings (client_id,date,time,service,note,status) VALUES (?,?,?,?,?,?)',
    [client_id, date, time, service, 'Записан мастером', 'pending']);
  addNotif('client:' + client_id, 'Мастер записал вас', `${date} в ${time} — ${service}`);
  res.json({ ok: true });
});

// SLOTS ADMIN
app.post('/api/admin/slots/toggle', requireAuth('admin'), (req, res) => {
  const { date, time } = req.body;
  ensureSlotsForDate(date);
  const s = get('SELECT * FROM slots WHERE date=? AND time=?', [date, time]);
  if(!s) return res.status(404).json({ error: 'Slot not found' });
  run('UPDATE slots SET available=? WHERE id=?', [s.available ? 0 : 1, s.id]);
  res.json({ ok: true });
});
app.post('/api/admin/slots/remove', requireAuth('admin'), (req, res) => {
  const { date, time } = req.body;
  run('DELETE FROM slots WHERE date=? AND time=?', [date, time]);
  res.json({ ok: true });
});
app.post('/api/admin/slots/add', requireAuth('admin'), (req, res) => {
  const { date, time } = req.body;
  if(!/^\d{2}:\d{2}$/.test(time)) return res.status(400).json({ error: 'Format HH:MM' });
  run('INSERT OR IGNORE INTO slots (date,time,available) VALUES (?,?,1)', [date, time]);
  res.json({ ok: true });
});

// CLIENTS
app.get('/api/admin/clients', requireAuth('admin'), (req, res) => {
  const clients = all("SELECT id,name,phone,telegram FROM users WHERE role='client'");
  const result = clients.map(c => {
    const done = get("SELECT date FROM bookings WHERE client_id=? AND status='done' ORDER BY date DESC LIMIT 1", [c.id]);
    const inc = get("SELECT COALESCE(SUM(price),0) as s FROM bookings WHERE client_id=? AND status='done'", [c.id]);
    const future = get("SELECT date,time FROM bookings WHERE client_id=? AND status='pending' ORDER BY date,time LIMIT 1", [c.id]);
    return {
      ...c,
      last_date: done ? done.date : null,
      income: inc ? inc.s : 0,
      sort_key: future ? future.date + future.time : '9999'
    };
  }).sort((a,b) => a.sort_key.localeCompare(b.sort_key));
  res.json({ clients: result });
});

app.get('/api/admin/clients/:id', requireAuth('admin'), (req, res) => {
  const { id } = req.params;
  const client = get('SELECT id,name,phone,telegram FROM users WHERE id=?', [id]);
  if(!client) return res.status(404).json({ error: 'Not found' });
  const bookings = all('SELECT * FROM bookings WHERE client_id=? ORDER BY date DESC, time DESC', [id]);
  const notes = all('SELECT * FROM notes WHERE client_id=? ORDER BY id DESC', [id]);
  res.json({ client, bookings, notes });
});

app.post('/api/admin/notes', requireAuth('admin'), (req, res) => {
  const { client_id, text } = req.body;
  if(!text) return res.status(400).json({ error: 'Empty' });
  run('INSERT INTO notes (client_id,text) VALUES (?,?)', [client_id, text]);
  res.json({ ok: true });
});
app.post('/api/admin/notes/:id/delete', requireAuth('admin'), (req, res) => {
  run('DELETE FROM notes WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// FINANCE
app.get('/api/admin/finance/:mode', requireAuth('admin'), (req, res) => {
  const { mode } = req.params;
  const done = all("SELECT * FROM bookings WHERE status='done'");

  if(mode === 'day'){
    const today = new Date().toISOString().split('T')[0];
    const todayB = done.filter(b => b.date === today);
    const sum = todayB.reduce((s,b) => s + (b.price || 0), 0);
    return res.json({ mode, sum, count: todayB.length, items: todayB, today });
  }
  if(mode === 'month'){
    const now = new Date();
    const ym = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
    const prev = `${now.getFullYear()-1}-${String(now.getMonth()+1).padStart(2,'0')}`;
    const monthB = done.filter(b => b.date.startsWith(ym));
    const prevB = done.filter(b => b.date.startsWith(prev));
    const sum = monthB.reduce((s,b) => s + (b.price || 0), 0);
    const prevSum = prevB.reduce((s,b) => s + (b.price || 0), 0);
    const byDay = {};
    monthB.forEach(b => { byDay[b.date] = (byDay[b.date] || 0) + (b.price || 0); });
    return res.json({ mode, sum, prevSum, count: monthB.length, byDay, ym });
  }
  if(mode === 'year'){
    const now = new Date();
    const year = String(now.getFullYear());
    const prevYear = String(now.getFullYear()-1);
    const yearB = done.filter(b => b.date.startsWith(year));
    const prevB = done.filter(b => b.date.startsWith(prevYear));
    const sum = yearB.reduce((s,b) => s + (b.price || 0), 0);
    const prevSum = prevB.reduce((s,b) => s + (b.price || 0), 0);
    const byMonth = {};
    for(let m=1; m<=12; m++){
      const key = `${year}-${String(m).padStart(2,'0')}`;
      byMonth[m] = yearB.filter(b => b.date.startsWith(key)).reduce((s,b) => s + (b.price || 0), 0);
    }
    return res.json({ mode, sum, prevSum, count: yearB.length, byMonth, year });
  }
  res.status(400).json({ error: 'Bad mode' });
});

// NOTIFICATIONS
app.get('/api/notifications', requireAuth(), (req, res) => {
  const target = req.session.user.role === 'admin' ? 'admin' : 'client:' + req.session.user.id;
  const list = all('SELECT * FROM notifications WHERE user_target=? ORDER BY id DESC LIMIT 50', [target]);
  const unread = list.filter(n => !n.is_read).length;
  res.json({ list, unread });
});
app.post('/api/notifications/read', requireAuth(), (req, res) => {
  const target = req.session.user.role === 'admin' ? 'admin' : 'client:' + req.session.user.id;
  run('UPDATE notifications SET is_read=1 WHERE user_target=?', [target]);
  res.json({ ok: true });
});

// MESSAGES
app.post('/api/messages', requireAuth('client'), (req, res) => {
  const { text } = req.body;
  if(!text) return res.status(400).json({ error: 'Empty' });
  run('INSERT INTO messages (client_id,text) VALUES (?,?)', [req.session.user.id, text]);
  addNotif('admin', 'Сообщение от клиента',
    `${req.session.user.name}: ${text.slice(0,60)}${text.length>60?'...':''}`);
  res.json({ ok: true });
});

// START
initDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Venera server started on port ${PORT}`);
  });
}).catch(err => {
  console.error('Start error:', err);
  process.exit(1);
});
