import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import nodemailer from 'nodemailer';
import { stringify } from 'csv-stringify';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const { Pool } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const ADMIN_PASS = process.env.ADMIN_PASS || '12041998avril1999A';

const DATABASE_URL = process.env.DATABASE_URL;
if(!DATABASE_URL){
  console.error('❌ No DATABASE_URL provided. Set it in environment variables.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      withdraw_code_hash TEXT,
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT,
      password_hash TEXT NOT NULL,
      balances JSONB DEFAULT '{"EUR":0,"BTC":0,"ETH":0,"USDT":0}'::jsonb,
      banned BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      messages JSONB DEFAULT '[]'::jsonb,
      updated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(username)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      username TEXT PRIMARY KEY,
      token TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      type TEXT,
      pair TEXT,
      amount NUMERIC,
      currency TEXT,
      value_eur NUMERIC,
      note TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ DB initialized');
}
initDb().catch(err=>{ console.error('DB init error', err); process.exit(1); });


// Ensure admin exists in users table (admin credentials come from ADMIN_PASS env)
async function ensureAdminUser(){
  try{
    const adminPass = process.env.ADMIN_PASS || '12041998avril1999A';
    const hashed = await bcrypt.hash(adminPass, 12);
    // Upsert admin user into users table; admin username = 'admin'
    await pool.query(`INSERT INTO users(username,email,password_hash,balances,banned) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`, ['admin','admin@localhost', hashed, JSON.stringify({EUR:0,BTC:0,ETH:0,USDT:0}), false]);
    // ensure chats row exists
    await pool.query('INSERT INTO chats(username,messages) VALUES($1,$2) ON CONFLICT(username) DO NOTHING', ['admin', JSON.stringify([])]);
    console.log('✅ Admin user ensured');
  }catch(e){ console.error('ensureAdminUser err', e); process.exit(1); }
}

ensureAdminUser().catch(e=>{ console.error('admin init failed', e); process.exit(1); });


const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true } });

app.use(cors());
app.use(express.json());
app.use(helmet());

// Rate limiting - basic
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', apiLimiter);

// CORS - restrict via ENV (comma-separated origin list) if provided
const allowed = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
if(allowed.length) app.use(cors({ origin: allowed }));
else app.use(cors());

// Nodemailer transporter (optional)
let transporter = null;
if(process.env.SMTP_HOST){
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: (process.env.SMTP_SECURE === 'true'),
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
}

app.use(express.static(path.join(__dirname, 'public')));

// Market simulation
const PAIRS = {
  'BTC/EUR': { symbol:'BTC', price:25000, vol:0.03 },
  'ETH/EUR': { symbol:'ETH', price:1500, vol:0.04 },
  'USDT/EUR': { symbol:'USDT', price:1, vol:0.001 }
};
const priceSeries = {};
Object.keys(PAIRS).forEach(k=>priceSeries[k]=[PAIRS[k].price]);
function stepMarket(){
  Object.keys(PAIRS).forEach(pair=>{
    const meta = PAIRS[pair];
    const last = priceSeries[pair][priceSeries[pair].length-1];
    const shock = (Math.random()-0.5)*2*meta.vol;
    const drift = (Math.random()-0.5)*0.001;
    const next = Math.max(0.00001, last*(1+shock+drift));
    priceSeries[pair].push(next);
    if(priceSeries[pair].length>300) priceSeries[pair].shift();
  });
  io.emit('prices', currentPrices());
}
setInterval(stepMarket, 1000);
function currentPrices(){ const out={}; for(const p in priceSeries) out[p]=priceSeries[p][priceSeries[p].length-1]; return out; }

// Helpers
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({ error:'no auth' });
  const token = h.split(' ')[1];
  try{ const payload = jwt.verify(token, JWT_SECRET); req.user = payload; next(); }catch(e){ return res.status(401).json({ error:'invalid token' }); }
}

async function getUserRow(username){
  const r = await pool.query('SELECT username, email, balances, banned FROM users WHERE username=$1', [username]);
  return r.rowCount? r.rows[0] : null;
}

// Routes
app.get('/health', (req,res)=> res.json({ status:'ok', uptime: process.uptime() }));

app.post('/api/register', [
  body('username').isLength({ min:3, max:40 }).matches(/^[a-zA-Z0-9_\-]+$/),
  body('email').isEmail(),
  body('password').isLength({ min:8 }),
  body('withdrawCode').isLength({ min:4, max:20 })
], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ error:'validation', details: errors.array() });
  const { username, email, password, withdrawCode } = req.body;
  if(!username || !email || !password) return res.status(400).json({ error:'missing' });
  if(username === 'admin') return res.status(400).json({ error:'invalid username' });
  try{
    const hash = await bcrypt.hash(password, 10);
    const withdrawHash = await bcrypt.hash(withdrawCode, 12);
    await pool.query('INSERT INTO users(username,email,password_hash,withdraw_code_hash) VALUES($1,$2,$3,$4)', [username, email, hash, withdrawHash]);
    await pool.query('INSERT INTO chats(username,messages) VALUES($1,$2) ON CONFLICT(username) DO NOTHING', [username, JSON.stringify([])]);
    // create email verification token
    const verToken = require('crypto').randomBytes(20).toString('hex');
    await pool.query('INSERT INTO email_verifications(username,token) VALUES($1,$2) ON CONFLICT (username) DO UPDATE SET token=$2, created_at=NOW()', [username, verToken]);
    // send email if transporter configured, otherwise log verification link
    const verifyLink = (process.env.BASE_URL || '') + '/verify-email?username=' + encodeURIComponent(username) + '&token=' + verToken;
    if(transporter){
      transporter.sendMail({ from: process.env.SMTP_FROM || 'no-reply@example.com', to: email, subject: 'Verify your trading bot account', text: 'Verify your account: ' + verifyLink, html: '<p>Click to verify: <a href="'+verifyLink+'">Verify email</a></p>' }).catch(e=>console.error('mail err', e));
    } else { console.log('VERIFICATION LINK:', verifyLink); }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { username, email, verifySent: true } });
  }catch(err){
    console.error('register err', err);
    res.status(400).json({ error:'user exists or db error' });
  }
});

app.post('/api/login', [ body('username').notEmpty(), body('password').notEmpty() ], async (req,res)=>{ const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ error:'validation' });
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'missing' });
  if(username === 'admin'){
    if(password !== ADMIN_PASS) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ username:'admin', admin:true }, JWT_SECRET, { expiresIn:'7d' });
    return res.json({ token, user:{ username:'admin', admin:true } });
  }
  try{
    const r = await pool.query('SELECT username, password_hash, balances, banned, email FROM users WHERE username=$1', [username]);
    if(r.rowCount===0) return res.status(401).json({ error:'invalid' });
    const row = r.rows[0];
    if(row.banned) return res.status(403).json({ error:'banned' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { username: row.username, email: row.email, balances: row.balances } });
  }catch(e){ console.error('login err', e); res.status(500).json({ error:'server' }); }
});

// Admin endpoints
app.get('/api/admin/users', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const r = await pool.query('SELECT username,email,balances,banned FROM users ORDER BY username');
  res.json(r.rows);
});

// Admin set balance (manual only)
app.post('/api/admin/set-balance', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, currency, amount } = req.body;
  if(!username || !currency || typeof amount !== 'number') return res.status(400).json({ error:'missing' });
  const r = await pool.query('SELECT balances FROM users WHERE username=$1', [username]);
  if(r.rowCount===0) return res.status(404).json({ error:'not found' });
  const balances = r.rows[0].balances || { EUR:0 };
  balances[currency] = amount;
  await pool.query('UPDATE users SET balances=$1 WHERE username=$2', [balances, username]);
  await pool.query('INSERT INTO transactions(username,type,currency,amount,note) VALUES($1,$2,$3,$4,$5)', [username,'admin-adjust',currency,amount,'admin set balance']);
  // notify via sockets and append chat
  io.to(username).emit('balance_updated', { username, balances });
  const cr = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
  let msgs = cr.rowCount ? cr.rows[0].messages || [] : [];
  msgs.push({ from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  await pool.query('INSERT INTO chats(username,messages) VALUES($1,$2) ON CONFLICT (username) DO UPDATE SET messages=$2, updated_at=NOW()', [username, msgs]);
  io.to(username).emit('chat_message', { user: username, from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  res.json({ ok:true });
});

// Admin ban/unban
app.post('/api/admin/ban', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, ban } = req.body;
  if(!username || typeof ban !== 'boolean') return res.status(400).json({ error:'missing' });
  await pool.query('UPDATE users SET banned=$1 WHERE username=$2', [ban, username]);
  io.to(username).emit('banned', { banned: ban, message: ban ? 'You have been banned by admin.' : 'You have been unbanned.' });
  res.json({ ok:true });
});

// Admin fetch chat history
app.get('/api/admin/chat/:username', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const username = req.params.username;
  const r = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
  res.json(r.rowCount ? r.rows[0].messages : []);
});

// Export transactions
app.get('/api/transactions/export', authMiddleware, async (req,res)=>{
  const requester = req.user.username;
  const username = req.query.username;
  let filter = '', params = [];
  if(requester !== 'admin'){ filter = 'WHERE username=$1'; params.push(requester); }
  else if(username){ filter = 'WHERE username=$1'; params.push(username); }
  const q = `SELECT username,type,pair,amount,currency,value_eur,created_at FROM transactions ${filter} ORDER BY created_at DESC`;
  const r = await pool.query(q, params);
  const records = r.rows.map(t=>({ username: t.username, type: t.type, pair: t.pair, amount: t.amount, currency: t.currency, valueEUR: t.value_eur, timestamp: t.created_at }));
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="transactions_${username||'all'}.csv"`);
  stringify(records, { header:true }).pipe(res);
});

app.get('/api/prices', (req,res)=> res.json(currentPrices()));




// Withdraw request endpoint - requires withdrawCode verification
app.post('/api/withdraw', authMiddleware, async (req,res)=>{
  const { amount, currency, withdrawCode } = req.body;
  if(!amount || !currency || !withdrawCode) return res.status(400).json({ error:'missing fields' });
  try{
    const r = await pool.query('SELECT withdraw_code_hash FROM users WHERE username=$1', [req.user.username]);
    if(r.rowCount===0) return res.status(400).json({ error:'user not found' });
    const ok = await bcrypt.compare(withdrawCode, r.rows[0].withdraw_code_hash);
    if(!ok) return res.status(403).json({ error:'Invalid security code' });

    // Create a message in chat for admin review
    const msg = { from: req.user.username, text: `Withdrawal request: ${amount} ${currency}` };
    const chatRes = await pool.query('SELECT messages FROM chats WHERE username=$1', [req.user.username]);
    let msgs = chatRes.rowCount? chatRes.rows[0].messages:[];
    msgs.push(msg);
    await pool.query('INSERT INTO chats(username,messages) VALUES($1,$2) ON CONFLICT(username) DO UPDATE SET messages=$2', [req.user.username, JSON.stringify(msgs)]);
    io.to('admin').emit('chat', { username:req.user.username, msg });
    res.json({ success:true, message:'Withdrawal request sent to admin' });
  }catch(e){ console.error('withdraw err', e); res.status(500).json({ error:'server error' }); }
});


// Email verification endpoint (simple GET used from email link)
app.get('/verify-email', async (req,res)=>{
  const username = req.query.username;
  const token = req.query.token;
  if(!username || !token) return res.status(400).send('missing');
  const r = await pool.query('SELECT token FROM email_verifications WHERE username=$1', [username]);
  if(r.rowCount===0 || r.rows[0].token !== token) return res.status(400).send('invalid or expired token');
  // verification passed - delete token row (or keep for audit)
  await pool.query('DELETE FROM email_verifications WHERE username=$1', [username]);
  res.send('Email verified for ' + username + '. You can now use the app.');
});


// Chat & sockets
io.on('connection', socket => {
  socket.on('auth', async ({ token })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      socket.user = p;
      if(p.username === 'admin'){
        socket.join('admins');
        socket.emit('prices', currentPrices());
      } else {
        socket.join(p.username);
        const r = await pool.query('SELECT balances FROM users WHERE username=$1', [p.username]);
        const balances = r.rowCount ? r.rows[0].balances : { EUR:0 };
        socket.emit('auth_ok', { user: { username: p.username, balances } });
        const cr = await pool.query('SELECT messages FROM chats WHERE username=$1', [p.username]);
        socket.emit('chat_history', cr.rowCount ? cr.rows[0].messages : []);
      }
    }catch(e){ socket.emit('auth_error', { msg:'invalid token' }); }
  });

  socket.on('send_chat', async ({ token, text })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      const username = p.username;
      const cr = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
      let msgs = cr.rowCount ? cr.rows[0].messages || [] : [];
      msgs.push({ from: username, text, time: new Date() });
      await pool.query('INSERT INTO chats(username,messages) VALUES($1,$2) ON CONFLICT (username) DO UPDATE SET messages=$2, updated_at=NOW()', [username, msgs]);
      // notify admin and user
      io.to('admins').emit('chat_message', { user: username, from: username, text, time: new Date() });
      io.to(username).emit('chat_message', { user: username, from: username, text, time: new Date() });
    }catch(e){ console.error('send_chat err', e); }
  });

  socket.on('admin_reply', async ({ token, username, text })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      if(p.username !== 'admin') return;
      const cr = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
      let msgs = cr.rowCount ? cr.rows[0].messages || [] : [];
      msgs.push({ from: 'admin', text, time: new Date() });
      await pool.query('INSERT INTO chats(username,messages) VALUES($1,$2) ON CONFLICT (username) DO UPDATE SET messages=$2, updated_at=NOW()', [username, msgs]);
      io.to(username).emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
      io.to('admins').emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
    }catch(e){ console.error('admin_reply err', e); }
  });

  socket.on('trade', async ({ token, pair, type, amountBase })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      const username = p.username;
      const ru = await pool.query('SELECT balances, banned FROM users WHERE username=$1', [username]);
      if(ru.rowCount===0) return socket.emit('trade_result', { ok:false, reason:'user not found' });
      const u = ru.rows[0];
      if(u.banned) return socket.emit('trade_result', { ok:false, reason:'banned' });
      const balances = u.balances || { EUR:0 };
      const price = currentPrices()[pair];
      const sym = PAIRS[pair].symbol;
      if(type === 'buy'){
        const cost = Number(amountBase) * Number(price);
        if((balances.EUR||0) < cost) return socket.emit('trade_result', { ok:false, reason:'insufficient EUR' });
        balances.EUR = (balances.EUR||0) - cost;
        balances[sym] = (balances[sym]||0) + Number(amountBase);
        await pool.query('UPDATE users SET balances=$1 WHERE username=$2', [balances, username]);
        await pool.query('INSERT INTO transactions(username,type,pair,amount,currency,value_eur) VALUES($1,$2,$3,$4,$5,$6)', [username,'buy',pair,amountBase,sym,cost]);
      } else {
        if((balances[sym]||0) < Number(amountBase)) return socket.emit('trade_result', { ok:false, reason:'insufficient asset' });
        balances[sym] = (balances[sym]||0) - Number(amountBase);
        const proceeds = Number(amountBase) * Number(price);
        balances.EUR = (balances.EUR||0) + proceeds;
        await pool.query('UPDATE users SET balances=$1 WHERE username=$2', [balances, username]);
        await pool.query('INSERT INTO transactions(username,type,pair,amount,currency,value_eur) VALUES($1,$2,$3,$4,$5,$6)', [username,'sell',pair,amountBase,sym,proceeds]);
      }
      io.to(username).emit('trade_result', { ok:true, balances });
      io.to('admins').emit('user_update', { username, balances });
    }catch(e){ console.error('trade err', e); socket.emit('trade_result', { ok:false, reason:'server' }); }
  });

  socket.on('disconnect', ()=>{});
});

// SPA fallback
app.get('/', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('*', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, ()=> console.log('Persistent trading bot server started on', PORT));