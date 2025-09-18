import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
import { stringify } from 'csv-stringify';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const ADMIN_PASS = process.env.ADMIN_PASS || '12041998avril1999A';

// In-memory storage
let users = {}; // username -> { passwordHash, email, balances, banned }
let chats = {}; // username -> [ { from, text, time } ]
let transactions = []; // { username, type, pair, amount, currency, valueEUR, timestamp }

// Seed admin (no password stored for admin; login checks ADMIN_PASS)
users['admin'] = { passwordHash: '', email: '', balances: { EUR: 0, BTC:0, ETH:0, USDT:0 }, banned: false };
chats['admin'] = [];

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true } });

app.use(cors());
app.use(express.json());
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

// Auth middleware
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({ error:'no auth' });
  const token = h.split(' ')[1];
  try{ const payload = jwt.verify(token, JWT_SECRET); req.user = payload; next(); }catch(e){ return res.status(401).json({ error:'invalid token' }); }
}

// Routes
app.get('/health', (req,res)=> res.json({ status:'ok', uptime: process.uptime() }));

app.post('/api/register', async (req,res)=>{
  const { username, email, password } = req.body;
  if(!username || !email || !password) return res.status(400).json({ error:'missing' });
  if(username === 'admin') return res.status(400).json({ error:'invalid username' });
  if(users[username]) return res.status(400).json({ error:'exists' });
  const hash = await bcrypt.hash(password, 10);
  users[username] = { passwordHash: hash, email, balances: { EUR: 1000, BTC:0, ETH:0, USDT:0 }, banned:false };
  chats[username] = [];
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: { username, email } });
});

app.post('/api/login', async (req,res)=>{
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'missing' });
  if(username === 'admin'){
    if(password !== ADMIN_PASS) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ username:'admin', admin:true }, JWT_SECRET, { expiresIn:'7d' });
    return res.json({ token, user: { username:'admin', admin:true } });
  }
  const u = users[username];
  if(!u) return res.status(401).json({ error:'invalid' });
  if(u.banned) return res.status(403).json({ error:'banned' });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if(!ok) return res.status(401).json({ error:'invalid' });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
  res.json({ token, user: { username, email: u.email, balances: u.balances } });
});

// Admin endpoints
app.get('/api/admin/users', authMiddleware, (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const all = Object.keys(users).filter(u=>u!=='admin').map(u=>({ username:u, email: users[u].email, balances: users[u].balances, banned: users[u].banned }));
  res.json(all);
});

app.post('/api/admin/set-balance', authMiddleware, (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, currency, amount } = req.body;
  if(!users[username]) return res.status(404).json({ error:'not found' });
  users[username].balances[currency] = amount;
  transactions.push({ username, type:'admin-adjust', currency, amount, timestamp: new Date() });
  io.to(username).emit('balance_updated', { username, balances: users[username].balances });
  chats[username].push({ from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  io.to(username).emit('chat_message', { user: username, from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  res.json({ ok:true });
});

app.post('/api/admin/ban', authMiddleware, (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, ban } = req.body;
  if(!users[username]) return res.status(404).json({ error:'not found' });
  users[username].banned = !!ban;
  io.to(username).emit('banned', { banned: !!ban, message: ban ? 'You have been banned by admin.' : 'You have been unbanned by admin.' });
  res.json({ ok:true });
});

// Chat fetch for admin
app.get('/api/admin/chat/:username', authMiddleware, (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const username = req.params.username;
  res.json(chats[username] || []);
});

// Export transactions CSV
app.get('/api/transactions/export', authMiddleware, (req,res)=>{
  const requester = req.user.username;
  const username = req.query.username;
  let list = transactions.slice().reverse();
  if(requester !== 'admin') list = list.filter(t=>t.username === requester);
  else if(username) list = list.filter(t=>t.username === username);
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="transactions_${username||'all'}.csv"`);
  stringify(list, { header:true }).pipe(res);
});

app.get('/api/prices', (req,res)=> res.json(currentPrices()));

// Socket.io events
io.on('connection', socket => {
  socket.on('auth', ({ token })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      socket.user = p;
      if(p.username === 'admin') { socket.join('admins'); socket.emit('prices', currentPrices()); }
      else {
        socket.join(p.username);
        const u = users[p.username] || { balances: { EUR:0 } };
        socket.emit('auth_ok', { user: { username: p.username, email: u.email, balances: u.balances } });
        socket.emit('chat_history', chats[p.username] || []);
      }
    }catch(e){ socket.emit('auth_error', { msg:'invalid token' }); }
  });

  socket.on('send_chat', ({ token, text })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      chats[p.username] = chats[p.username] || [];
      const msg = { from: p.username, text, time: new Date() };
      chats[p.username].push(msg);
      io.to('admins').emit('chat_message', { user: p.username, from: p.username, text, time: new Date() });
      io.to(p.username).emit('chat_message', { user: p.username, from: p.username, text, time: new Date() });
    }catch(e){}
  });

  socket.on('admin_reply', ({ token, username, text })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      if(p.username !== 'admin') return;
      chats[username] = chats[username] || [];
      const msg = { from: 'admin', text, time: new Date() };
      chats[username].push(msg);
      io.to(username).emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
      io.to('admins').emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
    }catch(e){}
  });

  socket.on('trade', ({ token, pair, type, amountBase })=>{
    try{
      const p = jwt.verify(token, JWT_SECRET);
      const username = p.username;
      const u = users[username];
      if(!u) return socket.emit('trade_result', { ok:false, reason:'user not found' });
      if(u.banned) return socket.emit('trade_result', { ok:false, reason:'banned' });
      const price = currentPrices()[pair];
      const sym = PAIRS[pair].symbol;
      if(type === 'buy'){
        const cost = Number(amountBase) * Number(price);
        if((u.balances.EUR||0) < cost) return socket.emit('trade_result', { ok:false, reason:'insufficient EUR' });
        u.balances.EUR = (u.balances.EUR||0) - cost;
        u.balances[sym] = (u.balances[sym]||0) + Number(amountBase);
        transactions.push({ username, type:'buy', pair, amount: amountBase, currency: sym, valueEUR: cost, timestamp: new Date() });
      } else {
        if((u.balances[sym]||0) < Number(amountBase)) return socket.emit('trade_result', { ok:false, reason:'insufficient asset' });
        u.balances[sym] = (u.balances[sym]||0) - Number(amountBase);
        const proceeds = Number(amountBase) * Number(price);
        u.balances.EUR = (u.balances.EUR||0) + proceeds;
        transactions.push({ username, type:'sell', pair, amount: amountBase, currency: sym, valueEUR: proceeds, timestamp: new Date() });
      }
      io.to(username).emit('trade_result', { ok:true, balances: u.balances });
      io.to('admins').emit('user_update', { username, balances: u.balances });
    }catch(e){ console.error('trade err', e); socket.emit('trade_result', { ok:false, reason:'server' }); }
  });

  socket.on('disconnect', ()=>{});
});

// SPA fallback
app.get('/', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('*', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, ()=> console.log('Memory server started on', PORT));