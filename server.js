const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8888);
const ACCOUNT_FILE = path.join(__dirname, 'accounts.txt');

const clients = new Map(); // ws -> username

function loadAccounts() {
  const map = new Map();
  if (!fs.existsSync(ACCOUNT_FILE)) return map;
  const lines = fs.readFileSync(ACCOUNT_FILE, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    const p = line.indexOf('|');
    if (p < 0) continue;
    const name = line.slice(0, p);
    const pass = line.slice(p + 1);
    map.set(name, pass);
  }
  return map;
}

function saveAccounts(accounts) {
  const lines = [];
  for (const [name, pass] of accounts.entries()) {
    lines.push(`${name}|${pass}`);
  }
  fs.writeFileSync(ACCOUNT_FILE, lines.join('\n') + '\n', 'utf8');
}

function ensureDefaultAccount() {
  const accounts = loadAccounts();
  if (!accounts.has('user')) {
    accounts.set('user', 'pass');
    saveAccounts(accounts);
    console.log('created default account: user / pass');
  }
}

function send(ws, text) {
  if (ws.readyState === WebSocket.OPEN) ws.send(text);
}

function broadcast(text) {
  for (const ws of clients.keys()) send(ws, text);
}

function parseAuthPacket(msg) {
  const parts = String(msg).split('|');
  if (parts.length < 3) return null;
  const type = parts[0];
  const name = parts[1];
  const pass = parts.slice(2).join('|');
  if (!name || !pass || name.includes('|')) return null;
  return { type, name, pass };
}

ensureDefaultAccount();

const wss = new WebSocket.Server({ port: PORT }, () => {
  console.log(`WebSocket TalkServer started on port ${PORT}`);
});

wss.on('connection', (ws, req) => {
  console.log('client connected:', req.socket.remoteAddress);

  ws.on('message', (data) => {
    const msg = data.toString();

    if (!clients.has(ws)) {
      const pkt = parseAuthPacket(msg);
      if (!pkt) {
        send(ws, 'LOGIN_FAILED');
        ws.close();
        return;
      }

      const accounts = loadAccounts();

      if (pkt.type === 'SIGNUP_PLAIN') {
        if (accounts.has(pkt.name)) {
          send(ws, 'SIGNUP_FAILED');
          ws.close();
          return;
        }
        accounts.set(pkt.name, pkt.pass);
        saveAccounts(accounts);
        clients.set(ws, pkt.name);
        send(ws, 'SIGNUP_SUCCESS');
        console.log('signup success:', pkt.name);
        return;
      }

      if (pkt.type === 'LOGIN_PLAIN') {
        if (accounts.get(pkt.name) !== pkt.pass) {
          send(ws, 'LOGIN_FAILED');
          ws.close();
          return;
        }
        clients.set(ws, pkt.name);
        send(ws, 'LOGIN_SUCCESS');
        console.log('login success:', pkt.name);
        return;
      }

      send(ws, 'LOGIN_FAILED');
      ws.close();
      return;
    }

    const name = clients.get(ws);
    const fullMsg = `${name}: ${msg}`;
    console.log('received:', fullMsg);
    broadcast(fullMsg);
  });

  ws.on('close', () => {
    const name = clients.get(ws);
    clients.delete(ws);
    console.log('client disconnected', name ? `(${name})` : '');
  });

  ws.on('error', (err) => {
    console.log('client error:', err.message);
  });
});
