#!/usr/bin/env node
// Stdio MCP adapter for Burp's legacy SSE+POST transport (BApp on 127.0.0.1:9876).
// Speaks newline-delimited JSON-RPC on stdin/stdout (MCP stdio).
// Upstream quirks handled here:
//  - replies arrive on the SSE stream, not as POST responses (POST = 202 Accepted);
//  - the server only answers after it received initialize;
//  - Node quirk: only 'data' listeners registered inside the response callback
//    receive chunks, so one listener owns all SSE parsing + reply routing.
const http = require('http');

const HOST = '127.0.0.1', PORT = 9876;

let sid = null;
let sse = null;
let initialized = false;
let serverInfo = { name: 'burp-suite', version: '1.1.2' };

const pending = new Map(); // id -> resolver(obj)
function expect(id, ms = 30000) {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve({ timeout: true }), ms);
    pending.set(id, (obj) => { clearTimeout(t); resolve(obj); });
  });
}

// open the SSE session; its single data listener parses frames for life
function openSSE() {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('sid timeout')), 10000);
    sse = http.get({ host: HOST, port: PORT, path: '/' }, (res) => {
      let acc = '';
      res.on('data', (c) => {
        acc += c.toString().replace(/\r/g, '');
        let idx;
        while ((idx = acc.indexOf('\n\n')) !== -1) {
          const frame = acc.slice(0, idx);
          acc = acc.slice(idx + 2);
          if (!sid) {
            const m = frame.match(/data: \?sessionId=([a-f0-9-]+)/);
            if (m) { sid = m[1]; clearTimeout(t); resolve(sid); }
          }
          const data = frame.split('\n').filter(l => l.startsWith('data: ')).map(l => l.slice(6)).join('');
          if (!data || data.startsWith('?sessionId=')) continue;
          try {
            const obj = JSON.parse(data);
            if (obj && typeof obj.id === 'number' && pending.has(obj.id)) pending.get(obj.id)(obj);
          } catch { /* not JSON */ }
        }
      });
    });
  });
}

// send JSON-RPC upstream; resolves with the SSE reply matched by id
async function rpc(id, method, params, timeoutMs = 30000) {
  if (!sid) throw new Error('no session yet');
  const rep = expect(id, timeoutMs);
  const body = JSON.stringify({ jsonrpc: '2.0', id, method, params: params ?? {} });
  const postDone = new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('post timeout: ' + method)), 15000);
    const req = http.request({ host: HOST, port: PORT, path: `/?sessionId=${sid}`, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => {
      let acc2 = '';
      res.on('data', (c) => (acc2 += c.toString()));
      res.on('end', () => { clearTimeout(t); resolve(res.statusCode); });
    });
    req.write(body);
  });
  const status = await postDone;
  const reply = await rep;
  if (reply && reply.timeout) throw new Error('no reply for: ' + method);
  return reply;
}

function respond(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }

async function ensureInit() {
  if (initialized) return;
  await openSSE();
  const reply = await rpc(0, 'initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'pi-adapter', version: '1.0' },
  });
  if (reply && reply.result) serverInfo = reply.result.serverInfo ?? serverInfo;
  initialized = true;
}

function postRaw(payload, ms = 8000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('post timeout')), ms);
    const body = JSON.stringify(payload);
    const req = http.request({ host: HOST, port: PORT, path: `/?sessionId=${sid}`, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => {
      res.resume();
      res.on('end', () => { clearTimeout(t); resolve(res.statusCode); });
    });
    req.write(body);
  });
}

// sequential stdio JSON-RPC loop
let buf = '';
process.stdin.on('data', (c) => {
  buf += c.toString();
  let idx;
  while ((idx = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    handle(line).catch(e => {
      respond({ jsonrpc: '2.0', id: null, error: { code: -32603, message: e.message } });
    });
  }
});

async function handle(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { respond({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid JSON' } }); return; }
  const { id, method, params } = msg;

  switch (method) {
    case 'initialize': {
      await ensureInit();
      respond({ jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo } });
      break;
    }
    case 'notifications/initialized': {
      await ensureInit();
      await postRaw({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
      respond({ jsonrpc: '2.0', id: null });
      break;
    }
    case 'tools/list': {
      await ensureInit();
      const reply = await rpc(id, 'tools/list', {});
      respond(reply);
      break;
    }
    case 'tools/call': {
      await ensureInit();
      const reply = await rpc(id, 'tools/call', { name: params?.name, arguments: params?.arguments ?? {} });
      respond(reply);
      break;
    }
    case 'ping': {
      respond({ jsonrpc: '2.0', id, result: {} });
      break;
    }
    default: {
      respond({ jsonrpc: '2.0', id, error: { code: -32601, message: 'method not supported' } });
    }
  }
}

process.stdin.on('end', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
