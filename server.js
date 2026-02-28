import crypto from 'node:crypto';
import express from 'express';
import http from 'node:http';
import { WebSocketServer } from 'ws';

const PORT = process.env.PORT || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const SESSION_TTL_MS = 10 * 60 * 1000;

const app = express();
if (TRUST_PROXY) {
  app.set('trust proxy', true);
}

app.disable('x-powered-by');
app.use(express.json({ limit: '8kb' }));

// Security headers: strict transport and anti-sniffing protections.
app.use((req, res, next) => {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  if (!isSecure && process.env.NODE_ENV === 'production') {
    const host = req.headers.host;
    return res.redirect(308, `https://${host}${req.originalUrl}`);
  }

  const connectSrc = process.env.NODE_ENV === 'production' ? "'self' wss:" : "'self' wss: ws:";

  // Enforce transport security in production (safe on localhost but ignored by browsers for non-HTTPS).
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self'; connect-src ${connectSrc}; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
  next();
});

app.use(express.static('public', { etag: false, maxAge: 0 }));

const sessions = new Map();

function makeSessionId() {
  // 256-bit random session IDs make invite links unguessable.
  return crypto.randomBytes(32).toString('base64url');
}

function destroySession(sessionId, reason = 'Session closed') {
  const session = sessions.get(sessionId);
  if (!session) return;

  if (session.expiresTimer) {
    clearTimeout(session.expiresTimer);
  }

  for (const client of session.clients) {
    try {
      if (client.socket.readyState === 1) {
        client.socket.send(JSON.stringify({ type: 'session_closed', reason }));
        client.socket.close(1000, reason);
      }
    } catch {
      // Intentionally ignore send/close errors to ensure best-effort teardown.
    }
  }

  // Remove all in-memory state immediately when either party disconnects.
  sessions.delete(sessionId);
}

function parseHost(req) {
  const host = req.headers.host || `localhost:${PORT}`;
  const proto = (req.secure || req.headers['x-forwarded-proto'] === 'https') ? 'https' : 'http';
  return `${proto}://${host}`;
}

app.post('/api/session', (req, res) => {
  // One-time invite session creation: IDs are never reused.
  let sessionId = makeSessionId();
  while (sessions.has(sessionId)) {
    sessionId = makeSessionId();
  }

  const session = {
    id: sessionId,
    createdAt: Date.now(),
    clients: [],
    expiresTimer: setTimeout(() => {
      destroySession(sessionId, 'Session expired before secure join');
    }, SESSION_TTL_MS)
  };

  sessions.set(sessionId, session);

  const base = parseHost(req);
  const inviteUrl = `${base}/?invite=${encodeURIComponent(sessionId)}`;

  res.status(201).json({ inviteUrl, sessionId });
});

app.get('/healthz', (_req, res) => {
  res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (socket, req) => {
  // Reject insecure websocket upgrades in production.
  const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  if (!secure && process.env.NODE_ENV === 'production') {
    socket.close(1008, 'Secure transport required');
    return;
  }

  let activeSessionId = null;

  socket.on('message', (buffer) => {
    let msg;
    try {
      msg = JSON.parse(buffer.toString('utf8'));
    } catch {
      socket.close(1003, 'Invalid payload');
      return;
    }

    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') {
      socket.close(1003, 'Malformed message');
      return;
    }

    if (msg.type === 'join') {
      if (activeSessionId) {
        socket.close(1008, 'Already joined');
        return;
      }

      const sessionId = typeof msg.sessionId === 'string' ? msg.sessionId : '';
      const session = sessions.get(sessionId);
      if (!session) {
        socket.send(JSON.stringify({ type: 'error', code: 'SESSION_NOT_FOUND' }));
        socket.close(1008, 'Session not found');
        return;
      }

      if (session.clients.length >= 2) {
        socket.send(JSON.stringify({ type: 'error', code: 'SESSION_FULL' }));
        socket.close(1008, 'Session full');
        return;
      }

      const slot = session.clients.length + 1;
      session.clients.push({ socket, slot });
      activeSessionId = sessionId;

      socket.send(JSON.stringify({ type: 'joined', slot }));
      if (session.clients.length === 2) {
        if (session.expiresTimer) {
          clearTimeout(session.expiresTimer);
          session.expiresTimer = null;
        }
        for (const client of session.clients) {
          client.socket.send(JSON.stringify({ type: 'peer_ready' }));
        }
      }
      return;
    }

    if (!activeSessionId) {
      socket.close(1008, 'Join required');
      return;
    }

    const session = sessions.get(activeSessionId);
    if (!session) {
      socket.close(1008, 'Session closed');
      return;
    }

    // Blind relay: server does not inspect encrypted payloads beyond envelope type checks.
    if (['key_init', 'key_response', 'key_rotate', 'auth_confirm', 'ciphertext'].includes(msg.type)) {
      const peer = session.clients.find((c) => c.socket !== socket);
      if (!peer || peer.socket.readyState !== 1) {
        socket.send(JSON.stringify({ type: 'error', code: 'PEER_NOT_CONNECTED' }));
        return;
      }
      peer.socket.send(JSON.stringify(msg));
      return;
    }

    socket.close(1003, 'Unsupported message type');
  });

  socket.on('close', () => {
    if (!activeSessionId) return;
    destroySession(activeSessionId, 'A participant disconnected');
    activeSessionId = null;
  });

  socket.on('error', () => {
    if (!activeSessionId) return;
    destroySession(activeSessionId, 'Connection error');
    activeSessionId = null;
  });
});

server.listen(PORT, () => {
  // Startup log only; no request/message metadata logged.
  console.log(`Secure chat server listening on :${PORT}`);
});
