# Minimal Secure One-to-One Chat

## Architecture

This app is intentionally minimal and enforces a strict **exactly-two-participant** model.

- **Frontend:** static HTML/CSS + vanilla JS using Web Crypto API.
- **Backend:** Node.js + Express + `ws` WebSocket relay.
- **State:** in-memory session map only; no database; no file-based message persistence.
- **Identity:** no accounts, usernames, emails, or phone numbers.
- **Session bootstrap:** one-time invite link containing a high-entropy, unguessable session ID.

### Data flow

1. User A clicks **Create Secure Session**.
2. Server creates a random 256-bit session ID and returns `/?invite=<id>`.
3. User B opens that link.
4. Both peers connect over WebSocket and join that session.
5. Browsers perform X25519 key exchange through the server relay.
6. Browsers derive symmetric keys with HKDF-SHA256.
7. Both browsers display the same short safety code derived from both public keys.
8. Users compare that code out-of-band and both click confirm.
9. Messages are AES-256-GCM encrypted client-side before transport.
10. Server relays ciphertext only and cannot decrypt.
11. If either peer disconnects, server destroys session state immediately.

## Threat model

### Security goals

- Confidentiality: server/network observers cannot read message plaintext.
- Integrity: ciphertext tampering is detected by AES-GCM authentication.
- Forward secrecy (windowed): periodic rekeying limits impact of key compromise.
- Ephemerality: no durable chat history on server.
- MITM resistance: key verification code prevents undetected relay key substitution.

### Explicit non-goals / trust assumptions

- Endpoint compromise (malware, XSS from third-party browser extensions) is out-of-scope.
- Manual invite sharing and safety-code comparison channel is trusted by users.
- TLS endpoint cert management is required in production deployment.

### Main mitigations

- **Unguessable session IDs:** 32-byte random IDs (`base64url`).
- **2-party max:** session hard limit of 2 sockets.
- **E2EE only:** plaintext never leaves browser.
- **Blind relay:** server validates envelope types only.
- **No metadata logging by app:** no message or key logging.
- **Immediate teardown:** disconnect from either side destroys room.
- **Invite expiry:** unpaired sessions auto-expire in RAM.
- **Transport hardening:** HTTPS redirect + HSTS + WSS requirement in production.
- **Browser hardening:** strict CSP, frame deny, no referrer, no sniff.

## WebSocket protocol

All messages are JSON objects.

### Session control
- `join`: `{ type: "join", sessionId }`
- `joined`: `{ type: "joined", slot: 1|2 }`
- `peer_ready`: `{ type: "peer_ready" }`
- `session_closed`: `{ type: "session_closed", reason }`
- `error`: `{ type: "error", code }`

### E2EE key management
- `key_init`: `{ type: "key_init", publicKey }`
- `key_response`: `{ type: "key_response", publicKey }`
- `auth_confirm`: `{ type: "auth_confirm" }` (sent only after user confirms matching safety code)
- `key_rotate` offer: `{ type: "key_rotate", stage: "offer", rekeyId, publicKey }`
- `key_rotate` answer: `{ type: "key_rotate", stage: "answer", rekeyId, publicKey, salt }`

### Encrypted chat
- `ciphertext`: `{ type: "ciphertext", counter, iv, data }`

## Security hardening checklist

- [x] Exactly two peers per session.
- [x] No account system or identifiers.
- [x] One-time invite IDs are cryptographically random.
- [x] X25519 key exchange in browser.
- [x] Safety-code verification gate before chat sends/decrypts.
- [x] HKDF-SHA256 key derivation.
- [x] AES-256-GCM authenticated encryption.
- [x] Rekeying periodically and by message count.
- [x] Server relays ciphertext only.
- [x] No DB or disk persistence for chats.
- [x] Session teardown on disconnect/error.
- [x] Pre-join invite expiration in RAM.
- [x] HTTPS redirect + HSTS + WSS-only in production.
- [x] CSP + anti-clickjacking + anti-sniffing headers.
- [x] No camera/mic/location/file permissions requested.

## Local run instructions

```bash
npm install
npm start
```

Then open `http://localhost:3000` in two browser tabs/devices.

### Production notes

- Terminate TLS (or run Node behind TLS proxy), set `NODE_ENV=production`.
- If behind reverse proxy, set `TRUST_PROXY=true` and forward `X-Forwarded-Proto: https`.
- Use only `https://` URL for clients so browser upgrades to `wss://`.
