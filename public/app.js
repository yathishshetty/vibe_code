const state = {
  ws: null,
  sessionId: null,
  slot: null,
  myStaticKeyPair: null,
  myStaticPublicBytes: null,
  peerStaticPublicKey: null,
  peerStaticPublicBytes: null,
  rootKey: null,
  sendCounter: 0,
  recvCounter: 0,
  rekeyTimer: null,
  pendingRekeyOffer: null,
  pendingRekeyId: null,
  localConfirmed: false,
  peerConfirmed: false,
  verified: false,
  safetyCode: null,
  closed: false
};

const statusEl = document.getElementById('status');
const createBtn = document.getElementById('createBtn');
const createSection = document.getElementById('createSection');
const inviteSection = document.getElementById('inviteSection');
const inviteUrlInput = document.getElementById('inviteUrl');
const verifySection = document.getElementById('verifySection');
const safetyCodeEl = document.getElementById('safetyCode');
const confirmCodeBtn = document.getElementById('confirmCodeBtn');
const chatSection = document.getElementById('chatSection');
const messagesEl = document.getElementById('messages');
const chatForm = document.getElementById('chatForm');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');

function setStatus(text) {
  statusEl.textContent = text;
}

function appendMessage(kind, text) {
  const div = document.createElement('div');
  div.className = `msg ${kind}`;
  div.textContent = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function ensureCryptoAvailable() {
  // Fails closed if required browser crypto primitives are missing.
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API unavailable');
  }
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) arr[i] = bin.charCodeAt(i);
  return arr;
}

function bytesToB64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function generateX25519() {
  return crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
}

async function exportRawPublic(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

async function importPeerPublic(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'X25519' }, false, []);
}

async function deriveRootFromECDH(myPrivateKey, peerPublicKey, saltBytes) {
  // ECDH -> HKDF -> AES key derivation (NIST-compatible primitives only).
  const sharedBits = await crypto.subtle.deriveBits({ name: 'X25519', public: peerPublicKey }, myPrivateKey, 256);
  const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: new TextEncoder().encode('minimal-secure-chat/root-v1')
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveMessageKey(counter, direction) {
  const rootBytes = await crypto.subtle.exportKey('raw', state.rootKey);
  const hkdfKey = await crypto.subtle.importKey('raw', rootBytes, 'HKDF', false, ['deriveKey']);
  const salt = new Uint8Array(16);
  const view = new DataView(salt.buffer);
  view.setUint32(0, counter, false);
  view.setUint8(4, direction === 'send' ? 1 : 2);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('minimal-secure-chat/msg-v1')
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function wsSend(msg) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    throw new Error('Socket not connected');
  }
  state.ws.send(JSON.stringify(msg));
}

async function computeSafetyCode(pubA, pubB) {
  const sorted = [pubA, pubB].sort((a, b) => {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i += 1) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });

  const transcript = new Uint8Array(sorted[0].length + sorted[1].length);
  transcript.set(sorted[0], 0);
  transcript.set(sorted[1], sorted[0].length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', transcript));
  const codeBytes = digest.slice(0, 6);
  return Array.from(codeBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function resetVerificationState() {
  state.localConfirmed = false;
  state.peerConfirmed = false;
  state.verified = false;
  state.safetyCode = null;
  confirmCodeBtn.disabled = false;
  safetyCodeEl.textContent = '----';
  verifySection.classList.add('hidden');
  chatSection.classList.add('hidden');
}

function maybeEnableChat() {
  if (!state.localConfirmed || !state.peerConfirmed) return;
  state.verified = true;
  verifySection.classList.add('hidden');
  chatSection.classList.remove('hidden');
  sendBtn.disabled = false;
  setStatus('Secure channel active and verified.');
}

async function sendEncrypted(plaintext) {
  if (!state.rootKey || !state.verified) throw new Error('Verified key not established');

  state.sendCounter += 1;
  const key = await deriveMessageKey(state.sendCounter, 'send');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`c:${state.sendCounter}`);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext)
  );

  wsSend({
    type: 'ciphertext',
    counter: state.sendCounter,
    iv: bytesToB64(iv),
    data: bytesToB64(new Uint8Array(ciphertext))
  });
}

async function decryptIncoming(counter, ivB64, dataB64) {
  if (!state.rootKey || !state.verified) throw new Error('Verified key not established');
  if (!Number.isInteger(counter) || counter <= state.recvCounter) {
    throw new Error('Replay or invalid counter');
  }
  const key = await deriveMessageKey(counter, 'recv');
  const iv = b64ToBytes(ivB64);
  const data = b64ToBytes(dataB64);
  const aad = new TextEncoder().encode(`c:${counter}`);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    data
  );
  state.recvCounter = counter;
  return new TextDecoder().decode(plaintext);
}

async function startHandshakeIfInitiator() {
  if (state.slot !== 1) return;
  const pub = await exportRawPublic(state.myStaticKeyPair.publicKey);
  state.myStaticPublicBytes = pub;
  wsSend({ type: 'key_init', publicKey: bytesToB64(pub) });
  setStatus('Waiting for peer key exchange...');
}

async function establishInitialKey(peerPubB64) {
  state.peerStaticPublicBytes = b64ToBytes(peerPubB64);
  state.peerStaticPublicKey = await importPeerPublic(state.peerStaticPublicBytes);
  const zeroSalt = new Uint8Array(32);
  state.rootKey = await deriveRootFromECDH(state.myStaticKeyPair.privateKey, state.peerStaticPublicKey, zeroSalt);
  state.sendCounter = 0;
  state.recvCounter = 0;
  resetVerificationState();

  state.safetyCode = await computeSafetyCode(state.myStaticPublicBytes, state.peerStaticPublicBytes);
  safetyCodeEl.textContent = state.safetyCode;
  verifySection.classList.remove('hidden');
  sendBtn.disabled = true;
  setStatus('Compare security code with peer, then confirm.');

  if (!state.rekeyTimer) {
    // Periodic rekey for forward secrecy window reduction.
    state.rekeyTimer = setInterval(() => {
      if (state.slot === 1 && !state.pendingRekeyId && state.verified) {
        initiateRekey().catch(() => closeSession('Rekey failed'));
      }
    }, 120000);
  }
}

async function initiateRekey() {
  const offerPair = await generateX25519();
  const offerPub = await exportRawPublic(offerPair.publicKey);
  const rekeyId = crypto.randomUUID();
  state.pendingRekeyOffer = offerPair;
  state.pendingRekeyId = rekeyId;
  wsSend({ type: 'key_rotate', stage: 'offer', rekeyId, publicKey: bytesToB64(offerPub) });
}

async function handleRekeyOffer(msg) {
  if (state.slot !== 2) return;
  const peerOfferPubBytes = b64ToBytes(msg.publicKey);
  const peerOfferPub = await importPeerPublic(peerOfferPubBytes);
  const answerPair = await generateX25519();
  const answerPub = await exportRawPublic(answerPair.publicKey);

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const nextRoot = await deriveRootFromECDH(answerPair.privateKey, peerOfferPub, salt);
  state.myStaticKeyPair = answerPair;
  state.myStaticPublicBytes = answerPub;
  state.peerStaticPublicBytes = peerOfferPubBytes;
  state.rootKey = nextRoot;
  state.sendCounter = 0;
  state.recvCounter = 0;
  resetVerificationState();

  state.safetyCode = await computeSafetyCode(state.myStaticPublicBytes, state.peerStaticPublicBytes);
  safetyCodeEl.textContent = state.safetyCode;
  verifySection.classList.remove('hidden');
  sendBtn.disabled = true;
  setStatus('Keys rotated. Re-verify security code with peer.');

  wsSend({
    type: 'key_rotate',
    stage: 'answer',
    rekeyId: msg.rekeyId,
    publicKey: bytesToB64(answerPub),
    salt: bytesToB64(salt)
  });

  appendMessage('peer', '[security] keys rotated - verification required');
}

async function handleRekeyAnswer(msg) {
  if (state.slot !== 1) return;
  if (!state.pendingRekeyOffer || state.pendingRekeyId !== msg.rekeyId) return;
  const peerAnswerPubBytes = b64ToBytes(msg.publicKey);
  const peerAnswerPub = await importPeerPublic(peerAnswerPubBytes);
  const salt = b64ToBytes(msg.salt);

  state.rootKey = await deriveRootFromECDH(state.pendingRekeyOffer.privateKey, peerAnswerPub, salt);
  state.myStaticKeyPair = state.pendingRekeyOffer;
  state.myStaticPublicBytes = await exportRawPublic(state.myStaticKeyPair.publicKey);
  state.peerStaticPublicBytes = peerAnswerPubBytes;
  state.pendingRekeyOffer = null;
  state.pendingRekeyId = null;
  state.sendCounter = 0;
  state.recvCounter = 0;
  resetVerificationState();

  state.safetyCode = await computeSafetyCode(state.myStaticPublicBytes, state.peerStaticPublicBytes);
  safetyCodeEl.textContent = state.safetyCode;
  verifySection.classList.remove('hidden');
  sendBtn.disabled = true;
  setStatus('Keys rotated. Re-verify security code with peer.');
  appendMessage('peer', '[security] keys rotated - verification required');
}

function closeSession(reason) {
  if (state.closed) return;
  state.closed = true;
  setStatus(reason);
  verifySection.classList.add('hidden');
  chatSection.classList.add('hidden');
  createSection.classList.remove('hidden');
  inviteSection.classList.add('hidden');

  if (state.rekeyTimer) clearInterval(state.rekeyTimer);
  state.rekeyTimer = null;

  // Best-effort zeroization of in-memory secrets.
  state.rootKey = null;
  state.peerStaticPublicKey = null;
  state.peerStaticPublicBytes = null;
  state.myStaticKeyPair = null;
  state.myStaticPublicBytes = null;
  state.pendingRekeyOffer = null;
  state.pendingRekeyId = null;
  state.sendCounter = 0;
  state.recvCounter = 0;
  resetVerificationState();

  if (state.ws && state.ws.readyState <= WebSocket.OPEN) {
    state.ws.close();
  }
  state.ws = null;
}

async function connectSocket() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws = ws;

  ws.addEventListener('open', () => {
    wsSend({ type: 'join', sessionId: state.sessionId });
  });

  ws.addEventListener('message', async (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      closeSession('Protocol error');
      return;
    }

    try {
      if (msg.type === 'joined') {
        state.slot = msg.slot;
        setStatus('Connected. Waiting for second participant...');
      } else if (msg.type === 'peer_ready') {
        setStatus('Peer connected. Starting key exchange...');
        state.myStaticKeyPair = await generateX25519();
        await startHandshakeIfInitiator();
      } else if (msg.type === 'key_init') {
        if (state.slot !== 2) return;
        if (!state.myStaticKeyPair) {
          state.myStaticKeyPair = await generateX25519();
        }
        state.myStaticPublicBytes = await exportRawPublic(state.myStaticKeyPair.publicKey);
        await establishInitialKey(msg.publicKey);
        wsSend({ type: 'key_response', publicKey: bytesToB64(state.myStaticPublicBytes) });
      } else if (msg.type === 'key_response') {
        if (state.slot !== 1) return;
        await establishInitialKey(msg.publicKey);
      } else if (msg.type === 'key_rotate') {
        if (msg.stage === 'offer') await handleRekeyOffer(msg);
        if (msg.stage === 'answer') await handleRekeyAnswer(msg);
      } else if (msg.type === 'auth_confirm') {
        state.peerConfirmed = true;
        maybeEnableChat();
      } else if (msg.type === 'ciphertext') {
        const plaintext = await decryptIncoming(msg.counter, msg.iv, msg.data);
        appendMessage('peer', `Peer: ${plaintext}`);
      } else if (msg.type === 'session_closed') {
        closeSession(msg.reason || 'Session ended');
      } else if (msg.type === 'error') {
        closeSession(`Error: ${msg.code}`);
      }
    } catch {
      closeSession('Security error; session closed');
    }
  });

  ws.addEventListener('close', () => {
    if (!state.closed) closeSession('Disconnected');
  });

  ws.addEventListener('error', () => {
    if (!state.closed) closeSession('Transport error');
  });
}

confirmCodeBtn.addEventListener('click', () => {
  if (!state.safetyCode || state.localConfirmed) return;
  state.localConfirmed = true;
  confirmCodeBtn.disabled = true;
  wsSend({ type: 'auth_confirm' });
  maybeEnableChat();
  if (!state.verified) {
    setStatus('Waiting for peer confirmation...');
  }
});

createBtn.addEventListener('click', async () => {
  try {
    ensureCryptoAvailable();
    setStatus('Creating one-time session...');
    const resp = await fetch('/api/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    if (!resp.ok) throw new Error('Failed to create session');
    const data = await resp.json();
    state.sessionId = data.sessionId;
    state.closed = false;

    inviteUrlInput.value = data.inviteUrl;
    createSection.classList.add('hidden');
    inviteSection.classList.remove('hidden');
    setStatus('Share the invite link once. Waiting for peer...');

    await connectSocket();
  } catch (error) {
    setStatus(`Cannot start secure chat: ${error.message}`);
  }
});

chatForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text) return;
  messageInput.value = '';
  try {
    await sendEncrypted(text);
    appendMessage('me', `You: ${text}`);
    if (state.slot === 1 && state.sendCounter % 25 === 0 && !state.pendingRekeyId) {
      // Additional message-count based rekeying for more frequent FS updates.
      await initiateRekey();
    }
  } catch {
    closeSession('Failed to send encrypted message');
  }
});

(() => {
  try {
    ensureCryptoAvailable();
  } catch (err) {
    setStatus(`Security requirement not met: ${err.message}`);
    createBtn.disabled = true;
    return;
  }

  const invite = new URLSearchParams(location.search).get('invite');
  if (invite) {
    state.sessionId = invite;
    state.closed = false;
    createSection.classList.add('hidden');
    inviteSection.classList.add('hidden');
    setStatus('Joining secure session...');
    connectSocket().catch(() => closeSession('Failed to connect'));
  } else {
    setStatus('Ready. Create a secure one-time session.');
  }
})();

addEventListener('beforeunload', () => {
  closeSession('Tab closed');
});
