// nft-login-server.js
require('dotenv').config();
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// === Ethers wiring (v5/v6 compatible) ===
const { ethers } = require('ethers');
const isAddress         = ethers.utils?.isAddress         || ethers.isAddress;
const keccak256         = ethers.utils?.keccak256         || ethers.keccak256;
const toUtf8Bytes       = ethers.utils?.toUtf8Bytes       || ethers.toUtf8Bytes;
const JsonRpcProvider   = ethers.providers?.JsonRpcProvider || ethers.JsonRpcProvider;
const parseUnits        = ethers.utils?.parseUnits        || ethers.parseUnits;
const solidityPack      = ethers.utils?.solidityPack      || ethers.solidityPack;
const hexlify           = ethers.utils?.hexlify           || ethers.hexlify;
const randomBytes       = ethers.utils?.randomBytes       || ethers.randomBytes;
const formatUnits       = ethers.utils?.formatUnits       || ((bn, unit) => String(bn)); // used only for fee logging

const RPC_URL                    = process.env.RPC_URL;               // e.g. https://polygon-mainnet.g.alchemy.com/v2/xxx
const CONTRACT_ADDRESS           = process.env.CONTRACT_ADDRESS;      // PersonaAuth final contract (deployed)
const DEPLOYER_PRIVATE_KEY       = process.env.DEPLOYER_PRIVATE_KEY;  // pays gas (separate from role keys)
const MINTER_PRIVATE_KEY         = process.env.MINTER_PRIVATE_KEY;    // signs EIP-712 MintAuth (must match MINTER_ROLE)
const USER_PEPPER                = process.env.USER_COMMITMENT_PEPPER;   // server-side secret (do NOT leak)
const DEVICE_PEPPER              = process.env.DEVICE_COMMITMENT_PEPPER; // server-side secret (do NOT leak)
const CARD_PUBKEY_PEM_PATH       = process.env.CARD_AUTH_PUBKEY_PEM_PATH || process.env.CARD_PUBKEY_PEM_PATH || "";
const CARD_PUBKEY_PEM_INLINE     = process.env.CARD_PUBKEY_PEM || "";

// ---------------------- Provider / Contract ----------------------
let provider, relayerSigner, personaAuth;
if (RPC_URL && CONTRACT_ADDRESS && DEPLOYER_PRIVATE_KEY && MINTER_PRIVATE_KEY && USER_PEPPER && DEVICE_PEPPER) {
  provider      = new JsonRpcProvider(RPC_URL);
  relayerSigner = new ethers.Wallet(DEPLOYER_PRIVATE_KEY, provider); // gas payer

  // PersonaAuth (final) ABI — only what we use
  const personaAuthAbi = [
    "function mintWithSig(address to, bytes32 userIdHash, bytes32 deviceHash, bytes32 salt, uint256 deadline, bytes sig) external",
    "function identityOf(uint256 tokenId) view returns (bytes32 userIdHash, bytes32 deviceHash, bool valid)",
    "function tokenOf(address user) view returns (uint256)",
    "function balanceOf(address owner) view returns (uint256)",
    "function locked(uint256 tokenId) view returns (bool)"
  ];

  personaAuth = new ethers.Contract(CONTRACT_ADDRESS, personaAuthAbi, relayerSigner);
} else {
  console.warn("⚠️ Minting disabled: set RPC_URL, CONTRACT_ADDRESS, DEPLOYER_PRIVATE_KEY, MINTER_PRIVATE_KEY, USER_COMMITMENT_PEPPER, DEVICE_COMMITMENT_PEPPER in env");
}

// --- Commitment helpers (peppered; no PII on-chain) ---
function commitUserId(email) {
  const norm = String(email || "").trim().toLowerCase();
  const packed = solidityPack(["string","string"], [norm, USER_PEPPER || ""]);
  return keccak256(packed);
}
function commitDevice(deviceFpr) {
  const val = String(deviceFpr || "").trim();
  const packed = solidityPack(["string","string"], [val, DEVICE_PEPPER || ""]);
  return keccak256(packed);
}

// --- Aggressive EIP-1559 fees for Polygon mainnet (v5/v6 compatible) ---
/**
 * Returns { maxFeePerGas, maxPriorityFeePerGas }.
 * Policy:
 *  - priority = max(suggestedPriority*3, 50 gwei)
 *  - baseFeeCeil = max(suggestedBase*3, 30 gwei)
 *  - maxFee = baseFeeCeil + priority
 */
async function getAggressiveFees(pvd) {
  const fd = await pvd.getFeeData();
  const toGwei = (wei) => {
    if (!wei) return 0;
    const s = wei.toString();
    return ethers.utils?.formatUnits ? Number(formatUnits(s, "gwei")) : (Number(s) / 1e9);
  };
  const suggestedPrio = toGwei(fd.maxPriorityFeePerGas ?? fd.gasPrice ?? 0);
  const suggestedBase = toGwei(fd.lastBaseFeePerGas ?? fd.gasPrice ?? 0);
  const prio = Math.max(Math.ceil(suggestedPrio * 3), 50);
  const base = Math.max(Math.ceil(suggestedBase * 3), 30);
  const maxPriorityFeePerGas = parseUnits(String(prio), "gwei");
  const maxFeePerGas         = parseUnits(String(base + prio), "gwei");
  return { maxFeePerGas, maxPriorityFeePerGas };
}

// v5/v6-safe typed data signing
const signTypedData = async (wallet, domain, types, value) => {
  if (typeof wallet._signTypedData === 'function') return wallet._signTypedData(domain, types, value);
  if (typeof wallet.signTypedData === 'function')   return wallet.signTypedData(domain, types, value);
  throw new Error('Wallet does not support EIP-712 signing');
};

// --- (Legacy helpers kept if needed elsewhere) ---
function normKeccak(input) {
  const norm = String(input || "").trim().toLowerCase();
  return keccak256(toUtf8Bytes(norm));
}
function anyEq(arr, val) {
  const v = String(val).toLowerCase();
  return Array.isArray(arr) && arr.some(x => String(x).toLowerCase() === v);
}

// ---------------------- App init ----------------------
const app = express();
app.use(express.json({ limit: '64kb' }));

// CORS — allow Chrome extensions; native apps / service workers send no Origin and don't need CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const isExtension = typeof origin === 'string' && origin.startsWith('chrome-extension://');
  if (isExtension) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// 🔐 Firebase Admin
let serviceAccount;
if (process.env.FIREBASE_CONFIG) {
  serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
} else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  const p = path.resolve(process.env.GOOGLE_APPLICATION_CREDENTIALS);
  serviceAccount = JSON.parse(fs.readFileSync(p, 'utf8'));
} else {
  throw new Error('No Firebase credentials: set FIREBASE_CONFIG or GOOGLE_APPLICATION_CREDENTIALS');
}
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });

// ---------- Load OpenPGP card auth public key (either env PEM or file PEM) ----------
let cardKeyFromPath = null;     // crypto.KeyObject
let cardKeyFromEnv  = null;     // crypto.KeyObject
let cardPathInfo    = null;     // { alg, modulusBits, spkiSha256 }
let cardEnvInfo     = null;     // { alg, modulusBits, spkiSha256 }

function describeKey(keyObj) {
  const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
  const sha256  = crypto.createHash('sha256').update(spkiDer).digest('base64');
  const details = keyObj.asymmetricKeyDetails || {};
  const modulusBits = details.modulusLength || null;
  return { alg: keyObj.asymmetricKeyType, modulusBits, spkiSha256: sha256 };
}

if (CARD_PUBKEY_PEM_PATH) {
  try {
    const pem = fs.readFileSync(path.resolve(CARD_PUBKEY_PEM_PATH), 'utf8');
    cardKeyFromPath = crypto.createPublicKey(pem); // SPKI PEM
    cardPathInfo    = describeKey(cardKeyFromPath);
    console.log(`🔐 Card key (path) loaded: alg=${cardPathInfo.alg}, bits=${cardPathInfo.modulusBits}, fp=${cardPathInfo.spkiSha256}`);
  } catch (e) {
    console.warn(`⚠️ Failed to load CARD_PUBKEY_PEM_PATH (${CARD_PUBKEY_PEM_PATH}): ${e.message}`);
  }
}
if (CARD_PUBKEY_PEM_INLINE) {
  try {
    cardKeyFromEnv = crypto.createPublicKey(CARD_PUBKEY_PEM_INLINE);
    cardEnvInfo    = describeKey(cardKeyFromEnv);
    console.log(`🔐 Card key (env)  loaded: alg=${cardEnvInfo.alg}, bits=${cardEnvInfo.modulusBits}, fp=${cardEnvInfo.spkiSha256}`);
  } catch (e) {
    console.error(`❌ Bad CARD_PUBKEY_PEM env: ${e.message}`);
  }
}

function getCardVerifyKey() {
  // Prefer explicit env string, then file path
  return cardKeyFromEnv || cardKeyFromPath || null;
}
function getActiveCardInfo() {
  return cardEnvInfo || cardPathInfo || null;
}

// ---------------------- In-memory stores (dev) ----------------------
let pendingLogins = {};          // { requestId: { email, websiteDomain?, status, timestamp, devicePublicKeyJwk?, extSession? } }
let userTokens = {};             // { email: deviceToken }
let userCredentials = {};        // { email: [ { id, name?, url?, enc, wrapped_key_session?, wrapped_key_device? } ] }
let pendingDecrypts = {};        // { txId: { email, credentialId, status, payload?, expiresAt?, createdAt } }
let sessionApprovals = {};       // { email: expiryMs }
let pendingCardChallenges = {};  // { email: { challenge, expiresAt } }

// Email verification (dev)
const pendingEmailCodes = {};    // { email: { code, expiresAt } }
const verifiedEmails     = {};   // { email: true }
const makeCode6 = () => String(Math.floor(100000 + Math.random() * 900000));

// ---------------------- Token registration ----------------------
app.post('/save-token', (req, res) => {
  const { email, deviceToken } = req.body || {};
  if (!email || !deviceToken) return res.status(400).json({ error: 'Email and deviceToken required' });
  userTokens[email] = deviceToken;
  console.log(`💾 Saved token for ${email}`);
  res.json({ success: true });
});

const db = {
  getUserByEmail: async (email) => {
    const token = userTokens[email] || process.env.TEST_PUSH_TOKEN;
    if (!token) return null;
    return { email, deviceToken: token };
  }
};

// ---------------------- Login approval flow ----------------------
app.post('/request-login', async (req, res) => {
  const { email, websiteDomain } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  const requestId = uuidv4();
  pendingLogins[requestId] = {
    email,
    websiteDomain: websiteDomain || null,
    status: 'pending',
    timestamp: Date.now(),
    devicePublicKeyJwk: null,
    extSession: null
  };

  const user = await db.getUserByEmail(email);
  const deviceToken = user?.deviceToken;
  if (!deviceToken) return res.status(404).json({ error: 'No device token registered' });

  const message = {
    token: deviceToken,
    notification: {
      title: 'NFT Auth Request',
      body: 'Approve or deny request'
    },
    data: {
      type: 'login_request',
      email,
      requestId,
      ...(websiteDomain ? { websiteDomain } : {})
    },
    android: { priority: 'high' },
    apns: { payload: { aps: { sound: 'default', category: 'LOGIN_REQUEST' } } }
  };

  try {
    await admin.messaging().send(message);
    console.log(`✅ Push sent to ${email} (${requestId})`);
    res.json({ success: true, requestId });
  } catch (error) {
    console.error("❌ FCM error:", error);
    res.status(500).json({ success: false, error: "Failed to send push notification" });
  }
});

app.post('/confirm-login', (req, res) => {
  const { requestId, approved, devicePublicKeyJwk } = req.body || {};
  const request = pendingLogins[requestId];
  if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

  request.status = approved ? 'approved' : 'denied';
  if (approved && devicePublicKeyJwk && devicePublicKeyJwk.x && devicePublicKeyJwk.y) {
    request.devicePublicKeyJwk = devicePublicKeyJwk;
    console.log(`📎 Stored devicePublicKeyJwk for ${requestId} (x.len=${devicePublicKeyJwk.x.length})`);
  } else if (approved) {
    console.warn(`⚠️ Approved but missing/invalid devicePublicKeyJwk for ${requestId}`);
  }

  res.json({ success: true, message: `Login ${approved ? 'approved' : 'denied'}` });
});

app.get('/check-login/:requestId', (req, res) => {
  const r = pendingLogins[req.params.requestId];
  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    success: true,
    status: r.status,
    devicePublicKeyJwk: r.devicePublicKeyJwk || null,
    extSession: r.extSession || null
  });
});

app.get('/get-session-handshake/:requestId', (req, res) => {
  const r = pendingLogins[req.params.requestId];
  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });

  res.setHeader('Cache-Control', 'no-store');
  if (r.status !== 'approved') return res.json({ success: true, found: false, status: r.status });
  if (!r.extSession) return res.json({ success: true, found: false, status: 'awaiting_handshake' });

  const { keyId, eph, salt } = r.extSession || {};
  return res.json({
    success: true,
    found: true,
    email: r.email,
    websiteDomain: r.websiteDomain || null,
    keyId, eph, salt
  });
});

// ---------------------- Email verify (dev) ----------------------
app.post('/start-email-verify', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ success: false, error: 'Missing email' });
  const code = makeCode6();
  pendingEmailCodes[email] = { code, expiresAt: Date.now() + 10 * 60 * 1000 };
  if (process.env.NODE_ENV !== 'production') {
    console.log(`📧 Email verify code for ${email}: ${code} (valid 10 min)`);
  }
  return res.json({ success: true });
});

app.post('/confirm-email-verify', (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ success: false, error: 'Missing fields' });
  const rec = pendingEmailCodes[email];
  if (!rec) return res.status(400).json({ success: false, error: 'No code pending' });
  if (Date.now() > rec.expiresAt) {
    delete pendingEmailCodes[email];
    return res.status(400).json({ success: false, error: 'Code expired' });
  }
  if (String(code).trim() !== rec.code) return res.status(400).json({ success: false, error: 'Invalid code' });
  verifiedEmails[email] = true;
  delete pendingEmailCodes[email];
  console.log(`✅ Email verified: ${email}`);
  return res.json({ success: true });
});

// ---------------------- Debug ----------------------
app.get("/debug", (req, res) => {
  res.json({ success: true, message: "This is the real nft-login-server.js" });
});

// Card key introspection
app.get('/card-pubkey-fp', (req, res) => {
  const active = getActiveCardInfo();
  if (!active) return res.status(503).json({ success: false, error: 'card key not loaded' });
  res.json({
    success: true,
    active,
    pathKey: cardPathInfo || null,
    envKey: cardEnvInfo || null,
    same: !!(cardPathInfo && cardEnvInfo && cardPathInfo.spkiSha256 === cardEnvInfo.spkiSha256)
  });
});

// --- Card challenge (to be signed by the card's Authentication key) ---
// POST /card-challenge { email }
// Returns { success, challenge, expiresAt, spec }
app.post('/card-challenge', (req, res) => {
  try {
    if (!getCardVerifyKey()) return res.status(503).json({ success: false, error: 'card key not loaded' });

    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email || !email.includes('@')) return res.status(400).json({ success: false, error: 'valid email required' });

    // Canonical message the client MUST sign (UTF-8 bytes)
    const now   = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex'); // 32 hex chars
    const challenge = `nftvault:card-auth|email=${email}|ts=${now}|nonce=${nonce}`;
    const ttlSec = 120; // 2 minutes

    pendingCardChallenges[email] = { challenge, expiresAt: Date.now() + ttlSec * 1000 };

    return res.json({
      success: true,
      challenge,
      expiresAt: now + ttlSec,
      spec: {
        algo: 'RSA-PKCS1v1_5-SHA256',
        encoding: 'UTF-8 bytes of challenge string',
        fieldOrder: 'literal string as returned (no JSON canonicalization)'
      }
    });
  } catch (e) {
    console.error('❌ /card-challenge:', e);
    return res.status(500).json({ success: false, error: 'challenge failed' });
  }
});

// ---------------------- Credentials storage ----------------------
app.post('/store-credentials', (req, res) => {
  const { email, deviceId, credentials } = req.body || {};
  if (!email || !deviceId || !Array.isArray(credentials)) {
    return res.status(400).json({ success: false, error: 'Missing or invalid fields' });
  }

  const hasLiveSession = sessionApprovals[email] && Date.now() < sessionApprovals[email];
  if (!verifiedEmails[email] && !hasLiveSession) {
    return res.status(403).json({ success: false, error: 'Session locked or expired' });
  }

  const token = userTokens[email] || process.env.TEST_PUSH_TOKEN;
  if (!token) return res.status(403).json({ success: false, error: 'Unregistered device' });

  userCredentials[email] = credentials;
  console.log(`💾 Stored ${credentials.length} encrypted credentials for ${email}`);
  return res.json({ success: true });
});

app.post('/get-credentials', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const token = userTokens[email] || process.env.TEST_PUSH_TOKEN || null;
  if (!token) return res.status(403).json({ error: 'No registered device token' });

  const creds = userCredentials[email] || [];
  console.log(`📤 Returned ${creds.length} credentials for ${email}`);
  res.json({ success: true, credentials: creds });
});

app.post('/delete-credential', (req, res) => {
  const { email, deviceId, credentialId } = req.body || {};
  console.log("🧠 Incoming DELETE request with:", { email, deviceId, credentialId });

  if (!email || !deviceId || !credentialId) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  const list = userCredentials[email];
  if (!Array.isArray(list)) return res.json({ success: true, removed: 0 });

  const target = String(credentialId).trim().toLowerCase();
  console.log("🧾 Existing IDs for", email, list.map(c => String(c?.id || '').toLowerCase()));

  const before = list.length;
  const updated = list.filter(c => String(c?.id || '').trim().toLowerCase() !== target);
  const removed = before - updated.length;

  userCredentials[email] = updated;

  console.log(`🗑️ Delete ${credentialId} for ${email} → removed=${removed} (before=${before}, after=${updated.length})`);
  return res.json({ success: true, removed });
});

app.post('/wipe-credentials', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });
  delete userCredentials[email];
  console.log(`🧹 Wiped all credentials for ${email}`);
  res.json({ success: true });
});

// ---------------------- Phone-assisted decrypt ----------------------
app.post('/request-decrypt', async (req, res) => {
  const { email, credentialId, label } = req.body || {};
  if (!email || !credentialId) return res.status(400).json({ success: false, error: 'email and credentialId required' });

  const user = await db.getUserByEmail(email);
  const deviceToken = user?.deviceToken;
  if (!deviceToken) return res.status(403).json({ success: false, error: 'No registered device token' });

  const txId = uuidv4();
  pendingDecrypts[txId] = {
    email,
    credentialId,
    status: 'pending',
    createdAt: Date.now()
  };

  const message = {
    token: deviceToken,
    notification: {
      title: 'Approve autofill?',
      body: `Send credential ${label || ''}`.trim() || 'Send credential to your browser?'
    },
    data: {
      type: 'decrypt_request',
      email,
      credentialId,
      txId
    },
    android: { priority: 'high' },
    apns: { payload: { aps: { sound: 'default', category: 'DECRYPT_REQUEST' } } }
  };

  try {
    await admin.messaging().send(message);
    console.log(`🔓 Decrypt request sent to ${email} (cred ${credentialId}, tx ${txId})`);
    res.json({ success: true, txId });
  } catch (e) {
    console.error("❌ FCM error (decrypt):", e);
    delete pendingDecrypts[txId];
    res.status(500).json({ success: false, error: 'Failed to send decrypt push' });
  }
});

app.post('/confirm-decrypt', (req, res) => {
  const { txId, approved, data } = req.body || {};
  const tx = pendingDecrypts[txId];
  if (!tx) return res.status(404).json({ success: false, error: 'Tx not found' });

  tx.status = approved ? 'approved' : 'denied';
  if (approved) {
    if (!data || typeof data.username !== 'string' || typeof data.password !== 'string') {
      return res.status(400).json({ success: false, error: 'Missing data' });
    }
    tx.payload  = { username: data.username, password: data.password };
    tx.expiresAt = Date.now() + 60_000; // 60s TTL
  }
  res.json({ success: true });
});

app.get('/check-decrypt/:txId', (req, res) => {
  const tx = pendingDecrypts[req.params.txId];
  if (!tx) return res.json({ success: true, found: false });

  if (tx.expiresAt && Date.now() > tx.expiresAt) {
    delete pendingDecrypts[req.params.txId];
    return res.json({ success: true, found: false, expired: true });
  }

  if (tx.status === 'approved' && tx.payload) {
    const data = tx.payload;
    delete pendingDecrypts[req.params.txId]; // consume once
    return res.json({ success: true, found: true, status: 'approved', data });
  }

  return res.json({ success: true, found: true, status: tx.status });
});

// ---------------------- Session handshake (extension -> phone) ----------------------
app.post('/post-session-handshake', (req, res) => {
  const { requestId, keyId, eph, salt } = req.body || {};
  const r = pendingLogins[requestId];

  console.log("🛰️  /post-session-handshake origin:", req.headers.origin || "(none)");
  console.log("🛰️  /post-session-handshake body keys:", Object.keys(req.body || {}));

  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });
  if (r.status !== 'approved') return res.status(409).json({ success: false, error: 'Login not approved yet' });
  if (!keyId || !eph || !eph.x || !eph.y || !salt) {
    return res.status(400).json({ success: false, error: 'Invalid handshake payload' });
  }

  r.extSession = { keyId, eph, salt };
  console.log(`🔐 Stored session handshake for ${r.email} requestId=${requestId} keyId=${keyId}`);

  // 2h session lease; allows saves/reads from the extension
  const TTL_MS = 2 * 60 * 60 * 1000;
  sessionApprovals[r.email] = Date.now() + TTL_MS;
  console.log(`🔓 Session approved for ${r.email} until ${new Date(sessionApprovals[r.email]).toISOString()}`);

  return res.json({ success: true });
});

// Beacon no-CORS fallback
app.get('/beacon/session-handshake', (req, res) => {
  const { requestId, keyId, x, y, salt } = req.query || {};
  const r = pendingLogins[String(requestId || '')];
  console.log("🛰️  beacon/session-handshake", { requestId, keyId, hasX: !!x, hasY: !!y, hasSalt: !!salt });

  if (!r) return res.status(404).end('nf');
  if (r.status !== 'approved') return res.status(409).end('not-approved');
  if (!keyId || !x || !y || !salt) return res.status(400).end('bad');

  r.extSession = { keyId: String(keyId), eph: { kty: "EC", crv: "P-256", x: String(x), y: String(y) }, salt: String(salt) };
  console.log(`🔐 [beacon] Stored extSession for ${r.email} requestId=${requestId} keyId=${keyId}`);

  // return 1x1 gif
  const buf = Buffer.from('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==', 'base64');
  res.setHeader('Content-Type', 'image/gif');
  res.end(buf);
});

// ---------------------- Cleanup ----------------------
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of Object.entries(pendingDecrypts)) {
    if ((v.expiresAt && now > v.expiresAt) || (now - (v.createdAt || 0) > 10 * 60_000)) {
      delete pendingDecrypts[k];
    }
  }
  for (const [k, v] of Object.entries(pendingLogins)) {
    if (now - (v.timestamp || 0) > 10 * 60_000) {
      delete pendingLogins[k];
    }
  }
  for (const [email, exp] of Object.entries(sessionApprovals)) {
    if (Date.now() > exp) delete sessionApprovals[email];
  }
  // Cleanup stale card challenges
  for (const [email, rec] of Object.entries(pendingCardChallenges)) {
    if (!rec || now > (rec.expiresAt || 0)) delete pendingCardChallenges[email];
  }
}, 60_000);

// ---------------------- Mint endpoints (EIP-712; no user on-chain) ----------------------
async function relayMintWithFallback(to, userIdHash, deviceHash, salt, deadline, signature) {
  const fee = await getAggressiveFees(provider);
  try {
    return await personaAuth.mintWithSig(to, userIdHash, deviceHash, salt, deadline, signature, {
      maxFeePerGas:         fee.maxFeePerGas,
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
    });
  } catch (e) {
    // Some RPCs refuse to estimate; retry with a conservative gasLimit
    if (String(e.code || '').includes('UNPREDICTABLE_GAS_LIMIT')) {
      console.warn('⚠️ estimateGas failed; retrying with manual gasLimit=250k');
      return await personaAuth.mintWithSig(to, userIdHash, deviceHash, salt, deadline, signature, {
        maxFeePerGas:         fee.maxFeePerGas,
        maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
        gasLimit: 250_000
      });
    }
    throw e;
  }
}

// Body: { email, deviceFpr, to }
app.post('/mint-nft', async (req, res) => {
  try {
    if (!personaAuth) return res.status(503).json({ success: false, error: 'Contract not configured' });

    const { email, deviceFpr, to } = req.body || {};
    if (!email || !deviceFpr || !to) return res.status(400).json({ success: false, error: 'email, deviceFpr, to required' });
    if (!isAddress(to)) return res.status(400).json({ success: false, error: 'Invalid recipient address' });

    // Gate by device push-registration (your existing policy)
    const token = userTokens[email] || process.env.TEST_PUSH_TOKEN || null;
    if (!token) return res.status(403).json({ success: false, error: 'No registered device token for this email' });

    // Commitments
    const userIdHash = commitUserId(email);
    const deviceHash = commitDevice(deviceFpr);

    // EIP-712 domain/types (Polygon mainnet)
    const domain = { name: "PersonaAuth", version: "1", chainId: 137, verifyingContract: CONTRACT_ADDRESS };
    const types  = { MintAuth: [
      { name: "to",          type: "address" },
      { name: "userIdHash",  type: "bytes32" },
      { name: "deviceHash",  type: "bytes32" },
      { name: "salt",        type: "bytes32" },
      { name: "deadline",    type: "uint256" },
    ]};

    const salt     = hexlify(randomBytes(32));
    const deadline = Math.floor(Date.now() / 1000) + 10 * 60;

    // Sign with MINTER role key (offline)
    const minter = new ethers.Wallet(MINTER_PRIVATE_KEY);
    const signature = await signTypedData(minter, domain, types, { to, userIdHash, deviceHash, salt, deadline });

    // Relay tx (gas payer) with fallback
    const tx = await relayMintWithFallback(to, userIdHash, deviceHash, salt, deadline, signature);
    console.log(`⛓️  mintWithSig → ${tx.hash}`);

    const rc = (typeof tx.wait === 'function') ? await tx.wait(1) : await provider.waitForTransaction(tx.hash, 1);

    // Optional: fetch tokenId via mapping
    let tokenId = null;
    try {
      const tid = await personaAuth.tokenOf(to);
      tokenId = tid?.toString?.() || String(tid);
    } catch {}

    return res.json({ success: true, txHash: tx.hash, confirmed: true, tokenId });
  } catch (err) {
    console.error('❌ /mint-nft error:', err);
    return res.status(500).json({ success: false, error: 'Mint failed', details: String(err.message || err) });
  }
});

// Back-compat alias
app.post('/mint-persona', async (req, res) => {
  try {
    if (!personaAuth) return res.status(503).json({ success: false, error: 'Contract not configured' });

    const { email, deviceFpr, to } = req.body || {};
    if (!email || !deviceFpr || !to) return res.status(400).json({ success: false, error: 'email, deviceFpr, to required' });
    if (!isAddress(to)) return res.status(400).json({ success: false, error: 'Invalid recipient address' });

    const token = userTokens[email] || process.env.TEST_PUSH_TOKEN || null;
    if (!token) return res.status(403).json({ success: false, error: 'No registered device token for this email' });

    const userIdHash = commitUserId(email);
    const deviceHash = commitDevice(deviceFpr);

    const domain = { name: "PersonaAuth", version: "1", chainId: 137, verifyingContract: CONTRACT_ADDRESS };
    const types  = { MintAuth: [
      { name: "to",          type: "address" },
      { name: "userIdHash",  type: "bytes32" },
      { name: "deviceHash",  type: "bytes32" },
      { name: "salt",        type: "bytes32" },
      { name: "deadline",    type: "uint256" },
    ]};

    const salt     = hexlify(randomBytes(32));
    const deadline = Math.floor(Date.now() / 1000) + 10 * 60;

    const minter = new ethers.Wallet(MINTER_PRIVATE_KEY);
    const signature = await signTypedData(minter, domain, types, { to, userIdHash, deviceHash, salt, deadline });

    const tx = await relayMintWithFallback(to, userIdHash, deviceHash, salt, deadline, signature);
    console.log(`⛓️  mintWithSig → ${tx.hash}`);

    const rc = (typeof tx.wait === 'function') ? await tx.wait(1) : await provider.waitForTransaction(tx.hash, 1);

    let tokenId = null;
    try {
      const tid = await personaAuth.tokenOf(to);
      tokenId = tid?.toString?.() || String(tid);
    } catch {}

    return res.json({ success: true, txHash: tx.hash, confirmed: true, tokenId });
  } catch (err) {
    console.error('❌ /mint-persona error:', err);
    return res.status(500).json({ success: false, error: String(err.message || err) });
  }
});

// Read-only: does this address own a PersonaAuth NFT?
app.get('/has-nft/:address', async (req, res) => {
  try {
    if (!personaAuth) {
      return res.status(503).json({ success: false, error: 'Contract not configured' });
    }
    const address = String(req.params.address || '').trim();
    if (!isAddress(address)) {
      return res.status(400).json({ success: false, error: 'Bad address' });
    }

    const bal = await personaAuth.balanceOf(address);
    const has = bal.gt ? bal.gt(0) : (BigInt(bal) > 0n);

    // Optional: fetch tokenId via mapping (one-per-wallet)
    let tokenIds = [];
    if (has) {
      try {
        const tid = await personaAuth.tokenOf(address);
        const s   = tid?.toString?.() || String(tid);
        if (s && s !== "0") tokenIds.push(s);
      } catch {}
    }

    return res.json({
      success: true,
      hasNFT: has,
      balance: bal.toString(),
      tokenIds
    });
  } catch (err) {
    console.error('❌ /has-nft error:', err);
    return res.status(500).json({ success: false, error: String(err.message || err) });
  }
});

// --- READ: does this address own at least 1 PNA? ---
app.get('/nft-owned', async (req, res) => {
  try {
    if (!provider || !CONTRACT_ADDRESS) {
      return res.status(503).json({ success: false, error: 'Read contract not configured' });
    }
    const addr = String(req.query.address || '').trim();
    if (!addr || !isAddress(addr)) {
      return res.status(400).json({ success: false, error: 'Valid address required' });
    }

    const readAbi = [
      "function balanceOf(address owner) view returns (uint256)",
      "function tokenOf(address user) view returns (uint256)",
      "function identityOf(uint256 tokenId) view returns (bytes32 userIdHash, bytes32 deviceHash, bool valid)"
    ];
    const personaRead = new ethers.Contract(CONTRACT_ADDRESS, readAbi, provider);

    const bal = await personaRead.balanceOf(addr);
    const owned = bal.gt ? bal.gt(0) : (BigInt(bal) > 0n);
    return res.json({ success: true, owned, balance: bal.toString() });
  } catch (e) {
    console.error('❌ /nft-owned:', e);
    return res.status(500).json({ success: false, error: 'query failed' });
  }
});

// --- READ+VERIFY: optional strict match on email/deviceFpr (commitments) ---
app.post('/nft-owned-verify', async (req, res) => {
  try {
    if (!provider || !CONTRACT_ADDRESS) {
      return res.status(503).json({ success: false, error: 'Read contract not configured' });
    }
    const { address, email, deviceFpr } = req.body || {};
    if (!address || !isAddress(address)) {
      return res.status(400).json({ success: false, error: 'Valid address required' });
    }

    const readAbi = [
      "function balanceOf(address owner) view returns (uint256)",
      "function tokenOf(address user) view returns (uint256)",
      "function identityOf(uint256 tokenId) view returns (bytes32 userIdHash, bytes32 deviceHash, bool valid)"
    ];
    const personaRead = new ethers.Contract(CONTRACT_ADDRESS, readAbi, provider);

    const bal = await personaRead.balanceOf(address);
    const owned = bal.gt ? bal.gt(0) : (BigInt(bal) > 0n);
    if (!owned) return res.json({ success: true, owned: false, matched: false });

    const tokenId = await personaRead.tokenOf(address);
    const tidStr  = tokenId?.toString?.() || String(tokenId || "0");
    if (tidStr === "0") return res.json({ success: true, owned: true, matched: false });

    const id = await personaRead.identityOf(tokenId);
    const onUser   = id.userIdHash || id[0];
    const onDevice = id.deviceHash || id[1];

    const wantEmail   = email ? String(email).trim() : null;
    const wantDevice  = deviceFpr ? String(deviceFpr).trim() : null;
    const emailOk     = wantEmail  ? (commitUserId(wantEmail).toLowerCase()  === String(onUser).toLowerCase())   : true;
    const deviceOk    = wantDevice ? (commitDevice(wantDevice).toLowerCase() === String(onDevice).toLowerCase()) : true;

    return res.json({ success: true, owned: true, matched: !!(emailOk && deviceOk), tokenId: tidStr });
  } catch (e) {
    console.error('❌ /nft-owned-verify:', e);
    return res.status(500).json({ success: false, error: 'verify failed' });
  }
});

// GET /tx-receipt?hash=0x...
app.get('/tx-receipt', async (req, res) => {
  try {
    if (!provider) return res.status(503).json({ success: false, error: 'provider not configured' });
    const hash = String(req.query.hash || '').trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
      return res.status(400).json({ success: false, error: 'bad hash' });
    }
    const r = await provider.getTransactionReceipt(hash);
    if (!r) return res.json({ success: true, found: false });
    return res.json({
      success: true,
      found: true,
      status: typeof r.status === 'number' ? r.status : null,
      blockNumber: r.blockNumber ?? null
    });
  } catch (e) {
    console.error('❌ /tx-receipt:', e);
    return res.status(500).json({ success: false, error: 'lookup failed' });
  }
});

// Runtime status
app.get('/runtime', async (req, res) => {
  try {
    const net = provider ? await provider.getNetwork() : null;
    let minterAddr = null;
    try { if (MINTER_PRIVATE_KEY) minterAddr = new ethers.Wallet(MINTER_PRIVATE_KEY).address; } catch {}
    return res.json({
      configured: !!personaAuth,
      contractAddress_env: CONTRACT_ADDRESS || null,
      personaAuth_connected: personaAuth?.address || null,
      relayerAddress: relayerSigner?.address || null,
      minterAddress: minterAddr,
      network: net ? { chainId: String(net.chainId), name: net.name } : null
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// --- Card verify (RSA-PKCS1v1_5 + SHA-256) ---
app.post('/card-verify', (req, res) => {
  try {
    const { email, challenge, signatureB64 } = req.body || {};
    if (!email || !challenge || !signatureB64) {
      return res.status(400).json({ success: false, error: 'email, challenge, signatureB64 required' });
    }
    if (!challenge.startsWith('nftvault:card-auth|')) {
      return res.status(400).json({ success: false, error: 'bad challenge prefix' });
    }

    const verifierKey = getCardVerifyKey();
    if (!verifierKey) {
      return res.status(503).json({ success: false, error: 'card key not loaded' });
    }

    // Parse fields
    const fields = Object.fromEntries(
      challenge.split('|').slice(1).map(kv => {
        const i = kv.indexOf('=');
        return i === -1 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)];
      })
    );

    const emailNorm = String(email).trim().toLowerCase();
    if (fields.email !== emailNorm) {
      return res.status(400).json({ success: false, error: 'email mismatch' });
    }

    // Require the challenge we issued (one-time, not expired)
    const rec = pendingCardChallenges[emailNorm];
    if (!rec || rec.challenge !== challenge || Date.now() > rec.expiresAt) {
      return res.status(400).json({ success: false, error: 'challenge not issued or expired' });
    }

    // Timestamp skew check
    const ts = Number(fields.ts);
    if (!Number.isFinite(ts)) return res.status(400).json({ success: false, error: 'bad ts' });
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > 5 * 60) {
      return res.status(400).json({ success: false, error: 'stale/future challenge', now, ts });
    }

    // Nonce sanity (16 bytes hex)
    if (!/^[0-9a-f]{32}$/i.test(String(fields.nonce || ''))) {
      return res.status(400).json({ success: false, error: 'bad nonce' });
    }

    // Verify RSA-PKCS1v1_5 + SHA-256 over UTF-8 challenge string
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(Buffer.from(challenge, 'utf8'));
    verifier.end();

    const sig = Buffer.from(signatureB64, 'base64');
    const ok = verifier.verify(verifierKey, sig);
    if (!ok) return res.status(400).json({ success: false, verified: false });

    delete pendingCardChallenges[emailNorm]; // one-time use

    return res.json({
      success: true,
      verified: true,
      email: emailNorm,
      ts,
      nonce: fields.nonce || null
    });
  } catch (e) {
    console.error('❌ /card-verify error:', e);
    return res.status(500).json({ success: false, error: 'verify failed' });
  }
});

// ---------------------- Start ----------------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`NFT Login server running on port ${PORT}`);
});
