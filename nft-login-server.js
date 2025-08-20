// nft-login-server.js
require('dotenv').config();
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');

// === Owner mint wiring (ethers v5) ===
const { ethers } = require('ethers');

const RPC_URL          = process.env.RPC_URL;             // e.g. https://polygon-mainnet.infura.io/v3/...
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;    // PersonaAuth contract
const OWNER_PRIVATE_KEY= process.env.OWNER_PRIVATE_KEY;   // owner key that deployed PersonaAuth

let provider, ownerSigner, personaAuth;
if (RPC_URL && CONTRACT_ADDRESS && OWNER_PRIVATE_KEY) {
  provider    = new ethers.providers.JsonRpcProvider(RPC_URL);
  ownerSigner = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);

  const personaAuthAbi = [
    "function safeMint(address to, bytes32[3] emailHashes, bytes32[3] deviceIdHashes) public"
  ];
  personaAuth = new ethers.Contract(CONTRACT_ADDRESS, personaAuthAbi, ownerSigner);
} else {
  console.warn("⚠️ Minting disabled: set RPC_URL, CONTRACT_ADDRESS, OWNER_PRIVATE_KEY in env");
}

// helpers
const ZERO32 = "0x0000000000000000000000000000000000000000000000000000000000000000";
function keccakUtf8(s) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(String(s || "")));
}
function makeHashTriplet(value) {
  // Minimal, explicit: first slot = keccak(value), rest zeroes (easy to change later)
  const h = keccakUtf8(value);
  return [h, ZERO32, ZERO32];
}


const app = express();
app.use(express.json());

// CORS (web demos); extensions can still call without ACAO if host-permissioned
// CORS — allow Webflow, and also Chrome extensions + no-origin (service workers sometimes omit)
const allowedOrigins = new Set([
    "https://nft-auth-two.webflow.io",
    "https://linear-template-48cfc7.webflow.io",
]);
  
app.use((req, res, next) => {
    const origin = req.headers.origin || "*";
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.sendStatus(200);
    next();
});

// 🔐 Firebase
const fs = require('fs');
let serviceAccount;

if (process.env.FIREBASE_CONFIG) {
  // Option A: creds provided inline as JSON string env var
  serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
} else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  // Option B: path to JSON file (what your .env uses)
  const p = path.resolve(process.env.GOOGLE_APPLICATION_CREDENTIALS);
  serviceAccount = JSON.parse(fs.readFileSync(p, 'utf8'));
} else {
  throw new Error('No Firebase credentials: set FIREBASE_CONFIG or GOOGLE_APPLICATION_CREDENTIALS');
}

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });


// In-memory stores (dev)
let pendingLogins = {};     // { requestId: { email, websiteDomain?, status, timestamp, devicePublicKeyJwk?, extSession? } }
let userTokens = {};        // { email: deviceToken }
let userCredentials = {};   // { email: [ { id, name?, url?, enc, wrapped_key_session?, wrapped_key_device? } ] }

// Phone-assisted decrypt state
let pendingDecrypts = {};   // { txId: { email, credentialId, status, payload?, expiresAt?, createdAt } }

let sessionApprovals = {}; 


// Email verification (dev)
const pendingEmailCodes = {};   // { email: { code, expiresAt } }
const verifiedEmails     = {};   // { email: true }
const makeCode6 = () => String(Math.floor(100000 + Math.random() * 900000));

// Save device token from the app
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

// at top-level
const logins = new Map(); // (unused alias, keeping for compatibility comments)

// 🔐 Request login → sends push to device
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
        // ⬇️ Updated copy
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
  

// ✅ App confirms login decision (and provides phone public key)
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

// Frontend (extension or web) polls login status
app.get('/check-login/:requestId', (req, res) => {
  const r = pendingLogins[req.params.requestId];
  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });
  res.setHeader('Cache-Control', 'no-store'); // ⭐ CHANGED: avoid any intermediary caching
  res.json({
    success: true,
    status: r.status,
    devicePublicKeyJwk: r.devicePublicKeyJwk || null,
    extSession: r.extSession || null
  });
});

// ⭐ NEW: Phone polls for the extension’s session handshake after approval
app.get('/get-session-handshake/:requestId', (req, res) => {
  const r = pendingLogins[req.params.requestId];
  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });

  res.setHeader('Cache-Control', 'no-store');
  if (r.status !== 'approved') {
    return res.json({ success: true, found: false, status: r.status });
  }
  if (!r.extSession) {
    return res.json({ success: true, found: false, status: 'awaiting_handshake' });
  }
  const { keyId, eph, salt } = r.extSession || {};
  return res.json({
    success: true,
    found: true,
    email: r.email,
    websiteDomain: r.websiteDomain || null,
    keyId, eph, salt
  });
});

// Email verification (dev: code is logged to server)
app.post('/start-email-verify', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ success: false, error: 'Missing email' });
  const code = makeCode6();
  pendingEmailCodes[email] = { code, expiresAt: Date.now() + 10 * 60 * 1000 };
  console.log(`📧 Email verify code for ${email}: ${code} (valid 10 min)`);
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
  if (String(code).trim() !== rec.code) {
    return res.status(400).json({ success: false, error: 'Invalid code' });
  }
  verifiedEmails[email] = true;
  delete pendingEmailCodes[email];
  console.log(`✅ Email verified: ${email}`);
  return res.json({ success: true });
});

app.get("/debug", (req, res) => {
  res.json({ success: true, message: "This is the real nft-login-server.js" });
});

// ===== Credentials (encrypted blobs) =====
app.post('/store-credentials', (req, res) => {
    const { email, deviceId, credentials } = req.body || {};
    if (!email || !deviceId || !Array.isArray(credentials)) {
      return res.status(400).json({ success: false, error: 'Missing or invalid fields' });
    }
  
    // Allow if (a) the old email verification is present OR (b) a push-approved session lease is active
    const hasLiveSession = sessionApprovals[email] && Date.now() < sessionApprovals[email];
    if (!verifiedEmails[email] && !hasLiveSession) {
      return res.status(403).json({ success: false, error: 'Session locked or expired' });
    }
  
    // Require a registered device token (phone owns the NFT)
    const token = userTokens[email] || process.env.TEST_PUSH_TOKEN;
    if (!token) return res.status(403).json({ success: false, error: 'Unregistered device' });
  
    // Persist encrypted blobs (source of truth is the phone; these are opaque to server/extension)
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
  if (!Array.isArray(list)) {
    return res.json({ success: true, removed: 0 }); // idempotent
  }

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

/* =======================================================
   🔐 Phone-assisted decrypt (no secrets in extension)
   ======================================================= */
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


// Extension posts its per-session handshake so the phone can derive the same key
// Body: { requestId, keyId, eph: {kty:"EC", crv:"P-256", x, y}, salt }
app.post('/post-session-handshake', (req, res) => {
    const { requestId, keyId, eph, salt } = req.body || {};
    const r = pendingLogins[requestId];
  
    console.log("🛰️  /post-session-handshake origin:", req.headers.origin || "(none)");
    console.log("🛰️  /post-session-handshake body keys:", Object.keys(req.body || {}));
  
    if (!r) return res.status(404).json({ success: false, error: 'Request not found' });
    if (r.status !== 'approved') {
      return res.status(409).json({ success: false, error: 'Login not approved yet' });
    }
    if (!keyId || !eph || !eph.x || !eph.y || !salt) {
      return res.status(400).json({ success: false, error: 'Invalid handshake payload' });
    }
  
    r.extSession = { keyId, eph, salt };
    console.log(`🔐 Stored session handshake for ${r.email} requestId=${requestId} keyId=${keyId}`);
  
    // ✅ Grant a 2h session lease for this email (used to allow saves/reads from the extension)
    const TTL_MS = 2 * 60 * 60 * 1000;
    sessionApprovals[r.email] = Date.now() + TTL_MS;
    console.log(`🔓 Session approved for ${r.email} until ${new Date(sessionApprovals[r.email]).toISOString()}`);
  
    return res.json({ success: true });
});


// Debug: what tokens we have
app.get('/debug-tokens', (req, res) => {
  res.json({
    success: true,
    emails: Object.keys(userTokens),
    tokens: userTokens,
  });
});

// --- Beacon fallback for extension handshake (no CORS preflight) ---
app.get('/beacon/session-handshake', (req, res) => {
    const { requestId, keyId, x, y, salt } = req.query || {};
    const r = pendingLogins[String(requestId || '')];
    console.log("🛰️  beacon/session-handshake", { requestId, keyId, hasX: !!x, hasY: !!y, hasSalt: !!salt });
  
    if (!r) return res.status(404).end('nf');
    if (r.status !== 'approved') return res.status(409).end('not-approved');
    if (!keyId || !x || !y || !salt) return res.status(400).end('bad');
  
    r.extSession = {
      keyId: String(keyId),
      eph: { kty: "EC", crv: "P-256", x: String(x), y: String(y) },
      salt: String(salt)
    };
  
    console.log(`🔐 [beacon] Stored extSession for ${r.email} requestId=${requestId} keyId=${keyId}`);
  
    // tiny 1x1 gif so we can return image content for no-cors fetch
    const buf = Buffer.from('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==', 'base64');
    res.setHeader('Content-Type', 'image/gif');
    res.end(buf);
});
  

// Cleanup
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
}, 60_000);


// === Owner-signed mint endpoint ===
// Body: { email, deviceId, to }  -> mints to `to`
app.post('/mint-nft', async (req, res) => {
    try {
      if (!personaAuth || !ownerSigner) {
        return res.status(503).json({ success: false, error: 'Minting not configured on server' });
      }
  
      const { email, deviceId, to } = req.body || {};
      if (!email || !to) {
        return res.status(400).json({ success: false, error: 'email and to are required' });
      }
      if (!ethers.utils.isAddress(to)) {
        return res.status(400).json({ success: false, error: 'Invalid recipient address' });
      }
  
      // Basic gate: only allow if this email has a registered device token (your current trust anchor)
      const token = userTokens[email] || process.env.TEST_PUSH_TOKEN || null;
      if (!token) {
        return res.status(403).json({ success: false, error: 'No registered device token for this email' });
      }
  
      // Normalize inputs
      const emailNorm   = String(email).trim().toLowerCase();
      const deviceIdStr = String(deviceId || "").trim();
  
      // Build bytes32[3] arrays (first slot populated, others zero; revise later if needed)
      const emailHashes    = makeHashTriplet(emailNorm);
      const deviceIdHashes = deviceIdStr ? makeHashTriplet(deviceIdStr) : [ZERO32, ZERO32, ZERO32];
  
      console.log(`🪙 Mint request → to=${to}, email=${emailNorm}, deviceId=${deviceIdStr || '(none)'}`);
  
      const tx = await personaAuth.safeMint(to, emailHashes, deviceIdHashes);
      console.log(`⛓️  Mint tx sent: ${tx.hash}`);
  
      // Do NOT await confirmations here (keep mobile UX snappy). Client can poll if needed.
      return res.json({ success: true, txHash: tx.hash });
  
    } catch (err) {
      console.error('❌ /mint-nft error:', err);
      return res.status(500).json({ success: false, error: 'Mint failed', details: String(err.message || err) });
    }
  });
  

// Start
const PORT = 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`NFT Login server running on port ${PORT}`);
});
