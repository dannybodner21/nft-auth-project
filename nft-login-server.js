// nft-login-server.js
require('dotenv').config();
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');

const app = express();
app.use(express.json());

const allowedOrigins = [
  "https://nft-auth-two.webflow.io",
  "https://linear-template-48cfc7.webflow.io"
];

app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.url}`);

  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// 🔐 Load Firebase service account
// const serviceAccount = require(path.join(__dirname, 'service-account.json'));
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });

// In-memory storage
let pendingLogins = {};     // { requestId: { email, status, timestamp, devicePublicKeyJwk? } }
let userTokens = {};        // { email: deviceToken }
let userCredentials = {};   // { email: [ { id, name?, url?, enc, wrapped_key_session?, wrapped_key_device? } ] }

// ✅ NEW: phone-assisted decrypt transactions (ephemeral)
// { txId: { email, credentialId, status: 'pending'|'approved'|'denied', payload?: {username,password}, expiresAt?: ts, createdAt } }
let pendingDecrypts = {};

// 🔐 Save device token from app
app.post('/save-token', (req, res) => {
  const { email, deviceToken } = req.body;
  if (!email || !deviceToken) return res.status(400).json({ error: 'Email and deviceToken required' });
  userTokens[email] = deviceToken;
  console.log(`💾 Saved token for ${email}`);
  res.json({ success: true });
});

// 🟢 Used by /request-login to fetch the token for an email
const db = {
  getUserByEmail: async (email) => {
    const token = userTokens[email] || process.env.TEST_PUSH_TOKEN;
    if (!token) return null;
    return { email, deviceToken: token };
  }
};

// 🔐 Request login → sends push to device
app.post('/request-login', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  console.log("📩 Received login request for:", email);

  const requestId = uuidv4();
  pendingLogins[requestId] = {
    email,
    status: 'pending',
    timestamp: Date.now(),
    devicePublicKeyJwk: null
  };

  const user = await db.getUserByEmail(email);
  const deviceToken = user?.deviceToken;
  if (!deviceToken) return res.status(404).json({ error: 'No device token registered' });

  const message = {
    token: deviceToken,
    notification: {
      title: 'NFT Login Request',
      body: `Approve login for ${email}?`
    },
    data: {
      type: 'login_request',
      email,
      requestId
    },
    android: { priority: 'high' },
    apns: { payload: { aps: { sound: 'default', category: 'LOGIN_REQUEST' } } }
  };

  try {
    await admin.messaging().send(message);
    console.log(`✅ Push sent to ${email}`);
    res.json({ success: true, requestId });
  } catch (error) {
    console.error("❌ FCM error:", error);
    res.status(500).json({ success: false, error: "Failed to send push notification" });
  }
});

// ✅ App confirms login decision
app.post('/confirm-login', (req, res) => {
  const { requestId, approved, devicePublicKeyJwk } = req.body || {};
  const request = pendingLogins[requestId];
  if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

  request.status = approved ? 'approved' : 'denied';
  if (approved && devicePublicKeyJwk) request.devicePublicKeyJwk = devicePublicKeyJwk;

  res.json({ success: true, message: `Login ${approved ? 'approved' : 'denied'}` });
});

// 🟢 Frontend checks login status
app.get('/check-login/:requestId', (req, res) => {
  console.log("📥 Incoming GET for", req.params.requestId);
  const request = pendingLogins[req.params.requestId];
  if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

  res.setHeader('Content-Type', 'application/json');
  res.json({ success: true, status: request.status, devicePublicKeyJwk: request.devicePublicKeyJwk || null });
});

app.get("/debug", (req, res) => {
  res.json({ success: true, message: "This is the real nft-login-server.js" });
});

// ===== Credentials (encrypted blobs) =====
app.post('/store-credentials', (req, res) => {
  const { email, deviceId, credentials } = req.body;
  if (!email || !deviceId || !Array.isArray(credentials)) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }

  const user = userTokens[email];
  if (!user) return res.status(403).json({ error: 'Unregistered device' });

  userCredentials[email] = credentials;
  console.log(`Stored ${credentials.length} encrypted credentials for ${email}`);
  res.json({ success: true });
});

app.post('/get-credentials', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const token = userTokens[email];
  if (!token) return res.status(403).json({ error: 'No registered device token' });

  const creds = userCredentials[email] || [];
  console.log("Full credential map:", userCredentials);
  console.log(`Returned ${creds.length} credentials for ${email}`);
  res.json({ success: true, credentials: creds });
});

app.post('/delete-credential', (req, res) => {
  const { email, deviceId, credentialId } = req.body;
  console.log("🧠 Incoming DELETE request with:", { email, deviceId, credentialId });

  if (!email || !deviceId || !credentialId) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const userCreds = userCredentials[email];
  if (!userCreds) return res.status(404).json({ error: 'No credentials found' });

  const updatedCreds = userCreds.filter(c => c.id !== credentialId);
  userCredentials[email] = updatedCreds;

  console.log(`✅ Deleted credential ${credentialId} for ${email}`);
  res.json({ success: true });
});

app.post('/wipe-credentials', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  delete userCredentials[email];
  console.log(`🧹 Wiped all credentials for ${email}`);
  res.json({ success: true });
});

/* =======================================================
   🔐 NEW: Phone-assisted decrypt (no secrets in extension)
   -------------------------------------------------------
   Flow:
   - Extension POST /request-decrypt { email, credentialId, label? }
     -> sends FCM "decrypt_request" to device
   - App decrypts locally, POST /confirm-decrypt { txId, approved, data:{username,password} }
   - Extension polls GET /check-decrypt/:txId until approved; then consumes once
   Secrets live only in memory briefly and are deleted on first read or expiry.
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
    // DO NOT log secrets
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

  // Expire old approved payloads
  if (tx.expiresAt && Date.now() > tx.expiresAt) {
    delete pendingDecrypts[req.params.txId];
    return res.json({ success: true, found: false, expired: true });
  }

  if (tx.status === 'approved' && tx.payload) {
    const data = tx.payload;
    // consume once
    delete pendingDecrypts[req.params.txId];
    return res.json({ success: true, found: true, status: 'approved', data });
  }

  return res.json({ success: true, found: true, status: tx.status });
});

// Optional: periodic cleanup
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
}, 60_000);

// Start server
const PORT = 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`NFT Login server running on port ${PORT}`);
});
