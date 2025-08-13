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

    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }

    next();
});


// 🔐 Load Firebase service account
//const serviceAccount = require(path.join(__dirname, 'service-account.json'));
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// In-memory storage
let pendingLogins = {};   // { requestId: { email, status, timestamp } }
let userTokens = {};      // { email: deviceToken }

// In-memory encrypted credentials store
let userCredentials = {
    // email: [{ url, username, passwordEncrypted }]
};

// 🔐 Save device token from app
app.post('/save-token', (req, res) => {
  const { email, deviceToken } = req.body;

  if (!email || !deviceToken) {
    return res.status(400).json({ error: 'Email and deviceToken required' });
  }

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
    android: {
      priority: 'high',
    },
    apns: {
      payload: {
        aps: {
          sound: 'default',
          category: 'LOGIN_REQUEST'
        }
      }
    }
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

    // store the phone’s P-256 JWK when approved
    if (approved && devicePublicKeyJwk) {
        request.devicePublicKeyJwk = devicePublicKeyJwk;
    }

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

app.post('/store-credentials', (req, res) => {
    const { email, deviceId, credentials } = req.body;
    if (!email || !deviceId || !Array.isArray(credentials)) {
      return res.status(400).json({ error: 'Missing or invalid fields' });
    }
  
    // Normalize incoming items (string → object), keep unknown fields
    const normIncoming = credentials.map(normalizeCred).filter(Boolean);
  
    // If incoming empty, don’t wipe
    if (normIncoming.length === 0) {
      console.log(`⚠️  /store-credentials: incoming empty for ${email} — ignoring to prevent wipe`);
      const existing = Array.isArray(userCredentials[email]) ? userCredentials[email] : [];
      return res.json({ success: true, merged: existing.length, incoming: 0 });
    }
  
    const existing = Array.isArray(userCredentials[email]) ? userCredentials[email] : [];
    const byId = new Map();
  
    for (const item of existing) {
      const id = item && item.id != null ? String(item.id) : null;
      if (id) byId.set(id, item);
    }
    for (const item of normIncoming) {
      const id = item && item.id != null ? String(item.id) : null;
      if (id) byId.set(id, item); // upsert
    }
  
    const merged = Array.from(byId.values());
    userCredentials[email] = merged;
  
    console.log(`✅ /store-credentials merged for ${email}: existing=${existing.length}, incoming=${normIncoming.length}, result=${merged.length}`);
    res.json({ success: true, count: merged.length });
  });
  
  
app.post('/get-credentials', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Missing email' });
  
    const raw = Array.isArray(userCredentials[email]) ? userCredentials[email] : [];
    const creds = raw.map(normalizeCred).filter(Boolean);
  
    console.log(`Returned ${creds.length} credentials for ${email}`);
    res.json({ success: true, credentials: creds });
  });
  
  // Keep this helper:
  function normalizeCred(it) {
    let obj = it;
    if (typeof obj === 'string') { try { obj = JSON.parse(obj); } catch { return null; } }
    if (!obj || typeof obj !== 'object') return null;
  
    if (typeof obj.enc === 'string') { try { obj.enc = JSON.parse(obj.enc); } catch {} }
  
    // session wrap may be base64 string (legacy) or object; parse JSON strings only
    if (typeof obj.wrapped_key_session === 'string') {
      try { const maybe = JSON.parse(obj.wrapped_key_session); if (maybe && typeof maybe === 'object') obj.wrapped_key_session = maybe; } catch {}
    }
    if (typeof obj.wrapped_key_device === 'string') { try { obj.wrapped_key_device = JSON.parse(obj.wrapped_key_device); } catch {} }
  
    if (obj.id != null && typeof obj.id !== 'string') { try { obj.id = String(obj.id); } catch {} }
    return obj;
  }
  

app.post('/delete-credential', (req, res) => {
    const { email, deviceId, credentialId } = req.body;

    console.log("🧠 Incoming DELETE request with:");
    console.log("email:", email);
    console.log("deviceId:", deviceId);
    console.log("credentialId:", credentialId);
    console.log("userCredentials[email]:", userCredentials[email]);

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
  

// Start server
//app.listen(4000, () => console.log('NFT Login server running at http://localhost:4000'));


const PORT = 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`NFT Login server running on port ${PORT}`);
});