// nft-login-server.js
require('dotenv').config();
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');


const app = express();
app.use(express.json());


const allowedOrigin = "https://nft-auth-two.webflow.io";

app.use((req, res, next) => {

    console.log(`➡️  ${req.method} ${req.url}`);

    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
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

  const requestId = uuidv4();
  pendingLogins[requestId] = {
    email,
    status: 'pending',
    timestamp: Date.now()
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
  const { requestId, approved } = req.body;
  const request = pendingLogins[requestId];
  if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

  request.status = approved ? 'approved' : 'denied';
  res.json({ success: true, message: `Login ${approved ? 'approved' : 'denied'}` });
});

// 🟢 Frontend checks login status
app.get('/check-login/:requestId', (req, res) => {
    console.log("📥 Incoming GET for", req.params.requestId);
    const request = pendingLogins[req.params.requestId];
    if (!request) return res.status(404).json({ success: false, error: 'Request not found' });
    
    res.setHeader('Content-Type', 'application/json');
    res.json({ success: true, status: request.status });
});

app.get("/debug", (req, res) => {
    res.json({ success: true, message: "This is the real nft-login-server.js" });
});

// Start server
//app.listen(4000, () => console.log('🔐 NFT Login server running at http://localhost:4000'));

const PORT = 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🔐 NFT Login server running on port ${PORT}`);
});