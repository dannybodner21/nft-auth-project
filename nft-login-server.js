// nft-login-server.js
require('dotenv').config();
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const jwt = require('jsonwebtoken');

const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET || 'CHANGE_ME_IN_PROD';
const AUTH_JWT_TTL_SECONDS = 5 * 60; // 5 minutes
const LOGIN_TOKEN_SECRET   = process.env.LOGIN_TOKEN_SECRET || 'CHANGE_ME_IN_PROD';
const LOGIN_TOKEN_ISSUER   = process.env.LOGIN_TOKEN_ISSUER || 'https://auth.nftauthproject.com';
const LOGIN_TOKEN_TTL_SEC  = 5 * 60; // 5 minutes
const MESSAGE_BUCKET_SALT = process.env.MESSAGE_BUCKET_SALT || 'CHANGE_ME_IN_PROD';

// In-memory storage maps
const userCards = Object.create(null);   // email -> { spkiPem, linkedAt }

// === In-memory payments (ephemeral) ===
const emailToTokens = Object.create(null);
const pendingPayments = Object.create(null);
let paymentCounter = 0;

// DigestInfo prefix for SHA-256 (must match OpenPGPTapSigner)
const SHA256_DIGESTINFO_PREFIX = Buffer.from([
  0x30, 0x31,       // SEQUENCE
  0x30, 0x0d,       // SEQUENCE
  0x06, 0x09,       // OID
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  0x05, 0x00,       // NULL
  0x04, 0x20        // OCTET STRING, 32 bytes
]);

function makeDigestInfoSha256(message) {
  const mBuf = Buffer.from(String(message), 'utf8');
  const hash = crypto.createHash('sha256').update(mBuf).digest();
  return Buffer.concat([SHA256_DIGESTINFO_PREFIX, hash]);
}

// very small TTL to avoid leaks
const PAYMENT_TTL_MS = 5 * 60 * 1000; // 5 minutes

function cleanupStalePayments() {
  const now = Date.now();
  for (const pid of Object.keys(pendingPayments)) {
    const p = pendingPayments[pid];
    if (!p) continue;
    if (now - p.createdAt > PAYMENT_TTL_MS) {
      delete pendingPayments[pid];
    }
  }
}
setInterval(cleanupStalePayments, 60 * 1000).unref();

// === Helper: send push to all tokens for an email ===
async function sendPaymentPush(emailNorm, payment) {
  const tokens = emailToTokens[emailNorm];
  if (!tokens || tokens.size === 0) {
    console.warn(`⚠️ No FCM tokens for ${emailNorm}, cannot send payment push`);
    return;
  }

  const registrationTokens = Array.from(tokens);

  const msg = {
    tokens: registrationTokens,
    data: {
      type: 'payment_approval',
      paymentId: payment.paymentId,
      amountCents: String(payment.amountCents),
      currency: payment.currency,
      description: payment.description
    },
    notification: {
      title: 'Payment Approval Required',
      body: `${payment.description} – ${(payment.amountCents / 100).toFixed(2)} ${payment.currency}`
    }
  };

  try {
    const resp = await admin.messaging().sendMulticast(msg);
    console.log(`📲 Payment push → ${emailNorm}: success=${resp.successCount}, failure=${resp.failureCount}`);
  } catch (err) {
    console.error('🔥 sendPaymentPush error:', err);
  }
}



function bucketKeyForMessagingId(messagingId) {
  const h = crypto
    .createHash('sha256')
    .update(MESSAGE_BUCKET_SALT)
    .update(':')
    .update(String(messagingId || ''))
    .digest('hex')
    .slice(0, 32); // short, still unlinkable
  return `pending_msgs:${h}`;
}

function messageBucketKey(recipientMessagingId) {
  const id = String(recipientMessagingId || '').trim();
  if (!id) throw new Error('recipientMessagingId required');

  const hash = crypto
    .createHash('sha256')
    .update(id + '|' + MESSAGE_BUCKET_SALT)
    .digest('hex');

  return `pending_msgs:${hash}`;
}


const Redis = require('ioredis');

// Initialize Redis connection
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

redis.on('connect', () => {
    console.log('✅ Redis connected');
});

redis.on('error', (err) => {
    console.error('❌ Redis error:', err.message);
});


process.on('uncaughtException', err => {
  console.error("🔥 Uncaught Exception:", err);
});
process.on('unhandledRejection', err => {
  console.error("🔥 Unhandled Promise Rejection:", err);
});


// Issue a signed auth token bound to a specific relying-party origin
function issueAuthToken({
  emailNorm,
  origin,          // e.g. "https://nftauthproject.com"
  deviceHash = null,
  nonce,           // random per-login
  lifetimeSec = 600
}) {
  if (!origin || !origin.startsWith('http')) {
    throw new Error('origin required for auth token');
  }
  if (!nonce) {
    throw new Error('nonce required for auth token');
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: emailNorm,
    aud: origin,           // relying-party origin
    iss: 'nftauthproject-login-relay',
    iat: now,
    exp: now + lifetimeSec,
    nonce,
    deviceHash: deviceHash || null
  };

  return jwt.sign(payload, AUTH_JWT_SECRET, { algorithm: 'HS256' });
}


// --- Helper: strict NFT + email + device binding check ---
async function verifyPersonaBinding({ emailNorm, address, deviceFpr }) {
  try {
    if (!provider || !CONTRACT_ADDRESS) {
      console.warn('⚠️ verifyPersonaBinding: contract/provider not configured');
      return { ok: false, reason: 'not_configured' };
    }

    const addr = String(address || '').trim();
    if (!addr || !ethers.utils.isAddress(addr)) {
      return { ok: false, reason: 'bad_address' };
    }

    const readAbi = [
      "function balanceOf(address owner) view returns (uint256)",
      "function tokenOf(address user) view returns (uint256)",
      "function identityOf(uint256 tokenId) view returns (bytes32 userIdHash, bytes32 deviceHash, bool valid)"
    ];
    const personaRead = new ethers.Contract(CONTRACT_ADDRESS, readAbi, provider);

    const bal = await personaRead.balanceOf(addr);
    const owned = bal.gt ? bal.gt(0) : (BigInt(bal) > 0n);
    if (!owned) {
      return { ok: false, reason: 'no_nft' };
    }

    const tokenId = await personaRead.tokenOf(addr);
    const tidStr = tokenId?.toString?.() || String(tokenId || '0');
    if (tidStr === '0') {
      return { ok: false, reason: 'no_token_mapping' };
    }

    const id = await personaRead.identityOf(tokenId);
    const onUser   = id.userIdHash || id[0];
    const onDevice = id.deviceHash || id[1];

    const emailOk  = emailNorm
      ? (commitUserId(emailNorm).toLowerCase() === String(onUser).toLowerCase())
      : true;
    const deviceOk = deviceFpr
      ? (commitDevice(deviceFpr).toLowerCase() === String(onDevice).toLowerCase())
      : true;

    if (!emailOk || !deviceOk) {
      return { ok: false, reason: 'mismatch' };
    }

    return { ok: true, reason: 'ok', tokenId: tidStr };
  } catch (e) {
    console.error('❌ verifyPersonaBinding error:', e);
    return { ok: false, reason: 'error', error: String(e.message || e) };
  }
}

function makeLoginToken({ emailNorm, origin, deviceHash, nonce }) {
  if (!emailNorm) throw new Error('emailNorm required');
  if (!origin)    throw new Error('origin required');
  if (!nonce)     throw new Error('nonce required');

  const now = Math.floor(Date.now() / 1000);

  const sub = commitUserId(emailNorm); // hashed identifier

  const payload = {
    iss:  LOGIN_TOKEN_ISSUER,
    aud:  origin,
    sub,
    nonce,
    iat:  now,
    exp:  now + LOGIN_TOKEN_TTL_SEC
  };

  if (deviceHash) {
    payload.device = deviceHash;
  }

  return jwt.sign(payload, LOGIN_TOKEN_SECRET, { algorithm: 'HS256' });
}



// Rate limiting helper
async function checkRateLimit(key, maxRequests, windowSeconds) {
  const current = await redis.incr(key);
  if (current === 1) {
      await redis.expire(key, windowSeconds);
  }
  return current <= maxRequests;
}


// Store FCM token for a messagingId (for calls)
async function addDeviceTokenForMessagingId(messagingId, token) {
  if (!messagingId || !token) return;
  const cleaned = String(token).trim();
  if (!cleaned) return;

  try {
      // Use a Redis Set so each messagingId can have multiple tokens (multiple devices)
      await redis.sadd(`call_tokens:${messagingId}`, cleaned);
      // Set expiry of 30 days - tokens refresh when app opens
      await redis.expire(`call_tokens:${messagingId}`, 30 * 24 * 60 * 60);
      
      const count = await redis.scard(`call_tokens:${messagingId}`);
      console.log("🔄 Redis: call token stored for", messagingId.slice(0, 16) + "…", "count:", count);
  } catch (err) {
      console.error("❌ Redis addDeviceTokenForMessagingId error:", err.message);
  }
}

// Get FCM tokens for a messagingId
async function getDeviceTokensForMessagingId(messagingId) {
  if (!messagingId) return [];

  try {
      // First try call tokens
      let tokens = await redis.smembers(`call_tokens:${messagingId}`);
      
      if (tokens && tokens.length > 0) {
          return tokens;
      }

      // Fallback: try messaging tokens
      tokens = await redis.smembers(`msg_tokens:${messagingId}`);
      if (tokens && tokens.length > 0) {
          console.log("ℹ️ Falling back to msg_tokens for", messagingId.slice(0, 16) + "…");
          return tokens;
      }

      console.warn("ℹ️ No FCM tokens found for", messagingId.slice(0, 16) + "…");
      return [];
  } catch (err) {
      console.error("❌ Redis getDeviceTokensForMessagingId error:", err.message);
      return [];
  }
}

// Store FCM token for messaging
async function addMessagingToken(messagingId, token) {
  if (!messagingId || !token) return;
  const cleaned = String(token).trim();
  if (!cleaned) return;

  try {
      await redis.sadd(`msg_tokens:${messagingId}`, cleaned);
      await redis.expire(`msg_tokens:${messagingId}`, 30 * 24 * 60 * 60);
      
      const count = await redis.scard(`msg_tokens:${messagingId}`);
      console.log("🔄 Redis: msg token stored for", messagingId.slice(0, 16) + "…", "count:", count);
  } catch (err) {
      console.error("❌ Redis addMessagingToken error:", err.message);
  }
}


// === Ethers wiring (v5/v6 compatible) ===
const { ethers } = require('ethers');
const isAddress       = ethers.utils?.isAddress       || ethers.isAddress;
const keccak256       = ethers.utils?.keccak256       || ethers.keccak256;
const toUtf8Bytes     = ethers.utils?.toUtf8Bytes     || ethers.toUtf8Bytes;
const JsonRpcProvider = ethers.providers?.JsonRpcProvider || ethers.JsonRpcProvider;
const parseUnits      = ethers.utils?.parseUnits      || ethers.parseUnits;
const solidityPack    = ethers.utils?.solidityPack    || ethers.solidityPack;

// --- Env ---
const RPC_URL                   = process.env.RPC_URL;
const CONTRACT_ADDRESS          = process.env.CONTRACT_ADDRESS;
const DEPLOYER_PRIVATE_KEY      = process.env.DEPLOYER_PRIVATE_KEY;
const MINTER_PRIVATE_KEY        = process.env.MINTER_PRIVATE_KEY;
const USER_PEPPER               = process.env.USER_COMMITMENT_PEPPER;
const DEVICE_PEPPER             = process.env.DEVICE_COMMITMENT_PEPPER;

// Card auth public key (choose ONE source; path preferred)
const CARD_AUTH_PUBKEY_PEM_PATH = process.env.CARD_AUTH_PUBKEY_PEM_PATH || ""; // file path to PEM (SPKI)
const CARD_PUBKEY_PEM_INLINE    = process.env.CARD_PUBKEY_PEM || "";           // inline PEM (SPKI)

// ---------------------- Helpers ----------------------
const normalizeEmail = (s) => String(s || '').trim().toLowerCase();

function commitUserId(email) {
  const norm = normalizeEmail(email);
  const packed = solidityPack(["string", "string"], [norm, USER_PEPPER || ""]);
  return keccak256(packed);
}

function commitDevice(deviceFpr) {
  const val = String(deviceFpr || "").trim();
  const packed = solidityPack(["string","string"], [val, DEVICE_PEPPER || ""]);
  return keccak256(packed);
}


// --- Auth token helper (HMAC "JWT"-style) ---
function createAuthToken({ emailNorm, websiteDomain }) {
  if (!AUTH_TOKEN_SECRET || AUTH_TOKEN_SECRET === 'CHANGE_ME_IN_PROD') {
    throw new Error('AUTH_TOKEN_SECRET not configured');
  }

  const now   = Math.floor(Date.now() / 1000);
  const exp   = now + 5 * 60; // 5 minutes
  const nonce = crypto.randomBytes(16).toString('hex');

  const payload = {
    sub: emailNorm,                       // subject = normalized email
    aud: websiteDomain || 'nftauthproject', // relying-party origin / RP id
    iat: now,
    exp,
    nonce
  };

  const header = { alg: 'HS256', typ: 'JWT' };

  const b64u = (obj) =>
    Buffer.from(JSON.stringify(obj)).toString('base64url');

  const unsigned = `${b64u(header)}.${b64u(payload)}`;
  const signature = crypto
    .createHmac('sha256', AUTH_TOKEN_SECRET)
    .update(unsigned)
    .digest('base64url');

  const token = `${unsigned}.${signature}`;
  return { token, nonce, iat: now, exp, aud: payload.aud, sub: payload.sub };
}


// Verify the email doesn't have a registered account before attempting to register
async function probeIdentityRegistered(emailNorm) {
  if (!personaAuth) throw new Error('Contract not configured');
  // fabricate a safe probe: no state change via callStatic
  const toProbe = relayerSigner.address;           // any valid address is fine for static call
  const userIdHash = commitUserId(emailNorm);
  const deviceHash = commitDevice('probe-device'); // arbitrary probe fingerprint
  const domain = { name: "PersonaAuth", version: "1", chainId: 137, verifyingContract: CONTRACT_ADDRESS };
  const types  = { MintAuth: [
    { name: "to",          type: "address" },
    { name: "userIdHash",  type: "bytes32" },
    { name: "deviceHash",  type: "bytes32" },
    { name: "salt",        type: "bytes32" },
    { name: "deadline",    type: "uint256" },
  ]};
  const salt     = ethers.utils.hexlify(ethers.utils.randomBytes(32));
  const deadline = Math.floor(Date.now() / 1000) + 120; // short-lived, irrelevant for static

  const minter = new ethers.Wallet(MINTER_PRIVATE_KEY);
  const sig = await minter._signTypedData(domain, types, { to: toProbe, userIdHash, deviceHash, salt, deadline });

  try {
    // static “dry run”. If email is unused, this SHOULD NOT revert.
    await personaAuth.callStatic.mintWithSig(toProbe, userIdHash, deviceHash, salt, deadline, sig);
    return { registered: false };
  } catch (e) {
    const msg = (e?.reason || e?.error?.message || String(e)).toLowerCase();
    if (msg.includes('identity already issued')) return { registered: true };
    // any other revert means something else (ABI mismatch, paused, etc.)
    throw e;
  }
}

// Aggressive EIP-1559 fees for Polygon
async function getAggressiveFees(pvd) {
  const fd = await pvd.getFeeData();
  const toGwei = (wei) => {
    if (!wei) return 0;
    const s = wei.toString();
    return ethers.utils?.formatUnits ? Number(ethers.utils.formatUnits(s, "gwei")) : (Number(s) / 1e9);
  };
  const suggestedPrio = toGwei(fd.maxPriorityFeePerGas ?? fd.gasPrice ?? 0);
  const suggestedBase = toGwei(fd.lastBaseFeePerGas ?? fd.gasPrice ?? 0);
  const prio = Math.max(Math.ceil(suggestedPrio * 3), 50);
  const base = Math.max(Math.ceil(suggestedBase * 3), 30);
  const maxPriorityFeePerGas = parseUnits(String(prio), "gwei");
  const maxFeePerGas         = parseUnits(String(base + prio), "gwei");
  return { maxFeePerGas, maxPriorityFeePerGas };
}

// ---------------------- App init ----------------------
const app = express();

const cors = require('cors');

// CORS for website logins - MUST come before express.json()
app.use(cors({
  origin: [
    'https://nftauthproject-two.webflow.io',
    'https://nftauthproject-one.webflow.io',
    'http://localhost:3000',
    'http://localhost:8080',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5500'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// CORS — allow Chrome extensions; native apps / SW send no Origin
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


// Global IP rate limit - 200 requests per minute per IP
app.use(async (req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  const allowed = await checkRateLimit(`ratelimit:ip:${ip}`, 200, 60);
  if (!allowed) {
      console.log(`🚫 Global rate limit for IP ${ip}`);
      return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
  }
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

// ---------------------- Card public key load ----------------------
function keyInfoFromKeyObject(keyObj) {
  const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
  const sha256  = crypto.createHash('sha256').update(spkiDer).digest('base64');
  const details = keyObj.asymmetricKeyDetails || {};
  return {
    alg: keyObj.asymmetricKeyType,           // 'rsa'
    modulusBits: details.modulusLength || null,
    spkiSha256: sha256
  };
}

let cardAuthKey = null;         // active KeyObject
let cardAuthKeyInfo = null;     // info for active key
let pathKeyInfo = null;         // info if loaded from path
let envKeyInfo  = null;         // info if loaded from env

try {
  // Prefer path if provided
  if (CARD_AUTH_PUBKEY_PEM_PATH) {
    const pem = fs.readFileSync(path.resolve(CARD_AUTH_PUBKEY_PEM_PATH), 'utf8');
    const obj = crypto.createPublicKey(pem);
    cardAuthKey = obj;
    cardAuthKeyInfo = keyInfoFromKeyObject(obj);
    pathKeyInfo = cardAuthKeyInfo;
    console.log(`🔐 Card key (path) loaded: alg=${cardAuthKeyInfo.alg}, bits=${cardAuthKeyInfo.modulusBits}, spki=${cardAuthKeyInfo.spkiSha256}`);
  } else if (CARD_PUBKEY_PEM_INLINE) {
    const obj = crypto.createPublicKey(CARD_PUBKEY_PEM_INLINE);
    cardAuthKey = obj;
    cardAuthKeyInfo = keyInfoFromKeyObject(obj);
    envKeyInfo = cardAuthKeyInfo;
    console.log(`🔐 Card key (env) loaded: alg=${cardAuthKeyInfo.alg}, bits=${cardAuthKeyInfo.modulusBits}, spki=${cardAuthKeyInfo.spkiSha256}`);
  } else {
    console.warn('⚠️ No CARD_AUTH_PUBKEY_PEM_PATH or CARD_PUBKEY_PEM; card-based unlock disabled');
  }
} catch (e) {
  console.warn(`⚠️ Failed to load card key: ${e.message}`);
}

// Quick check endpoint
app.get('/card-pubkey-fp', (req, res) => {
  if (!cardAuthKeyInfo) return res.status(503).json({ success: false, error: 'card key not loaded' });
  const same = !!(pathKeyInfo && cardAuthKeyInfo && pathKeyInfo.spkiSha256 === cardAuthKeyInfo.spkiSha256)
            || !!(envKeyInfo  && cardAuthKeyInfo && envKeyInfo.spkiSha256  === cardAuthKeyInfo.spkiSha256);
  res.json({ success: true, active: cardAuthKeyInfo, pathKey: pathKeyInfo, envKey: envKeyInfo, same });
});

// ---------------------- Ethers / contract wiring ----------------------
let provider, relayerSigner, personaAuth;
if (RPC_URL && CONTRACT_ADDRESS && DEPLOYER_PRIVATE_KEY && MINTER_PRIVATE_KEY && USER_PEPPER && DEVICE_PEPPER) {
  provider      = new JsonRpcProvider(RPC_URL);
  relayerSigner = new ethers.Wallet(DEPLOYER_PRIVATE_KEY, provider); // gas payer

  const personaAuthAbi = [
    "function mintWithSig(address to, bytes32 userIdHash, bytes32 deviceHash, bytes32 salt, uint256 deadline, bytes sig) external",
    "function identityOf(uint256 tokenId) view returns (bytes32 userIdHash, bytes32 deviceHash, bool valid)",
    "function tokenOf(address user) view returns (uint256)",
    "function tokenByUser(bytes32 userIdHash) view returns (uint256)",
    "function ownerOf(uint256 tokenId) view returns (address)",
    "function balanceOf(address owner) view returns (uint256)",
    "function locked(uint256 tokenId) view returns (bool)"
];
  personaAuth = new ethers.Contract(CONTRACT_ADDRESS, personaAuthAbi, relayerSigner);
} else {
  console.warn("⚠️ Minting disabled: set RPC_URL, CONTRACT_ADDRESS, DEPLOYER_PRIVATE_KEY, MINTER_PRIVATE_KEY, USER_COMMITMENT_PEPPER, DEVICE_COMMITMENT_PEPPER");
}






// ---------------------- In-memory stores (dev) ----------------------
let pendingLogins = {};          // { requestId: { email, websiteDomain?, status, timestamp, devicePublicKeyJwk?, extSession? } }
let userTokens = {};             // { email: deviceToken }
let userCredentials = {};        // { email: [ ... ] }
let pendingDecrypts = {};        // { txId: { ... } }
let sessionApprovals = {};       // { email: expiryMs }
let pendingCardChallenges = {};  // { emailNorm: { challenge, expiresAt } }
const loginChallenges = Object.create(null); // nonce → challenge record


// E2EE messaging: in-memory, deliver-once queues keyed by recipient messaging ID
// messagesByRecipient[recipientMessagingId] = [ { id, ts, senderMessagingId, ciphertextB64 } ]
//let messagesByRecipient = {};

// messagingRouting[messagingId] = { email, deviceToken }
let messagingRouting = {};

// ---- Call signaling state (in-memory, ephemeral) ----
// callsById[callId] = {
//   id,
//   fromMessagingId,
//   toMessagingId,
//   status: 'ringing' | 'connected' | 'ended',
//   sdpOffer?: string,
//   sdpAnswer?: string,
//   createdAt: number,
//   endedAt?: number,
//   lastUpdate: number
// }
const callsById = Object.create(null);

const pendingEmailCodes = {};
const verifiedEmails = {};

const makeCode6 = () => String(Math.floor(100000 + Math.random() * 900000));

// === BEGIN: per-user card binding (production) ===

// In-memory card key registry (replace with DB in prod):
// cardKeys[emailNorm] = { keyObj, spkiSha256, pem }
let cardKeys = {};

function b64urlToStd(b64) {
  return String(b64 || "").replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
}

// function keyInfoFromKeyObject(keyObj) {
//   const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
//   const sha256  = crypto.createHash('sha256').update(spkiDer).digest('base64');
//   const details = keyObj.asymmetricKeyDetails || {};
//   return { alg: keyObj.asymmetricKeyType, modulusBits: details.modulusLength || null, spkiSha256: sha256 };
// }


// function b64urlToStd(b64url) {
//   return b64url.replace(/-/g, '+').replace(/_/g, '/').replace(/(?<![=])$/,'').padEnd(Math.ceil(b64url.length/4)*4, '=');
// }

function verifyCardSignature({ publicKey, challenge, signatureB64 }) {
  const msg = Buffer.from(challenge, 'utf8');
  const sig = Buffer.from(b64urlToStd(signatureB64), 'base64');

  // 1) Try PKCS#1 v1.5 + SHA-256
  try {
    const ok = crypto.verify('RSA-SHA256', msg, publicKey, sig);
    if (ok) {
      console.log('✅ Verified (PKCS1v1_5 + SHA-256)');
      return true;
    }
  } catch (e) {
    // ignore and fall through to PSS
  }

  // 2) Try RSA-PSS + SHA-256 (saltLength = 32)
  try {
    const ok = crypto.verify(
      'RSA-SHA256',
      msg,
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
      sig
    );
    if (ok) {
      console.log('✅ Verified (RSA-PSS + SHA-256, saltLength=32)');
      return true;
    }
  } catch (e) {
    // ignore
  }

  console.log('❌ Signature did not verify with PKCS1v1_5 or PSS');
  return false;
}

module.exports = { verifyCardSignature };






// function verifyCardSignature({ publicKey, challenge, signatureB64, scheme = 'PKCS1V15' }) {
  
//   console.log('🔍 SERVER: Challenge bytes (hex, first 100):', Buffer.from(challenge, 'utf8').toString('hex').substring(0, 100));
//   console.log('🔍 SERVER: Signature B64 (first 50):', signatureB64.substring(0, 50));
  
//   const sigBuf = Buffer.from(b64urlToStd(signatureB64), 'base64');
//   console.log('🔍 SERVER: Signature buffer length:', sigBuf.length);
//   console.log('🔍 SERVER: Signature buffer (hex, first 50):', sigBuf.toString('hex').substring(0, 50));
  
//   if (scheme.toUpperCase() === 'PSS') {
//     const v = crypto.createVerify('sha256');
//     v.update(Buffer.from(challenge, 'utf8'));
//     v.end();
//     return v.verify(
//       { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
//       sigBuf
//     );
//   } else {
//     // PKCS#1 v1.5 - iOS sends signature over DigestInfo(SHA-256(challenge))
//     const hash = crypto.createHash('sha256').update(Buffer.from(challenge, 'utf8')).digest();
    
//     console.log('🔍 Hash input challenge length:', challenge.length);
//     console.log('🔍 Hash input challenge full:', challenge);
//     console.log('🔍 Hash output (hex):', hash.toString('hex'));

//     // DigestInfo for SHA-256
//     const diPrefix = Buffer.from([
//       0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
//       0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
//       0x00, 0x04, 0x20
//     ]);
//     const expectedDigestInfo = Buffer.concat([diPrefix, hash]);
//     console.log('🔍 Expected DigestInfo (hex):', expectedDigestInfo.toString('hex'));
//     console.log('🔍 Expected DigestInfo length:', expectedDigestInfo.length);

//     console.log('🔍 Raw signature B64 (first 50):', signatureB64.substring(0, 50));
//     console.log('🔍 After b64urlToStd:', b64urlToStd(signatureB64).substring(0, 50));
//     console.log('🔍 Signature buffer length:', sigBuf.length);
//     console.log('🔍 Expected sig length for 2048-bit RSA: 256 bytes');

//     // Try to parse as DER-encoded signature first
//     try {
//       const parsed = crypto.createVerify('SHA256');
//       parsed.update(Buffer.from(challenge, 'utf8'));
//       parsed.end();
//       const verified = parsed.verify(publicKey, sigBuf);
//       if (verified) {
//         console.log('✅ Verified using createVerify!');
//         return true;
//       }
//     } catch (e) {
//       console.log('createVerify failed, trying manual decrypt');
//     }
    
//     // Decrypt the signature and compare
//     try {
//       const decrypted = crypto.publicDecrypt(
//         {
//           key: publicKey,
//           padding: crypto.constants.RSA_PKCS1_PADDING
//         },
//         sigBuf
//       );
      
//       console.log('🔍 Decrypted signature (hex):', decrypted.toString('hex'));
//       console.log('🔍 Decrypted length:', decrypted.length);
      
//       return decrypted.equals(expectedDigestInfo);
//     } catch (e) {
//       console.error('❌ Decryption error:', e.message);
      
//       // Try without PKCS1 padding to see raw data
//       try {
//         const raw = crypto.publicDecrypt({ key: publicKey, padding: crypto.constants.RSA_NO_PADDING }, sigBuf);
//         console.log('🔍 Raw decrypted (no padding, first 100 hex):', raw.toString('hex').substring(0, 100));
//       } catch (e2) {
//         console.log('🔍 Even raw decrypt failed');
//       }
      
//       return false;
//     }


//   }
// }

// function verifyCardSignature({ publicKey, challenge, signatureB64, scheme = 'PKCS1V15' }) {
  
//   const sigBuf = Buffer.from(b64urlToStd(signatureB64), 'base64');
  
//   if (scheme.toUpperCase() === 'PSS') {
//     const v = crypto.createVerify('sha256');
//     v.update(Buffer.from(challenge, 'utf8'));
//     v.end();
//     return v.verify(
//       { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
//       sigBuf
//     );
//   } else {
//     const hash = crypto.createHash('sha256').update(Buffer.from(challenge, 'utf8')).digest();
//     const diPrefix = Buffer.from([
//       0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
//       0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
//       0x00, 0x04, 0x20
//     ]);
//     const expectedDigestInfo = Buffer.concat([diPrefix, hash]);

//     try {
//       const raw = crypto.publicDecrypt(
//         { key: publicKey, padding: crypto.constants.RSA_NO_PADDING },
//         sigBuf
//       );
      
//       console.log('🔍 Raw decrypted (full hex):', raw.toString('hex'));
//       console.log('🔍 Expected DigestInfo (hex):', expectedDigestInfo.toString('hex'));
      
//       // Search for DigestInfo prefix (0x3031300d...) anywhere in the decrypted data
//       const prefixHex = diPrefix.toString('hex');
//       const rawHex = raw.toString('hex');
//       const prefixIndex = rawHex.indexOf(prefixHex);
      
//       if (prefixIndex === -1) {
//         console.log('❌ DigestInfo prefix not found in signature');
//         return false;
//       }
      
//       // Extract the DigestInfo (prefix + hash = 51 bytes = 102 hex chars)
//       const extractedHex = rawHex.substring(prefixIndex, prefixIndex + 102);
//       const extracted = Buffer.from(extractedHex, 'hex');
      
//       console.log('🔍 Found DigestInfo at position:', prefixIndex / 2, 'bytes');
//       console.log('🔍 Extracted DigestInfo (hex):', extracted.toString('hex'));
      
//       const match = extracted.equals(expectedDigestInfo);
//       console.log('🔐 Signature verification result:', match);
//       return match;
//     } catch (e) {
//       console.error('❌ Verification error:', e.message);
//       return false;
//     }
//   }
// }

// Inspect what key is bound for an email (debug)
app.get('/card-key-fp/:email', (req, res) => {
  const emailNorm = normalizeEmail(req.params.email || '');
  const rec = cardKeys[emailNorm] || null;
  if (!rec) return res.json({ success: true, bound: false });
  return res.json({ success: true, bound: true, spkiSha256: rec.spkiSha256 });
});



app.post('/card-register', (req, res) => {
  try {
    const rawEmail  = String(req.body?.email || '').trim();
    const emailNorm = normalizeEmail(rawEmail);
    const cardPem   = String(req.body?.spkiPem || req.body?.publicKeyPem || '').trim();

    if (!emailNorm || !cardPem) {
      return res.status(400).json({
        success: false,
        error: 'email and publicKeyPem (or spkiPem) required'
      });
    }

    userCards[emailNorm] = {
      spkiPem: cardPem,
      linkedAt: Date.now()
    };

    cardOwners[cardPem] = emailNorm;

    console.log(`🔐 Registered card for ${emailNorm}`);
    return res.json({ success: true });
  } catch (err) {
    console.error('🔥 /card-register error:', err);
    return res.status(500).json({ success: false, error: 'server error' });
  }
});





// DROP-IN REPLACEMENT: /card-verify now prefers the **per-user** key if present; falls back to global env key for legacy.
app.post('/card-verify', (req, res) => {
  try {
    const rawEmail   = String(req.body?.email || '').trim();
    const emailNorm  = normalizeEmail(rawEmail);
    const challenge  = String(req.body?.challenge || '');
    const signatureB64 = String(req.body?.signatureB64 || '');

    if (!emailNorm || !challenge || !signatureB64) {
      return res.status(400).json({
        success: false,
        verified: false,
        error: 'email, challenge, signatureB64 required'
      });
    }

    const cardInfo = userCards[emailNorm];
    if (!cardInfo || !cardInfo.spkiPem) {
      return res.status(400).json({
        success: false,
        verified: false,
        error: 'no card registered for this email'
      });
    }

    const pending = pendingCardChallenges[emailNorm];
    if (!pending || pending.challenge !== challenge) {
      return res.status(400).json({
        success: false,
        verified: false,
        error: 'no matching challenge'
      });
    }

    // Optional: expiry check (30s)
    if (Date.now() - pending.createdAt > 30_000) {
      delete pendingCardChallenges[emailNorm];
      return res.status(400).json({
        success: false,
        verified: false,
        error: 'challenge expired'
      });
    }

    const publicKeyPem = cardInfo.spkiPem;
    const sigBuf       = Buffer.from(signatureB64, 'base64');

    const ok = crypto.verify(
      'sha256',
      Buffer.from(challenge, 'utf8'),
      publicKeyPem,
      sigBuf
    );

    if (!ok) {
      console.warn(`❌ Card verify failed for ${emailNorm}`);
      return res.json({ success: true, verified: false });
    }

    delete pendingCardChallenges[emailNorm];
    console.log(`✅ Card verified for ${emailNorm}`);

    // You can attach a sessionExpiresAt here if you want
    return res.json({
      success: true,
      verified: true
    });
  } catch (err) {
    console.error('🔥 /card-verify error:', err);
    return res.status(500).json({ success: false, verified: false, error: 'server error verify' });
  }
});


// === END: per-user card binding ===



// -------------- Recovery account with seed phrase ---------------
app.post('/verify-recovery', async (req, res) => {
  try {
    if (!personaAuth) return res.status(503).json({ success: false, error: 'Contract not configured' });
    
    const emailNorm = normalizeEmail(req.body?.email || '');
    const address = String(req.body?.address || '').toLowerCase();
    
    if (!emailNorm || !address) {
      return res.status(400).json({ success: false, error: 'email and address required' });
    }
    
    // Get the commitment hash for this email
    const userIdHash = commitUserId(emailNorm);
    
    // Query the contract to see if this email hash has a token
    const tokenId = await personaAuth.tokenByUser(userIdHash);
    const tokenIdNum = tokenId?.toString?.() || String(tokenId);
    
    // If no token, email is not registered
    if (tokenIdNum === "0") {
      return res.json({ success: true, valid: false });
    }
    
    // Get the owner of this token
    const owner = await personaAuth.ownerOf(tokenId);
    
    // Check if the derived address matches the owner
    const valid = owner.toLowerCase() === address.toLowerCase();
    
    res.json({ success: true, valid });
  } catch (e) {
    console.error('❌ /verify-recovery error:', e);
    res.status(500).json({ success: false, error: 'verification failed' });
  }
});

app.post('/burn-and-remint', async (req, res) => {
  try {
    const emailNorm = normalizeEmail(req.body?.email || '');
    const newAddress = String(req.body?.newAddress || '').toLowerCase();
    const deviceId = String(req.body?.deviceId || '');
    
    if (!emailNorm || !newAddress || !deviceId) {
      return res.status(400).json({ success: false, error: 'email, newAddress, and deviceId required' });
    }
    
    if (!isAddress(newAddress)) {
      return res.status(400).json({ success: false, error: 'Invalid new address' });
    }
    
    // Just mint new NFT to new address
    // The old NFT will still exist but user won't have access to old device
    // In production, you'd call the reissue function on the contract
    const userIdHash = commitUserId(emailNorm);
    const deviceHash = commitDevice(deviceId);

    const domain = { name: "PersonaAuth", version: "1", chainId: 137, verifyingContract: CONTRACT_ADDRESS };
    const types  = { MintAuth: [
      { name: "to",          type: "address" },
      { name: "userIdHash",  type: "bytes32" },
      { name: "deviceHash",  type: "bytes32" },
      { name: "salt",        type: "bytes32" },
      { name: "deadline",    type: "uint256" },
    ]};

    const salt     = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const deadline = Math.floor(Date.now() / 1000) + 10 * 60;

    const minter = new ethers.Wallet(MINTER_PRIVATE_KEY);
    const signature = await minter._signTypedData(domain, types, { to: newAddress, userIdHash, deviceHash, salt, deadline });

    const fee = await getAggressiveFees(provider);
    const tx = await personaAuth.mintWithSig(newAddress, userIdHash, deviceHash, salt, deadline, signature, {
      maxFeePerGas:         fee.maxFeePerGas,
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
    });
    
    console.log(`🔥 Recovery: minted new NFT for ${emailNorm} to ${newAddress}, tx: ${tx.hash}`);
    
    if (typeof tx.wait === 'function') await tx.wait(1);
    else await provider.waitForTransaction(tx.hash, 1);
    
    res.json({ success: true, txHash: tx.hash });
  } catch (e) {
    console.error('❌ /burn-and-remint error:', e);
    const msg = (e?.reason || e?.error?.message || String(e)).toLowerCase();
    if (msg.includes('identity already issued')) {
      // Old NFT still exists - need to use reissue instead
      return res.status(400).json({ success: false, error: 'Identity already exists, old NFT must be revoked first' });
    }
    res.status(500).json({ success: false, error: 'burn and remint failed' });
  }
});

// === END: Account recovery through seed phrase ==================







// ---------------------- Token registration ----------------------
app.post('/save-token', (req, res) => {
  const { email, deviceToken } = req.body || {};
  const messagingId = String(req.body?.messagingId || '').trim();

  if (!email || !deviceToken) {
    return res.status(400).json({ error: 'Email and deviceToken required' });
  }

  const emailNorm = normalizeEmail(email);

  // Preserve existing single-token mapping
  userTokens[emailNorm] = deviceToken;

  // NEW: maintain a set of tokens per email for pushes (login, payments, etc.)
  if (!emailToTokens[emailNorm]) {
    emailToTokens[emailNorm] = new Set();
  }
  emailToTokens[emailNorm].add(deviceToken);

  // If the client passes a messagingId (Curve25519 pubkey), map it to this device token.
  if (messagingId.length > 0) {
    messagingRouting[messagingId] = {
      email: emailNorm,
      deviceToken
    };
    console.log(`💬 Registered messagingId for ${emailNorm} (len=${messagingId.length})`);
  }

  console.log(`💾 Saved token for ${emailNorm}, tokens=${emailToTokens[emailNorm].size}`);
  verifiedEmails[emailNorm] = true;
  res.json({ success: true });
});



// ---------------------- Login token verification ----------------------
// POST /verify-login-token
// Body: { token, origin }
// Verifies HS256 JWT issued by this server and bound to a relying-party origin.
app.post('/verify-login-token', (req, res) => {
  try {
    const token  = String(req.body?.token  || '').trim();
    const origin = String(req.body?.origin || '').trim(); // relying-party origin

    if (!token || !origin) {
      return res.status(400).json({ success: false, error: 'token and origin required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, LOGIN_TOKEN_SECRET, {
        algorithms: ['HS256'],
        issuer: LOGIN_TOKEN_ISSUER,
        audience: origin
      });
    } catch (e) {
      console.error('❌ /verify-login-token jwt.verify failed:', e.message || e);
      return res.status(401).json({ success: false, error: 'invalid_token' });
    }

    // Required claims
    const { sub, nonce, iat, exp, aud, iss, device } = decoded;
    if (!sub || !nonce || !iat || !exp) {
      return res.status(400).json({ success: false, error: 'missing_claims' });
    }

    // ---- Nonce / challenge replay protection ----
    const rec = loginChallenges[nonce];
    if (!rec) {
      // Either unknown nonce or already consumed
      return res.status(400).json({ success: false, error: 'unknown_or_replayed_nonce' });
    }

    // Check server-side challenge expiry (ms)
    if (Date.now() > rec.challengeExpiresAt) {
      delete loginChallenges[nonce];
      return res.status(400).json({ success: false, error: 'stale_challenge' });
    }

    // Optional: enforce that the RP origin matches what we saw at challenge time
    if (rec.relyingPartyOrigin && rec.relyingPartyOrigin !== origin) {
      return res.status(400).json({ success: false, error: 'origin_mismatch' });
    }

    // ✅ Single-use: burn the challenge so it cannot be replayed
    delete loginChallenges[nonce];

    // All good – return minimal claims (no raw email anywhere)
    return res.json({
      success: true,
      valid: true,
      claims: {
        sub,       // hashed email / user id
        nonce,
        iat,
        exp,
        aud,
        iss,
        device: device || null
      }
    });
  } catch (err) {
    console.error('❌ /verify-login-token error:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});



const db = {
  getUserByEmail: async (email) => {
    const token = userTokens[normalizeEmail(email)] || process.env.TEST_PUSH_TOKEN;
    if (!token) return null;
    return { email: normalizeEmail(email), deviceToken: token };
  }
};

// ---------------------- Login approval flow ----------------------
app.post('/request-login', async (req, res) => {
  try {
    const emailNorm     = normalizeEmail(req.body?.email || '');
    const websiteDomain = req.body?.websiteDomain || null;
    const origin        = req.body?.origin || null; // e.g. "https://app.nftauthproject.com"

    if (!emailNorm) {
      return res.status(400).json({ error: 'Email required' });
    }

    const allowed = await checkRateLimit(`ratelimit:login:${emailNorm}`, 10, 60); // 10 per 60s
    if (!allowed) {
      console.log(`🚫 Rate limited /request-login for ${emailNorm}`);
      return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
    }

    const requestId = uuidv4();
    const nonce     = crypto.randomBytes(16).toString('hex');

    // 🔐 Compute a real relying-party origin, even if client only sends websiteDomain
    const relyingPartyOrigin =
      origin ||
      (websiteDomain ? `https://${websiteDomain}` : null);

    if (!relyingPartyOrigin) {
      console.error('❌ /request-login: no origin or websiteDomain provided');
      return res.status(400).json({ success: false, error: 'origin_required' });
    }

    // Store core login request state (used later when user approves on phone)
    pendingLogins[requestId] = {
      email: emailNorm,
      websiteDomain,
      origin: relyingPartyOrigin,   // 👈 ALWAYS non-null now
      nonce,
      status: 'pending',
      timestamp: Date.now(),
      devicePublicKeyJwk: null,
      extSession: null
    };

    // --- Nonce-based challenge object for this login (for token minting / verification) ---
    const challengeNonce     = crypto.randomBytes(16).toString('hex');
    const challengeExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes (ms)

    const hashedEmail = crypto
      .createHash('sha256')
      .update(emailNorm)
      .digest('hex');

    loginChallenges[challengeNonce] = {
      requestId,
      emailHash: hashedEmail,
      relyingPartyOrigin,      // 👈 keep this for later checks
      issuedAt: Date.now(),
      challengeExpiresAt       // 👈 name matches what /verify-login-token expects
    };

    const user = await db.getUserByEmail(emailNorm);
    const deviceToken = user?.deviceToken;
    if (!deviceToken) {
      return res.status(404).json({ error: 'No device token registered' });
    }

    const message = {
      token: deviceToken,
      notification: {
        title: 'NFT Auth Request',
        body: 'Approve or deny request'
      },
      data: {
        type: 'login_request',
        email: emailNorm,
        requestId,
        nonce,
        ...(websiteDomain ? { websiteDomain } : {}),
        origin: relyingPartyOrigin
      },
      android: { priority: 'high' },
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
      console.log(`✅ Push sent to ${emailNorm} (${requestId})`);
      return res.json({
        success: true,
        requestId,
        nonce,
        challengeNonce,
        challengeExpiresAt
      });
    } catch (error) {
      console.error('❌ FCM error:', error);
      return res.status(500).json({ success: false, error: 'Failed to send push notification' });
    }
  } catch (err) {
    console.error('❌ /request-login error:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});



// app.post('/confirm-login', (req, res) => {
//   const { requestId, approved, devicePublicKeyJwk } = req.body || {};
//   const request = pendingLogins[requestId];
//   if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

//   request.status = approved ? 'approved' : 'denied';
//   if (approved && devicePublicKeyJwk && devicePublicKeyJwk.x && devicePublicKeyJwk.y) {
//     request.devicePublicKeyJwk = devicePublicKeyJwk;
//     console.log(`📎 Stored devicePublicKeyJwk for ${requestId} (x.len=${devicePublicKeyJwk.x.length})`);
//   } else if (approved) {
//     console.warn(`⚠️ Approved but missing/invalid devicePublicKeyJwk for ${requestId}`);
//   }
//   res.json({ success: true, message: `Login ${approved ? 'approved' : 'denied'}` });
// });


// Phone → approves or denies a login request
// Body: { requestId, approved, deviceFpr? }
// Body: { requestId, approved: true/false, deviceHash? }
app.post('/confirm-login', (req, res) => {
  try {
    const requestId = String(req.body?.requestId || '').trim();
    const approved  = !!req.body?.approved;
    const devicePublicKeyJwk = req.body?.devicePublicKeyJwk || null;

    if (!requestId) {
      return res.status(400).json({ success: false, error: 'requestId required' });
    }

    const login = pendingLogins[requestId];
    if (!login) {
      return res.status(404).json({ success: false, error: 'login_not_found' });
    }

    if (login.status !== 'pending') {
      return res.status(409).json({ success: false, error: 'login_not_pending' });
    }

    // If mobile says "deny", just record and return
    if (!approved) {
      login.status = 'denied';
      login.deniedAt = Date.now();
      return res.json({ success: true, approved: false });
    }

    const { email: emailNorm, origin, nonce } = login;

    if (!origin) {
      console.error('❌ /confirm-login: missing origin on pending login', requestId);
      return res.status(400).json({ success: false, error: 'missing_origin' });
    }
    if (!emailNorm || !nonce) {
      console.error('❌ /confirm-login: missing email/nonce on pending login', requestId);
      return res.status(400).json({ success: false, error: 'missing_email_or_nonce' });
    }

    // Optionally store device key JWK (for future session / key binding)
    if (devicePublicKeyJwk) {
      login.devicePublicKeyJwk = devicePublicKeyJwk;
    }

    // 🔐 Issue origin-bound, nonce-bound login token
    let loginToken;
    try {
      loginToken = makeLoginToken({
        emailNorm,
        origin,
        deviceHash: null, // or a real deviceHash if you have it
        nonce
      });
    } catch (e) {
      console.error('❌ /confirm-login makeLoginToken failed:', e.message || e);
      return res.status(500).json({ success: false, error: 'token_issue_failed' });
    }

    login.status      = 'approved';
    login.approvedAt  = Date.now();
    login.loginToken  = loginToken;

    return res.json({
      success:  true,
      approved: true,
      requestId,
      token:    loginToken
    });
  } catch (err) {
    console.error('❌ /confirm-login error:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});




app.get('/check-login/:requestId', (req, res) => {
  const r = pendingLogins[req.params.requestId];
  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });

  res.setHeader('Cache-Control', 'no-store');

  // If not approved yet, just report status (no token)
  if (r.status !== 'approved') {
    return res.json({
      success: true,
      status: r.status,
      devicePublicKeyJwk: r.devicePublicKeyJwk || null,
      extSession: r.extSession || null,
      loginToken: null
    });
  }

  // If approved, include loginToken (if minted)
  const loginToken = r.loginToken || null;

  return res.json({
    success: true,
    status: r.status,
    devicePublicKeyJwk: r.devicePublicKeyJwk || null,
    extSession: r.extSession || null,
    loginToken
  });
});


// ---------------------- Login status (extension / RP polls) ----------------------
// POST /check-login
// Body: { requestId, origin }
app.post('/check-login', (req, res) => {
  try {
    const { requestId, origin } = req.body || {};

    if (!requestId) {
      return res.status(400).json({ success: false, error: 'requestId required' });
    }
    if (!origin) {
      return res.status(400).json({ success: false, error: 'origin required' });
    }

    const r = pendingLogins[requestId];
    if (!r) {
      return res.status(404).json({ success: false, error: 'request_not_found' });
    }

    // Must be approved by phone
    if (r.status !== 'approved') {
      return res.status(409).json({ success: false, error: 'not_approved', status: r.status });
    }

    // Enforce origin binding (must match what we stored when request-login was called)
    if (!r.origin || r.origin !== origin) {
      return res.status(403).json({ success: false, error: 'origin_mismatch' });
    }

    const now = Date.now();
    const MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes from initial request
    if (!r.timestamp || (now - r.timestamp) > MAX_AGE_MS) {
      r.status = 'expired';
      return res.status(410).json({ success: false, error: 'expired' });
    }

    // Single-use: if already consumed, refuse
    if (r.status === 'consumed') {
      return res.status(409).json({ success: false, error: 'already_consumed' });
    }

    // Either use precomputed token from /confirm-login or mint now
    let token = r.loginToken;
    if (!token) {
      try {
        token = makeLoginToken({
          emailNorm:  r.email,
          origin:     r.origin,
          deviceHash: r.deviceHash || null,
          nonce:      r.nonce
        });
      } catch (e) {
        console.error('❌ makeLoginToken in /check-login failed:', e);
        return res.status(500).json({ success: false, error: 'token_issue_failed' });
      }
    }

    // Mark as consumed so it cannot be reused
    r.status = 'consumed';
    r.consumedAt = now;
    delete r.loginToken;

    return res.json({
      success: true,
      token,
      requestId
    });

  } catch (err) {
    console.error('❌ /check-login error:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});



app.get('/login-status/:requestId', (req, res) => {
  const requestId = String(req.params.requestId || '').trim();
  if (!requestId) {
    return res.status(400).json({ success: false, error: 'requestId required' });
  }

  const r = pendingLogins[requestId];
  if (!r) {
    return res.status(404).json({ success: false, error: 'request_not_found' });
  }

  const now = Date.now();
  const MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes hard cap
  if (!r.timestamp || (now - r.timestamp) > MAX_AGE_MS) {
    delete pendingLogins[requestId];
    return res.status(410).json({ success: false, error: 'expired' });
  }

  // Still waiting on phone
  if (r.status === 'pending') {
    return res.json({ success: true, status: 'pending' });
  }

  // Phone explicitly denied
  if (r.status === 'denied') {
    return res.json({ success: true, status: 'denied' });
  }

  // Approved: hand back the login token once, then wipe it
  if (r.status === 'approved') {
    const token = r.loginToken || null;

    // Optional: keep minimal record, but nuke token so it can't be replayed
    r.loginToken = null;

    if (!token) {
      // Should not normally happen if /confirm-login set it correctly
      return res.status(500).json({ success: false, error: 'token_missing' });
    }

    return res.json({
      success: true,
      status: 'approved',
      loginToken: token
    });
  }

  // Fallback for any weird state
  return res.status(500).json({ success: false, error: 'bad_state', state: r.status });
});


app.get('/get-session-handshake/:requestId', (req, res) => {
  const r = pendingLogins[req.params.requestId];
  if (!r) return res.status(404).json({ success: false, error: 'Request not found' });
  res.setHeader('Cache-Control', 'no-store');
  if (r.status !== 'approved') return res.json({ success: true, found: false, status: r.status });
  if (!r.extSession) return res.json({ success: true, found: false, status: 'awaiting_handshake' });
  const { keyId, eph, salt } = r.extSession || {};
  return res.json({ success: true, found: true, email: r.email, websiteDomain: r.websiteDomain || null, keyId, eph, salt });
});



// ---------------------- Issue Login Token ----------------------
// POST /issue-login-token
// Body: { requestId, origin }
// Returns a signed JWT login token if the request is approved.

app.post('/issue-login-token', (req, res) => {
  try {
    const requestId = String(req.body?.requestId || '').trim();
    const origin    = String(req.body?.origin || '').trim();

    if (!requestId || !origin) {
      return res.status(400).json({ success: false, error: 'requestId and origin required' });
    }

    const r = pendingLogins[requestId];
    if (!r) {
      return res.status(404).json({ success: false, error: 'Unknown requestId' });
    }

    if (r.status !== 'approved') {
      return res.status(400).json({ success: false, error: 'Not approved yet' });
    }

    const emailNorm = r.email;
    const nonce     = r.nonce;

    if (!emailNorm || !nonce) {
      return res.status(500).json({ success: false, error: 'Corrupt pendingLogin entry' });
    }

    // --- Create the final login token ---
    const token = makeLoginToken({
      emailNorm,
      origin,      // relying-party origin
      nonce,
      deviceHash: r.deviceHash || null
    });

    // Mark consumed
    r.status = 'consumed';

    return res.json({
      success: true,
      loginToken: token
    });

  } catch (err) {
    console.error("❌ /issue-login-token error:", err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});




// Pre-registration check - make sure email is not already registered
app.get('/identity-status', async (req, res) => {
  try {
    const emailNorm = normalizeEmail(req.query?.email || '');
    if (!emailNorm || !emailNorm.includes('@')) {
      return res.status(400).json({ success:false, error:'valid email required' });
    }
    const out = await probeIdentityRegistered(emailNorm);
    return res.json({ success:true, registered: out.registered });
  } catch (err) {
    console.error('❌ /identity-status:', err);
    return res.status(500).json({ success:false, error:'identity_status_failed' });
  }
});


// ---------------------- Email verify (dev) ----------------------
app.post('/start-email-verify', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  if (!emailNorm) return res.status(400).json({ success: false, error: 'Missing email' });
  const code = makeCode6();
  pendingEmailCodes[emailNorm] = { code, expiresAt: Date.now() + 10 * 60 * 1000 };
  console.log(`📧 Email verify code for ${emailNorm}: ${code} (valid 10 min)`);
  return res.json({ success: true });
});

app.post('/confirm-email-verify', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  const code = String(req.body?.code || '');
  if (!emailNorm || !code) return res.status(400).json({ success: false, error: 'Missing fields' });
  const rec = pendingEmailCodes[emailNorm];
  if (!rec) return res.status(400).json({ success: false, error: 'No code pending' });
  if (Date.now() > rec.expiresAt) { delete pendingEmailCodes[emailNorm]; return res.status(400).json({ success: false, error: 'Code expired' }); }
  if (code !== rec.code) return res.status(400).json({ success: false, error: 'Invalid code' });
  verifiedEmails[emailNorm] = true;
  delete pendingEmailCodes[emailNorm];
  console.log(`✅ Email verified: ${emailNorm}`);
  return res.json({ success: true });
});

// ---------------------- Debug ----------------------
app.get('/debug', (req, res) => res.json({ success: true, message: 'This is the real nft-login-server.js' }));

// --- Card challenge (to be signed by the card's Authentication key) ---
// app.post('/card-challenge', (req, res) => {
//   try {
//     if (!cardAuthKey) return res.status(503).json({ success: false, error: 'card key not loaded' });
//     const emailNorm = normalizeEmail(req.body?.email || '');
//     if (!emailNorm || !emailNorm.includes('@')) return res.status(400).json({ success: false, error: 'valid email required' });

//     const now = Math.floor(Date.now() / 1000);
//     const nonce = crypto.randomBytes(16).toString('hex');
//     const challenge = `nftvault:card-auth|email=${emailNorm}|ts=${now}|nonce=${nonce}`;
//     const ttlSec = 120;

//     pendingCardChallenges[emailNorm] = { challenge, expiresAt: Date.now() + ttlSec * 1000 };

//     return res.json({
//       success: true,
//       challenge,
//       expiresAt: now + ttlSec,
//       spec: {
//         algo: 'RSA-PKCS1v1_5-SHA256',
//         encoding: 'UTF-8 bytes of challenge string',
//         fieldOrder: 'literal string as returned (no JSON canonicalization)'
//       }
//     });
//   } catch (e) {
//     console.error('❌ /card-challenge:', e);
//     return res.status(500).json({ success: false, error: 'challenge failed' });
//   }
// });

const activeChallenges = Object.create(null);

app.post('/card-challenge', (req, res) => {
  try {
    const rawEmail  = String(req.body?.email || '').trim();
    const emailNorm = normalizeEmail(rawEmail);

    if (!emailNorm) {
      return res.status(400).json({
        success: false,
        error: 'email required'
      });
    }

    const cardInfo = userCards[emailNorm];
    if (!cardInfo || !cardInfo.spkiPem) {
      return res.status(400).json({
        success: false,
        error: 'no card registered for this email'
      });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');

    pendingCardChallenges[emailNorm] = {
      challenge,
      createdAt: Date.now()
    };

    console.log(`💳 Issued card challenge for ${emailNorm}`);
    return res.json({ success: true, challenge });
  } catch (err) {
    console.error('🔥 /card-challenge error:', err);
    return res.status(500).json({ success: false, error: 'server error challenge' });
  }
});


function pemToDer(pem) {
  return Buffer.from(
    pem.replace(/-----BEGIN PUBLIC KEY-----/g, "")
       .replace(/-----END PUBLIC KEY-----/g, "")
       .replace(/\s+/g, ""),
    "base64"
  );
}


app.post('/card-register-final', async (req, res) => {
  try {
    const emailNorm = normalizeEmail(req.body?.email || '');
    const spkiPem = req.body?.spkiPem;
    const signatureB64 = req.body?.signatureB64;

    if (!emailNorm || !spkiPem || !signatureB64) {
      return res.status(400).json({
        success: false,
        error: "email, spkiPem, signatureB64 required"
      });
    }

    // 1. Verify challenge exists
    const challenge = activeChallenges[emailNorm];
    if (!challenge) {
      return res.status(400).json({ success: false, error: "missing challenge" });
    }

    // 2. Verify signature
    const verifier = crypto.createVerify("SHA256");
    verifier.update(challenge);
    verifier.end();

    const spkiDer = pemToDer(spkiPem);

    const ok = verifier.verify(
      { key: spkiDer, type: "spki", format: "der" },
      Buffer.from(signatureB64, "base64")
    );

    if (!ok) {
      return res.status(400).json({ success: false, error: "signature invalid" });
    }

    // 3. Store it
    // cardRegistry[emailNorm] = {
    //   spkiPem,
    //   added: Date.now()
    // };

    // Challenge is now consumed
    delete activeChallenges[emailNorm];

    res.json({ success: true });

  } catch (e) {
    console.error("card-register-final error:", e);
    res.status(500).json({ success: false, error: "server error" });
  }
});








// ---------------------- Credentials storage ----------------------
app.post('/store-credentials', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  const deviceId = String(req.body?.deviceId || '');
  const credentials = req.body?.credentials;

  if (!emailNorm || !deviceId || !Array.isArray(credentials)) {
    console.log('❌ /store-credentials 400 shape', {
      emailNorm,
      deviceId,
      credsType: Array.isArray(credentials) ? 'array' : typeof credentials,
    });
    return res.status(400).json({ success: false, error: 'Missing or invalid fields' });
  }

  const hasLiveSession =
    sessionApprovals[emailNorm] && Date.now() < sessionApprovals[emailNorm];

  if (!verifiedEmails[emailNorm] && !hasLiveSession) {
    console.log('❌ /store-credentials 403 session gate', {
      emailNorm,
      verified: !!verifiedEmails[emailNorm],
      hasLiveSession,
      sessionExpiry: sessionApprovals[emailNorm] || null,
    });
    return res.status(403).json({ success: false, error: 'Session locked or expired' });
  }

  const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN || null;
  if (!token) {
    console.log('❌ /store-credentials 403 token gate', {
      emailNorm,
      hasUserToken: !!userTokens[emailNorm],
      hasTestToken: !!process.env.TEST_PUSH_TOKEN,
    });
    return res.status(403).json({ success: false, error: 'Unregistered device' });
  }

  userCredentials[emailNorm] = credentials;
  console.log(`💾 Stored ${credentials.length} encrypted credentials for ${emailNorm}`);
  return res.json({ success: true });
});


// app.post('/get-credentials', (req, res) => {
//   const emailNorm = normalizeEmail(req.body?.email || '');
//   if (!emailNorm) return res.status(400).json({ error: 'Missing email' });

//   const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN || null;
//   if (!token) return res.status(403).json({ error: 'No registered device token' });

//   const creds = userCredentials[emailNorm] || [];
//   console.log(`📤 Returned ${creds.length} credentials for ${emailNorm}`);
//   res.json({ success: true, credentials: creds });
// });

app.post('/get-credentials', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  if (!emailNorm) return res.status(400).json({ success: false, error: 'Missing email' });

  const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN || null;
  if (!token) return res.status(403).json({ success: false, error: 'No registered device token' });

  // Require live session or verified email before returning vault contents
  const hasLiveSession = sessionApprovals[emailNorm] && Date.now() < sessionApprovals[emailNorm];
  if (!verifiedEmails[emailNorm] && !hasLiveSession) {
    return res.status(403).json({ success: false, error: 'Session locked or expired' });
  }

  const creds = userCredentials[emailNorm] || [];
  console.log(`📤 Returned ${creds.length} credentials for ${emailNorm}`);
  return res.json({
    success: true,
    credentials: creds,
    sessionExpiresAt: hasLiveSession ? sessionApprovals[emailNorm] : null
  });
});


app.post('/delete-credential', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  const deviceId = String(req.body?.deviceId || '');
  const credentialId = req.body?.credentialId;
  console.log("🧠 Incoming DELETE request with:", { email: emailNorm, deviceId, credentialId });

  if (!emailNorm || !deviceId || !credentialId) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  const list = userCredentials[emailNorm];
  if (!Array.isArray(list)) return res.json({ success: true, removed: 0 });

  const target = String(credentialId).trim().toLowerCase();
  const before = list.length;
  const updated = list.filter(c => String(c?.id || '').trim().toLowerCase() !== target);
  const removed = before - updated.length;

  userCredentials[emailNorm] = updated;

  console.log(`🗑️ Delete ${credentialId} for ${emailNorm} → removed=${removed} (before=${before}, after=${updated.length})`);
  return res.json({ success: true, removed });
});

app.post('/wipe-credentials', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  if (!emailNorm) return res.status(400).json({ error: 'Missing email' });
  delete userCredentials[emailNorm];
  console.log(`🧹 Wiped all credentials for ${emailNorm}`);
  res.json({ success: true });
});

// ---------------------- Messaging endpoints ----------------------

// In-memory mapping from messagingId (Curve25519 pubkey base64) -> Set of FCM tokens
//const messagingTokensById = Object.create(null);

// Generic helper: fan-out a push to all FCM tokens registered for a messagingId
// messagingId (base64 pubkey) -> FCM tokens are stored in callDeviceMap / messaging device maps
async function pushToMessagingId(messagingId, data) {
  const tokens = await getDeviceTokensForMessagingId(messagingId);
  if (!tokens || tokens.length === 0) {
    console.warn("📡 pushToMessagingId: no tokens for", messagingId);
    return;
  }

  // FCM data must be strings
  const dataStrings = {};
  for (const [k, v] of Object.entries(data || {})) {
    if (v === undefined || v === null) continue;
    dataStrings[k] = String(v);
  }

  // Build APNs payload with all keys at top level
  const apnsPayload = {
    aps: {
      "content-available": 1
    }
  };

  // Mirror all data keys into APNs (top-level in userInfo)
  for (const [k, v] of Object.entries(dataStrings)) {
    if (k === "type") continue; // type handled below
    apnsPayload[k] = v;
  }

  // Put type into aps.category and into userInfo["type"]
  if (dataStrings.type) {
    apnsPayload.aps.category = dataStrings.type;
    apnsPayload.type = dataStrings.type;
  }

  const message = {
    tokens,
    data: dataStrings,
    apns: {
      headers: {
        "apns-push-type": "background",
        "apns-priority": "5"
      },
      payload: apnsPayload
    }
  };

  try {
    const resp = await admin.messaging().sendEachForMulticast(message);
    console.log(
      "✅ FCM push →",
      resp.successCount,
      "success,",
      resp.failureCount,
      "failure for type=",
      dataStrings.type || ""
    );
    return resp;
  } catch (err) {
    console.error("🔥 pushToMessagingId error:", err);
    throw err;
  }
}




// ---------------------- E2EE Messaging relay (no plaintext stored) ----------------------

// POST /messages/send
// Body: { senderMessagingId, recipientMessagingId, messageId, timestamp, ciphertextB64 }
// app.post('/messages/send', async (req, res) => {
//   try {
//       const senderMessagingId    = String(req.body?.senderMessagingId || '').trim();
//       const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
//       const messageId            = String(req.body?.messageId || '').trim();
//       const tsRaw                = req.body?.timestamp;
//       const ciphertextB64        = String(req.body?.ciphertextB64 || '').trim();

//       if (!senderMessagingId || !recipientMessagingId || !messageId || !ciphertextB64) {
//           return res.status(400).json({ success: false, error: 'Missing fields' });
//       }

//       // Rate limit: 60 messages per minute per sender
//       const allowed = await checkRateLimit(`ratelimit:send:${senderMessagingId}`, 60, 60);
//       if (!allowed) {
//           console.log(`🚫 Rate limited /messages/send for ${senderMessagingId.slice(0, 16)}…`);
//           return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
//       }

//       if (
//           senderMessagingId.length > 256 ||
//           recipientMessagingId.length > 256 ||
//           messageId.length > 128
//       ) {
//           return res.status(400).json({ success: false, error: 'Bad id length' });
//       }

//       const ts = Number(tsRaw) > 0 ? Number(tsRaw) : Date.now();

//       const msg = {
//           id: messageId,
//           ts,
//           senderMessagingId,
//           ciphertextB64
//       };

//       // Store message in Redis with 7-day TTL
//       const msgKey = `pending_msgs:${recipientMessagingId}`;
//       await redis.rpush(msgKey, JSON.stringify(msg));
//       await redis.expire(msgKey, 24 * 60 * 60);  // 24 hours TTL

//       // Cap at 200 messages per recipient
//       const listLen = await redis.llen(msgKey);
//       if (listLen > 200) {
//           await redis.ltrim(msgKey, listLen - 200, -1);
//       }

//       console.log(`📨 Stored message for recipient ${recipientMessagingId.slice(0, 16)}… (queue size=${listLen})`);

//       // ✅ NEW: Get tokens from Redis instead of in-memory object
//       const tokens = await redis.smembers(`msg_tokens:${recipientMessagingId}`);
//       console.log(`🔔 Chat push lookup for ${recipientMessagingId.slice(0, 16)}… tokens=${tokens.length}`);

//       if (tokens && tokens.length > 0) {
//           const baseMsg = {
//               notification: {
//                   title: 'NFTAuth Messenger',
//                   body: 'New encrypted message'
//               },
//               data: {
//                   type: 'message',
//                   senderMessagingId,
//                   messageId
//               }
//           };

//           for (const token of tokens) {
//               admin.messaging()
//                   .send({ token, ...baseMsg })
//                   .then((id) => {
//                       console.log(`📨 FCM chat push sent to ${token.slice(0, 12)}…: ${id}`);
//                   })
//                   .catch((err) => {
//                       console.warn('⚠️ FCM chat push failed:', err.message || err);
//                   });
//           }
//       } else {
//           console.log(`ℹ️ No registered messaging tokens for ${recipientMessagingId.slice(0, 16)}…`);
//       }

//       return res.json({ success: true });
//   } catch (err) {
//       console.error('❌ /messages/send crashed:', err);
//       return res.status(500).json({ success: false, error: 'internal_error' });
//   }
// });

// POST /messages/send
app.post('/messages/send', async (req, res) => {
  try {
      const senderMessagingId    = String(req.body?.senderMessagingId || '').trim();
      const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
      const messageId            = String(req.body?.messageId || '').trim();
      const tsRaw                = req.body?.timestamp;
      const ciphertextB64        = String(req.body?.ciphertextB64 || '').trim();

      if (!senderMessagingId || !recipientMessagingId || !messageId || !ciphertextB64) {
          return res.status(400).json({ success: false, error: 'Missing fields' });
      }

      // Rate limit: 60 messages per minute per sender
      const allowed = await checkRateLimit(`ratelimit:send:${senderMessagingId}`, 60, 60);
      if (!allowed) {
          console.log(`🚫 Rate limited /messages/send for ${senderMessagingId.slice(0, 16)}…`);
          return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
      }

      if (
          senderMessagingId.length > 256 ||
          recipientMessagingId.length > 256 ||
          messageId.length > 128
      ) {
          return res.status(400).json({ success: false, error: 'Bad id length' });
      }

      const ts = Number(tsRaw) > 0 ? Number(tsRaw) : Date.now();

      const msg = {
          id: messageId,
          ts,
          senderMessagingId,
          ciphertextB64
      };

      // Store message in Redis with 10-minute TTL
      const msgKey = bucketKeyForMessagingId(recipientMessagingId);
      await redis.rpush(msgKey, JSON.stringify(msg));
      await redis.expire(msgKey, 10 * 60);  // 10 minutes TTL

      // Cap at 200 messages per recipient bucket
      const listLen = await redis.llen(msgKey);
      if (listLen > 200) {
          await redis.ltrim(msgKey, listLen - 200, -1);
      }

      console.log(`📨 Stored message for bucket ${msgKey} (queue size=${listLen})`);

      // ✅ Get tokens from Redis instead of in-memory object
      const tokens = await redis.smembers(`msg_tokens:${recipientMessagingId}`);
      console.log(`🔔 Chat push lookup for ${recipientMessagingId.slice(0, 16)}… tokens=${tokens.length}`);

      if (tokens && tokens.length > 0) {
          const baseMsg = {
              notification: {
                  title: 'NFTAuth Messenger',
                  body: 'New encrypted message'
              },
              data: {
                  type: 'message',
                  senderMessagingId,
                  messageId
              }
          };

          for (const token of tokens) {
              admin.messaging()
                  .send({ token, ...baseMsg })
                  .then((id) => {
                      console.log(`📨 FCM chat push sent to ${token.slice(0, 12)}…: ${id}`);
                  })
                  .catch((err) => {
                      console.warn('⚠️ FCM chat push failed:', err.message || err);
                  });
          }
      } else {
          console.log(`ℹ️ No registered messaging tokens for ${recipientMessagingId.slice(0, 16)}…`);
      }

      return res.json({ success: true });
  } catch (err) {
      console.error('❌ /messages/send crashed:', err);
      return res.status(500).json({ success: false, error: 'internal_error' });
  }
});



// app.post('/messages/ack', async (req, res) => {
//   try {
//     const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
//     const messageIds = req.body?.messageIds;

//     if (!recipientMessagingId || !Array.isArray(messageIds) || messageIds.length === 0) {
//       return res.status(400).json({ success: false, error: 'recipientMessagingId and messageIds[] required' });
//     }

//     const key = `pending_msgs:${recipientMessagingId}`;
    
//     // Get all messages
//     const rawMessages = await redis.lrange(key, 0, -1);
    
//     // Filter out acknowledged ones
//     const remaining = rawMessages.filter(m => {
//       try {
//         const parsed = JSON.parse(m);
//         return !messageIds.includes(parsed.id);
//       } catch {
//         return false;
//       }
//     });

//     // Replace list with remaining messages
//     await redis.del(key);
//     if (remaining.length > 0) {
//       await redis.rpush(key, ...remaining);
//       await redis.expire(ackedKey, 24 * 60 * 60);  // 24 hours TTL
//     }

//     console.log(`✅ ACK ${messageIds.length} messages for ${recipientMessagingId.slice(0, 16)}… (${remaining.length} remaining)`);

//     return res.json({ success: true, acknowledged: messageIds.length });
//   } catch (err) {
//     console.error('❌ /messages/ack error:', err);
//     return res.status(500).json({ success: false, error: 'internal_error' });
//   }
// });

app.post('/messages/ack', async (req, res) => {
  try {
    const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
    const messageIds = req.body?.messageIds;

    if (!recipientMessagingId || !Array.isArray(messageIds) || messageIds.length === 0) {
      return res.status(400).json({ success: false, error: 'recipientMessagingId and messageIds[] required' });
    }

    const key = bucketKeyForMessagingId(recipientMessagingId);
    
    // Get all messages
    const rawMessages = await redis.lrange(key, 0, -1);
    
    // Filter out acknowledged ones
    const remaining = rawMessages.filter(m => {
      try {
        const parsed = JSON.parse(m);
        return !messageIds.includes(parsed.id);
      } catch {
        return false;
      }
    });

    // Replace list with remaining messages
    await redis.del(key);
    if (remaining.length > 0) {
      await redis.rpush(key, ...remaining);
      await redis.expire(key, 10 * 60);
    }

    console.log(`✅ ACK ${messageIds.length} messages for bucket ${key} (${remaining.length} remaining)`);

    return res.json({ success: true, acknowledged: messageIds.length });
  } catch (err) {
    console.error('❌ /messages/ack error:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});




// POST /messages/sync
// Body: { recipientMessagingId }
// Returns and *clears* all queued messages for that recipient
// app.post('/messages/sync', async (req, res) => {
//   try {
//     const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
//     if (!recipientMessagingId) {
//       return res.status(400).json({ success: false, error: 'recipientMessagingId required' });
//     }

//     // Rate limit: 30 syncs per minute
//     const allowed = await checkRateLimit(`ratelimit:sync:${recipientMessagingId}`, 30, 60);
//     if (!allowed) {
//         console.log(`🚫 Rate limited /messages/sync for ${recipientMessagingId.slice(0, 16)}…`);
//         return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
//     }

//     const key = `pending_msgs:${recipientMessagingId}`;
    
//     // Get all pending messages (but don't delete)
//     const rawMessages = await redis.lrange(key, 0, -1);
    
//     const messages = rawMessages.map(m => {
//       try {
//         return JSON.parse(m);
//       } catch {
//         return null;
//       }
//     }).filter(Boolean);

//     console.log(`📤 Sync for ${recipientMessagingId.slice(0, 16)}… returned=${messages.length}`);

//     res.setHeader('Cache-Control', 'no-store');
//     return res.json({ success: true, messages });
//   } catch (err) {
//     console.error('❌ /messages/sync error:', err);
//     return res.status(500).json({ success: false, error: 'internal_error' });
//   }
// });

// POST /messages/sync
// Body: { recipientMessagingId }
// Returns all queued messages for that recipient (does NOT clear them here)
app.post('/messages/sync', async (req, res) => {
  try {
    const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
    if (!recipientMessagingId) {
      return res.status(400).json({ success: false, error: 'recipientMessagingId required' });
    }

    // Rate limit: 30 syncs per minute
    const allowed = await checkRateLimit(`ratelimit:sync:${recipientMessagingId}`, 30, 60);
    if (!allowed) {
        console.log(`🚫 Rate limited /messages/sync for ${recipientMessagingId.slice(0, 16)}…`);
        return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
    }

    const key = bucketKeyForMessagingId(recipientMessagingId);
    
    // Get all pending messages (but don't delete)
    const rawMessages = await redis.lrange(key, 0, -1);
    
    const messages = rawMessages.map(m => {
      try {
        return JSON.parse(m);
      } catch {
        return null;
      }
    }).filter(Boolean);

    console.log(`📤 Sync for bucket ${key} returned=${messages.length}`);

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ success: true, messages });
  } catch (err) {
    console.error('❌ /messages/sync error:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});



// POST /messaging/register-device
app.post('/messaging/register-device', async (req, res) => {
  try {
      const messagingId = String(req.body?.messagingId || '').trim();
      const deviceToken = String(req.body?.deviceToken || '').trim();

      if (!messagingId || !deviceToken) {
          console.warn('⚠️ /messaging/register-device missing fields', req.body);
          return res.status(400).json({ success: false, error: 'messagingId and deviceToken required' });
      }

      await addMessagingToken(messagingId, deviceToken);

      return res.json({ success: true });
  } catch (err) {
      console.error('❌ /messaging/register-device error:', err);
      return res.status(500).json({ success: false, error: 'internal_error' });
  }
});


// === CALLS: register device token for a messagingId ===
//
// POST /calls/register
// {
//   "messagingId": "base64-public-key",
//   "fcmToken": "device-fcm-token"
// }
app.post("/calls/register", async (req, res) => {
  try {
      const { messagingId, fcmToken } = req.body || {};
      if (!messagingId || !fcmToken) {
          console.error("❌ /calls/register missing fields:", req.body);
          return res.status(400).json({ error: "missing messagingId or fcmToken" });
      }

      await addDeviceTokenForMessagingId(messagingId, fcmToken);

      const count = await redis.scard(`call_tokens:${messagingId}`);
      return res.json({ ok: true, tokenCount: count });
  } catch (err) {
      console.error("🔥 /calls/register error:", err);
      return res.status(500).json({ error: "internal_error" });
  }
});



// ---------------------- Call signaling (WebRTC-style) ----------------------


// === CALLS: outgoing offer ===
//
// iOS sends POST /calls/offer with:
// {
//   callId: "uuid",
//   fromMessagingId: "base64 pubkey (caller)",
//   toMessagingId: "base64 pubkey (callee)",
//   sdpOffer: "…",
//   displayName: "Caller Name"
// }
app.post("/calls/offer", async (req, res) => {
  try {
    const {
      callId,
      fromMessagingId,
      toMessagingId,
      sdpOffer,
      displayName
    } = req.body || {};

    if (!callId || !fromMessagingId || !toMessagingId || !sdpOffer) {
      console.error("❌ /calls/offer missing fields:", req.body);
      return res.status(400).json({ error: "missing required fields" });
    }

    // Rate limit: 10 calls per minute per caller
    const allowed = await checkRateLimit(`ratelimit:call:${fromMessagingId}`, 10, 60);
    if (!allowed) {
        console.log(`🚫 Rate limited /calls/offer for ${fromMessagingId.slice(0, 16)}…`);
        return res.status(429).json({ success: false, error: 'rate_limited', retryAfter: 60 });
    }

    console.log(
      "📞 /calls/offer",
      callId,
      "from",
      (fromMessagingId || "").slice(0, 12) + "…",
      "→",
      (toMessagingId || "").slice(0, 12) + "…"
    );

    // Get tokens for the callee
    const tokens = await getDeviceTokensForMessagingId(toMessagingId);
    if (!tokens || tokens.length === 0) {
      console.warn("📡 /calls/offer: no tokens for", toMessagingId);
      return res.status(404).json({ error: "no device tokens for recipient" });
    }

    const callerName = displayName || fromMessagingId.slice(0, 8) + "…";

    // Data payload (all strings)
    const dataPayload = {
      type: "call_offer",
      callId: String(callId),
      callerMessagingId: String(fromMessagingId),
      callerDisplayName: callerName,
      sdpOffer: String(sdpOffer),
      sdp: String(sdpOffer)
    };

    const message = {
      tokens,
      
      // ✅ Visible notification for iOS
      notification: {
        title: "Incoming Call",
        body: `${callerName} is calling you`
      },
      
      // Data payload
      data: dataPayload,
      
      // Android: high priority
      android: {
        priority: "high",
        notification: {
          channelId: "calls",
          priority: "max",
          defaultSound: true,
          defaultVibrateTimings: true
        }
      },
      
      // ✅ iOS: alert push with high priority
      apns: {
        headers: {
          "apns-push-type": "alert",   // ← Changed from "background"
          "apns-priority": "10"         // ← High priority (10 = immediate)
        },
        payload: {
          aps: {
            alert: {
              title: "Incoming Call",
              body: `${callerName} is calling you`
            },
            sound: "default",           // ← Play sound
            badge: 1,
            "content-available": 1,     // Also wake the app
            category: "CALL_INCOMING"   // Optional: for actionable notifications
          },
          // Mirror data into APNs payload
          type: "call_offer",
          callId: String(callId),
          callerMessagingId: String(fromMessagingId),
          callerDisplayName: callerName,
          sdpOffer: String(sdpOffer),
          sdp: String(sdpOffer)
        }
      }
    };

    const resp = await admin.messaging().sendEachForMulticast(message);
    console.log(
      "✅ FCM call_offer push →",
      resp.successCount,
      "success,",
      resp.failureCount,
      "failure"
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error("🔥 /calls/offer error:", err);
    return res.status(500).json({ error: "internal_error" });
  }
});


app.post('/calls/answer', async (req, res) => {
  try {
    const { callId, callerMessagingId, calleeMessagingId, sdpAnswer } = req.body;

    console.log(
      "📞 /calls/answer",
      callId,
      "from",
      calleeMessagingId,
      "→",
      callerMessagingId
    );

    if (!callId || !callerMessagingId || !sdpAnswer) {
      return res.status(400).json({ error: "missing_fields" });
    }

    await pushToMessagingId(callerMessagingId, {
      type: "call_answer",
      callId,
      sdpAnswer
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("🔥 /calls/answer error:", err);
    return res.status(500).json({ error: "internal_error" });
  }
});


// === CALLS: ICE candidates ===
//
// iOS sends POST /calls/ice with:
// {
//   callId: "uuid",
//   fromMessagingId: "sender pubkey",
//   toMessagingId: "receiver pubkey",
//   sdp: "candidate sdp",
//   sdpMLineIndex: 0,
//   sdpMid: "0"
// }
app.post("/calls/ice", async (req, res) => {
  try {
    const {
      callId,
      fromMessagingId,
      toMessagingId,
      sdp,
      sdpMLineIndex,
      sdpMid
    } = req.body || {};

    if (!callId || !fromMessagingId || !toMessagingId || !sdp) {
      console.error("❌ /calls/ice missing fields:", req.body);
      return res.status(400).json({ error: "missing required fields" });
    }

    const dataPayload = {
      type: "call_ice",
      callId: String(callId),
      fromMessagingId: String(fromMessagingId),
      toMessagingId: String(toMessagingId),
      sdp: String(sdp),
      sdpMLineIndex: String(sdpMLineIndex ?? "0"),
      sdpMid: sdpMid != null ? String(sdpMid) : ""
    };

    await pushToMessagingId(toMessagingId, dataPayload);

    return res.json({ ok: true });
  } catch (err) {
    console.error("🔥 /calls/ice error:", err);
    return res.status(500).json({ error: "internal_error" });
  }
});


// POST /calls/candidate
// Body: { callId, fromMessagingId, toMessagingId, candidateJson }
app.post('/calls/candidate', async (req, res) => {
  try {
    const callId          = String(req.body?.callId || '').trim();
    const fromMessagingId = String(req.body?.fromMessagingId || '').trim();
    const toMessagingId   = String(req.body?.toMessagingId || '').trim();
    const candidateJson   = String(req.body?.candidateJson || '').trim();

    if (!callId || !fromMessagingId || !toMessagingId || !candidateJson) {
      return res.status(400).json({ success: false, error: 'callId, fromMessagingId, toMessagingId, candidateJson required' });
    }

    const call = callsById[callId];
    if (call) call.lastUpdate = Date.now();

    await pushToMessagingId(toMessagingId, {
      type: 'call_candidate',
      callId,
      fromMessagingId,
      toMessagingId,
      candidateJson
    });

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ /calls/candidate crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});


// POST /calls/hangup
// Body: { callId, fromMessagingId, toMessagingId, reason? }
app.post('/calls/hangup', async (req, res) => {
  try {
    const callId          = String(req.body?.callId || '').trim();
    const fromMessagingId = String(req.body?.fromMessagingId || '').trim();
    const toMessagingId   = String(req.body?.toMessagingId || '').trim();
    const reason          = String(req.body?.reason || 'hangup').trim();

    if (!callId || !fromMessagingId || !toMessagingId) {
      return res.status(400).json({ success: false, error: 'callId, fromMessagingId, toMessagingId required' });
    }

    const call = callsById[callId];
    if (call) {
      call.status     = 'ended';
      call.endedAt    = Date.now();
      call.lastUpdate = call.endedAt;
    }

    console.log(`📵 /calls/hangup ${callId} from ${fromMessagingId.slice(0, 12)}… reason=${reason}`);

    await pushToMessagingId(toMessagingId, {
      type: 'call_hangup',
      callId,
      fromMessagingId,
      toMessagingId,
      reason
    });

    delete callsById[callId];

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ /calls/hangup crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});


// ---------------------- Phone-assisted decrypt ----------------------
app.post('/request-decrypt', async (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  const credentialId = String(req.body?.credentialId || '');
  const label = req.body?.label || '';
  if (!emailNorm || !credentialId) return res.status(400).json({ success: false, error: 'email and credentialId required' });

  const user = await db.getUserByEmail(emailNorm);
  const deviceToken = user?.deviceToken;
  if (!deviceToken) return res.status(403).json({ success: false, error: 'No registered device token' });

  const txId = uuidv4();
  pendingDecrypts[txId] = { email: emailNorm, credentialId, status: 'pending', createdAt: Date.now() };

  const message = {
    token: deviceToken,
    notification: { title: 'Approve autofill?', body: `Send credential ${label || ''}`.trim() || 'Send credential to your browser?' },
    data: { type: 'decrypt_request', email: emailNorm, credentialId, txId },
    android: { priority: 'high' },
    apns: { payload: { aps: { sound: 'default', category: 'DECRYPT_REQUEST' } } }
  };

  try {
    await admin.messaging().send(message);
    console.log(`🔓 Decrypt request sent to ${emailNorm} (cred ${credentialId}, tx ${txId})`);
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
    tx.expiresAt = Date.now() + 60_000;
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




// ---------------------- Pay endpoints ----------------------

// Per-payment session state (in-memory, like pendingLogins)
const cardPayments = Object.create(null);
// shape: cardPayments[paymentId] = {
//   paymentId,
//   cardKey,       // some identifier for the card (e.g. card public key or app-derived id)
//   amount,
//   currency,
//   vendorId,
//   status: "pending" | "approved" | "denied",
//   approved: boolean,
//   createdAt: number
// }



// POST /pay-start
// body: { amountCents, currency, description }
app.post('/pay-start', (req, res) => {
  try {
    const amountCents = Number(req.body?.amountCents || 0);
    const currency    = String(req.body?.currency || 'USD').toUpperCase();
    const description = String(req.body?.description || 'Payment');

    if (!Number.isFinite(amountCents) || amountCents <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid amountCents' });
    }

    const paymentId = `pay_${Date.now()}_${++paymentCounter}`;
    const challenge = crypto.randomBytes(32).toString('base64url');

    pendingPayments[paymentId] = {
      paymentId,
      challenge,
      amountCents,
      currency,
      description,
      status: 'awaiting_card',   // awaiting_card → pending_approval → approved/denied/expired
      emailNorm: null,
      cardEmailNorm: null,
      createdAt: Date.now()
    };

    console.log(`💳 /pay-start → paymentId=${paymentId}, amount=${amountCents} ${currency}, desc="${description}"`);

    return res.json({
      success: true,
      paymentId,
      challenge
    });
  } catch (err) {
    console.error('🔥 /pay-start error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});


// POST /pay-card
// body: { paymentId, signatureB64 }
app.post('/pay-card', async (req, res) => {
  try {
    const paymentId    = String(req.body?.paymentId || '');
    const signatureB64 = String(req.body?.signatureB64 || '');

    if (!paymentId || !signatureB64) {
      return res.status(400).json({ success: false, error: 'paymentId and signatureB64 required' });
    }

    const payment = pendingPayments[paymentId];
    if (!payment) {
      return res.status(404).json({ success: false, error: 'Unknown paymentId' });
    }

    if (payment.status !== 'awaiting_card') {
      return res.status(400).json({ success: false, error: `Payment not in awaiting_card state (status=${payment.status})` });
    }

    const sig = Buffer.from(signatureB64, 'base64');
    const di  = makeDigestInfoSha256(payment.challenge);

    let matchedEmailNorm = null;

    // userCards[emailNorm] = [ { spkiPem: '...', ... }, ... ]
    for (const [emailNorm, cards] of Object.entries(userCards)) {
      if (!Array.isArray(cards)) continue;

      for (const card of cards) {
        const spkiPem = card.spkiPem || card.publicKeyPem || card.spki;
        if (!spkiPem) continue;

        try {
          const pubKey = crypto.createPublicKey(spkiPem);
          const recovered = crypto.publicDecrypt(
            { key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            sig
          );
          if (recovered.equals(di)) {
            matchedEmailNorm = normalizeEmail(emailNorm);
            console.log(`💳 /pay-card → signature verified for ${matchedEmailNorm}`);
            break;
          }
        } catch (e) {
          // try next key
        }
      }

      if (matchedEmailNorm) break;
    }

    if (!matchedEmailNorm) {
      console.warn('⚠️ /pay-card signature invalid or card not registered');
      return res.status(400).json({ success: false, error: 'Card signature invalid or card not registered' });
    }

    payment.status        = 'pending_approval';
    payment.emailNorm     = matchedEmailNorm;
    payment.cardEmailNorm = matchedEmailNorm;

    // send push to the account owner asking to approve this payment
    await sendPaymentPush(matchedEmailNorm, payment);

    return res.json({ success: true });
  } catch (err) {
    console.error('🔥 /pay-card error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});


// GET /pay-status?paymentId=...
app.get('/pay-status', (req, res) => {
  try {
    const paymentId = String(req.query.paymentId || '');
    if (!paymentId) {
      return res.status(400).json({ success: false, error: 'paymentId required' });
    }

    const payment = pendingPayments[paymentId];
    if (!payment) {
      return res.json({ success: true, status: 'expired' });
    }

    const age = Date.now() - payment.createdAt;
    if (age > PAYMENT_TTL_MS && payment.status === 'awaiting_card') {
      payment.status = 'expired';
    }

    return res.json({ success: true, status: payment.status });
  } catch (err) {
    console.error('🔥 /pay-status error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});


// POST /pay-confirm
// body: { paymentId, approved: true/false }
app.post('/pay-confirm', (req, res) => {
  try {
    const paymentId = String(req.body?.paymentId || '');
    const approved  = Boolean(req.body?.approved);

    if (!paymentId) {
      return res.status(400).json({ success: false, error: 'paymentId required' });
    }

    const payment = pendingPayments[paymentId];
    if (!payment) {
      return res.status(404).json({ success: false, error: 'Unknown paymentId' });
    }

    if (payment.status !== 'pending_approval') {
      return res.status(400).json({ success: false, error: `Payment not pending approval (status=${payment.status})` });
    }

    payment.status = approved ? 'approved' : 'denied';
    console.log(`✅ /pay-confirm → paymentId=${paymentId} status=${payment.status}`);

    return res.json({ success: true });
  } catch (err) {
    console.error('🔥 /pay-confirm error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/payment-status', (req, res) => {
  const { paymentId } = req.body || {};
  if (!paymentId) {
    return res.status(400).json({ success: false, error: 'paymentId required' });
  }

  const p = cardPayments[paymentId];
  if (!p) {
    return res.status(404).json({ success: false, error: 'payment not found' });
  }

  return res.json({
    success: true,
    status: p.status,           // "pending" | "approved" | "denied"
    approved: !!p.approved
  });
});


app.post('/payment-confirm', (req, res) => {
  const { paymentId, approved } = req.body || {};

  if (!paymentId || typeof approved !== 'boolean') {
    return res.status(400).json({
      success: false,
      error: 'paymentId and approved (boolean) required'
    });
  }

  const p = cardPayments[paymentId];
  if (!p) {
    return res.status(404).json({ success: false, error: 'payment not found' });
  }

  p.status = approved ? 'approved' : 'denied';
  p.approved = approved;

  console.log(`💳 payment-confirm: ${paymentId} → ${approved ? 'APPROVED' : 'DENIED'}`);

  return res.json({ success: true });
});

// at top of file with your other in-memory maps:
const cardPaymentSessions = Object.create(null);
const cardOwners = Object.create(null);  // cardPubKeyPem -> normalizedEmail




app.post('/card-pay-start', (req, res) => {
  try {
    const { amountCents, description, merchantId, cardPubKeyPem, signatureB64, challenge } = req.body || {};

    // Basic validation
    if (!amountCents || !description || !merchantId || !cardPubKeyPem || !signatureB64 || !challenge) {
      return res.status(400).json({
        success: false,
        error: 'amountCents, description, merchantId, cardPubKeyPem, signatureB64, challenge required'
      });
    }

    const ownerEmail = cardOwners[cardPubKeyPem];
    if (!ownerEmail) {
      return res.status(404).json({ success: false, error: 'card not registered' });
    }

    const emailNorm = normalizeEmail(ownerEmail);
    const deviceToken = userTokens[emailNorm];
    if (!deviceToken) {
      return res.status(404).json({ success: false, error: 'no device token for card owner' });
    }

    // Create a payment session
    const sessionId = crypto.randomUUID();
    cardPaymentSessions[sessionId] = {
      sessionId,
      amountCents,
      description,
      merchantId,
      cardPubKeyPem,
      challenge,
      status: 'pending',
      createdAt: Date.now()
    };

    // Send push to card owner (same FCM wiring you already use)
    const message = {
      token: deviceToken,
      notification: {
        title: 'Payment Approval',
        body: `${description} - $${(amountCents / 100).toFixed(2)}`
      },
      data: {
        type: 'CARD_PAYMENT',
        sessionId,
        amountCents: String(amountCents),
        description,
        merchantId
      },
      android: { priority: 'high' },
      apns: {
        payload: {
          aps: {
            category: 'LOGIN_REQUEST', // reuse existing category if you want same buttons
            sound: 'default'
          }
        }
      }
    };

    admin
      .messaging()
      .send(message)
      .then((id) => {
        console.log(`📲 Sent card payment push to ${emailNorm} (session ${sessionId}, msgId=${id})`);
        res.json({
          success: true,
          sessionId
        });
      })
      .catch((err) => {
        console.error('❌ FCM error for card payment:', err);
        res.status(500).json({ success: false, error: 'push failed' });
      });
  } catch (err) {
    console.error('❌ /card-pay-start error:', err);
    res.status(500).json({ success: false, error: 'internal error' });
  }
});

app.post('/card-pay-complete', (req, res) => {
  try {
    const { sessionId, approved } = req.body || {};
    if (!sessionId || typeof approved !== 'boolean') {
      return res.status(400).json({ success: false, error: 'sessionId, approved required' });
    }

    const sess = cardPaymentSessions[sessionId];
    if (!sess) {
      return res.status(404).json({ success: false, error: 'unknown session' });
    }

    sess.status = approved ? 'approved' : 'denied';
    sess.completedAt = Date.now();

    console.log(`💳 Payment session ${sessionId} -> ${sess.status}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ /card-pay-complete error:', err);
    res.status(500).json({ success: false, error: 'internal error' });
  }
});

app.get('/card-pay-status', (req, res) => {
  try {
    const sessionId = req.query.sessionId;
    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId required' });
    }

    const sess = cardPaymentSessions[sessionId];
    if (!sess) {
      return res.status(404).json({ success: false, error: 'unknown session' });
    }

    res.json({
      success: true,
      status: sess.status
    });
  } catch (err) {
    console.error('❌ /card-pay-status error:', err);
    res.status(500).json({ success: false, error: 'internal error' });
  }
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

  // 1x1 gif
  const buf = Buffer.from('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==', 'base64');
  res.setHeader('Content-Type', 'image/gif');
  res.end(buf);
});

// ---------------------- Cleanup ----------------------
setInterval(() => {

  const now = Date.now();

  for (const [k, v] of Object.entries(pendingDecrypts)) {
    if ((v.expiresAt && now > v.expiresAt) || (now - (v.createdAt || 0) > 10 * 60_000)) delete pendingDecrypts[k];
  }

  for (const [k, v] of Object.entries(pendingLogins)) {
    if (now - (v.timestamp || 0) > 10 * 60_000) delete pendingLogins[k];
  }

  // Cleanup expired login challenges
  for (const [nonce, rec] of Object.entries(loginChallenges)) {
    if (!rec) {
      delete loginChallenges[nonce];
      continue;
    }
    const exp = rec.challengeExpiresAt || 0;
    if (!exp || now > exp) {
      // ⏳ Challenge expired, remove it
      delete loginChallenges[nonce];
    }
  }

  for (const [email, exp] of Object.entries(sessionApprovals)) {
    if (Date.now() > exp) delete sessionApprovals[email];
  }

  // Cleanup stale card challenges
  for (const [email, rec] of Object.entries(pendingCardChallenges)) {
    if (!rec || now > (rec.expiresAt || 0)) delete pendingCardChallenges[email];
  }

  // Cleanup stale calls (e.g. > 15 minutes old)
  const CALL_TTL = 15 * 60_000;
  for (const [id, c] of Object.entries(callsById)) {
    const t = c.lastUpdate || c.createdAt || 0;
    if (!t || now - t > CALL_TTL) {
      console.log(`🧹 Cleaning stale call ${id}`);
      delete callsById[id];
    }
  }

}, 60_000);


// ---------------------- Mint endpoints (EIP-712) ----------------------
app.post('/mint-nft', async (req, res) => {
  try {
    if (!personaAuth) return res.status(503).json({ success: false, error: 'Contract not configured' });

    const emailNorm = normalizeEmail(req.body?.email || '');
    const deviceFpr = String(req.body?.deviceFpr || '');
    const to = String(req.body?.to || '');
    if (!emailNorm || !deviceFpr || !to) return res.status(400).json({ success: false, error: 'email, deviceFpr, to required' });
    if (!isAddress(to)) return res.status(400).json({ success: false, error: 'Invalid recipient address' });

    const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN || null;
    if (!token) return res.status(403).json({ success: false, error: 'No registered device token for this email' });

    const userIdHash = commitUserId(emailNorm);
    const deviceHash = commitDevice(deviceFpr);

    const domain = { name: "PersonaAuth", version: "1", chainId: 137, verifyingContract: CONTRACT_ADDRESS };
    const types  = { MintAuth: [
      { name: "to",          type: "address" },
      { name: "userIdHash",  type: "bytes32" },
      { name: "deviceHash",  type: "bytes32" },
      { name: "salt",        type: "bytes32" },
      { name: "deadline",    type: "uint256" },
    ]};

    const salt     = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const deadline = Math.floor(Date.now() / 1000) + 10 * 60;

    const minter = new ethers.Wallet(MINTER_PRIVATE_KEY);
    const signature = await minter._signTypedData(domain, types, { to, userIdHash, deviceHash, salt, deadline });

    const fee = await getAggressiveFees(provider);
    const tx = await personaAuth.mintWithSig(to, userIdHash, deviceHash, salt, deadline, signature, {
      maxFeePerGas:         fee.maxFeePerGas,
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
    });
    console.log(`⛓️  mintWithSig → ${tx.hash}`);

    if (typeof tx.wait === 'function') await tx.wait(1);
    else await provider.waitForTransaction(tx.hash, 1);

    let tokenId = null;
    try {
      const tid = await personaAuth.tokenOf(to);
      tokenId = tid?.toString?.() || String(tid);
    } catch {}

    return res.json({ success: true, txHash: tx.hash, confirmed: true, tokenId });
  } catch (err) {
    console.error('❌ /mint-nft error:', err);
    const msg = (err?.reason || err?.error?.message || String(err)).toLowerCase();
    if (msg.includes('identity already issued')) {
      return res.status(200).json({ success: true, minted: false, alreadyRegistered: true });
    }
    return res.status(500).json({ success: false, error: 'Mint failed', details: String(err.message || err) });
  }
});

// Back-compat alias
app.post('/mint-persona', async (req, res) => {
  try {
    if (!personaAuth) return res.status(503).json({ success: false, error: 'Contract not configured' });

    const emailNorm = normalizeEmail(req.body?.email || '');
    const deviceFpr = String(req.body?.deviceFpr || '');
    const to = String(req.body?.to || '');
    if (!emailNorm || !deviceFpr || !to) return res.status(400).json({ success: false, error: 'email, deviceFpr, to required' });
    if (!isAddress(to)) return res.status(400).json({ success: false, error: 'Invalid recipient address' });

    const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN || null;
    if (!token) return res.status(403).json({ success: false, error: 'No registered device token for this email' });

    const userIdHash = commitUserId(emailNorm);
    const deviceHash = commitDevice(deviceFpr);

    const domain = { name: "PersonaAuth", version: "1", chainId: 137, verifyingContract: CONTRACT_ADDRESS };
    const types  = { MintAuth: [
      { name: "to",          type: "address" },
      { name: "userIdHash",  type: "bytes32" },
      { name: "deviceHash",  type: "bytes32" },
      { name: "salt",        type: "bytes32" },
      { name: "deadline",    type: "uint256" },
    ]};

    const salt     = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const deadline = Math.floor(Date.now() / 1000) + 10 * 60;

    const minter = new ethers.Wallet(MINTER_PRIVATE_KEY);
    const signature = await minter._signTypedData(domain, types, { to, userIdHash, deviceHash, salt, deadline });

    const fee = await getAggressiveFees(provider);
    const tx = await personaAuth.mintWithSig(to, userIdHash, deviceHash, salt, deadline, signature, {
      maxFeePerGas:         fee.maxFeePerGas,
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
    });
    console.log(`⛓️  mintWithSig → ${tx.hash}`);

    if (typeof tx.wait === 'function') await tx.wait(1);
    else await provider.waitForTransaction(tx.hash, 1);

    let tokenId = null;
    try {
      const tid = await personaAuth.tokenOf(to);
      tokenId = tid?.toString?.() || String(tid);
    } catch {}

    return res.json({ success: true, txHash: tx.hash, confirmed: true, tokenId });
  } catch (err) {
    console.error('❌ /mint-persona error:', err);
    const msg = (err?.reason || err?.error?.message || String(err)).toLowerCase();
    if (msg.includes('identity already issued')) {
      return res.status(200).json({ success: true, minted: false, alreadyRegistered: true });
    }
    return res.status(500).json({ success: false, error: String(err.message || err) });
  }
});

// Read-only: does this address own a PersonaAuth NFT?
app.get('/has-nft/:address', async (req, res) => {
  try {
    if (!personaAuth) return res.status(503).json({ success: false, error: 'Contract not configured' });
    const address = String(req.params.address || '').trim();
    if (!ethers.utils.isAddress(address)) return res.status(400).json({ success: false, error: 'Bad address' });

    const bal = await personaAuth.balanceOf(address);
    const has = bal.gt ? bal.gt(0) : (BigInt(bal) > 0n);

    let tokenIds = [];
    if (has) {
      try {
        const tid = await personaAuth.tokenOf(address);
        const s = tid?.toString?.() || String(tid);
        if (s && s !== "0") tokenIds.push(s);
      } catch {}
    }

    return res.json({ success: true, hasNFT: has, balance: bal.toString(), tokenIds });
  } catch (err) {
    console.error('❌ /has-nft error:', err);
    return res.status(500).json({ success: false, error: String(err.message || err) });
  }
});

// --- READ: does this address own at least 1 PNA? ---
app.get('/nft-owned', async (req, res) => {
  try {
    if (!provider || !CONTRACT_ADDRESS) return res.status(503).json({ success: false, error: 'Read contract not configured' });
    const addr = String(req.query.address || '').trim();
    if (!addr || !ethers.utils.isAddress(addr)) return res.status(400).json({ success: false, error: 'Valid address required' });

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

// --- READ+VERIFY: strict match on email/deviceFpr (commitments) ---
// app.post('/nft-owned-verify', async (req, res) => {
//   try {
//     if (!provider || !CONTRACT_ADDRESS) return res.status(503).json({ success: false, error: 'Read contract not configured' });
//     const address = String(req.body?.address || '').trim();
//     const email   = req.body?.email || null;
//     const deviceFpr = req.body?.deviceFpr || null;
//     if (!address || !ethers.utils.isAddress(address)) return res.status(400).json({ success: false, error: 'Valid address required' });

//     const readAbi = [
//       "function balanceOf(address owner) view returns (uint256)",
//       "function tokenOf(address user) view returns (uint256)",
//       "function identityOf(uint256 tokenId) view returns (bytes32 userIdHash, bytes32 deviceHash, bool valid)"
//     ];
//     const personaRead = new ethers.Contract(CONTRACT_ADDRESS, readAbi, provider);

//     const bal = await personaRead.balanceOf(address);
//     const owned = bal.gt ? bal.gt(0) : (BigInt(bal) > 0n);
//     if (!owned) return res.json({ success: true, owned: false, matched: false });

//     const tokenId = await personaRead.tokenOf(address);
//     const tidStr = tokenId?.toString?.() || String(tokenId || "0");
//     if (tidStr === "0") return res.json({ success: true, owned: true, matched: false });

//     const id = await personaRead.identityOf(tokenId);
//     const onUser   = id.userIdHash || id[0];
//     const onDevice = id.deviceHash || id[1];

//     const emailOk  = email  ? (commitUserId(email).toLowerCase()   === String(onUser).toLowerCase())   : true;
//     const deviceOk = deviceFpr ? (commitDevice(deviceFpr).toLowerCase() === String(onDevice).toLowerCase()) : true;

//     return res.json({ success: true, owned: true, matched: !!(emailOk && deviceOk) });
//   } catch (e) {
//     console.error('❌ /nft-owned-verify:', e);
//     return res.status(500).json({ success: false, error: 'verify failed' });
//   }
// });

// --- READ+VERIFY: strict match on email/deviceFpr (commitments) ---
app.post('/nft-owned-verify', async (req, res) => {
  try {
    if (!provider || !CONTRACT_ADDRESS) {
      return res.status(503).json({ success: false, error: 'Read contract not configured' });
    }

    const address   = String(req.body?.address || '').trim();
    const emailRaw  = req.body?.email || null;
    const deviceFpr = req.body?.deviceFpr || null;

    if (!address || !ethers.utils.isAddress(address)) {
      return res.status(400).json({ success: false, error: 'Valid address required' });
    }

    const emailNorm = emailRaw ? normalizeEmail(emailRaw) : '';

    const result = await verifyPersonaBinding({ emailNorm, address, deviceFpr });

    // Map helper result → legacy response shape
    if (!result.ok) {
      if (result.reason === 'no_nft' || result.reason === 'no_token_mapping') {
        // Address has no persona NFT
        return res.json({ success: true, owned: false, matched: false });
      }
      if (result.reason === 'mismatch') {
        // NFT exists but does not match email/deviceFpr
        return res.json({ success: true, owned: true, matched: false });
      }
      // Generic error
      console.error('❌ /nft-owned-verify helper error:', result);
      return res.status(500).json({ success: false, error: 'verify failed' });
    }

    // All good: NFT exists and matches bindings
    return res.json({
      success: true,
      owned: true,
      matched: true,
      tokenId: result.tokenId || null
    });
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
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) return res.status(400).json({ success: false, error: 'bad hash' });
    const r = await provider.getTransactionReceipt(hash);
    if (!r) return res.json({ success: true, found: false });
    return res.json({ success: true, found: true, status: typeof r.status === 'number' ? r.status : null, blockNumber: r.blockNumber ?? null });
  } catch (e) {
    console.error('❌ /tx-receipt:', e);
    return res.status(500).json({ success: false, error: 'lookup failed' });
  }
});

// Runtime/debug
app.get('/runtime', async (req, res) => {
  try {
    const net = provider ? await provider.getNetwork() : null;
    let minterAddr = null;
    try { if (MINTER_PRIVATE_KEY) minterAddr = new ethers.Wallet(MINTER_PRIVATE_KEY).address; } catch {}
    return res.json({
      configured: !!personaAuth,
      contractAddress_env: CONTRACT_ADDRESS || null,
      personaAuth_connected: personaAuth?.address || null,
      relayerAddress: (relayerSigner && relayerSigner.address) || null,
      minterAddress: minterAddr,
      network: net ? { chainId: String(net.chainId), name: net.name } : null
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------------------- Start ----------------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`NFT Login server running on port ${PORT}`);
});
