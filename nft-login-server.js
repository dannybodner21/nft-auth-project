// nft-login-server.js
require('dotenv').config();
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');


process.on('uncaughtException', err => {
  console.error("🔥 Uncaught Exception:", err);
});
process.on('unhandledRejection', err => {
  console.error("🔥 Unhandled Promise Rejection:", err);
});


// In-memory mapping from messagingId → set of FCM tokens
const callDeviceMap = new Map();

function addDeviceTokenForMessagingId(messagingId, token) {
  if (!messagingId || !token) return;
  const cleaned = String(token).trim();
  if (!cleaned) return;

  const set = callDeviceMap.get(messagingId) || new Set();
  set.add(cleaned);
  callDeviceMap.set(messagingId, set);
  console.log("🔄 callDeviceMap updated for", messagingId, "tokens:", set.size);
}

async function getDeviceTokensForMessagingId(messagingId) {
  const set = callDeviceMap.get(messagingId);
  if (!set) {
    console.warn("ℹ️ No FCM tokens for messagingId", messagingId);
    return [];
  }
  return Array.from(set);
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

// E2EE messaging: in-memory, deliver-once queues keyed by recipient messaging ID
// messagesByRecipient[recipientMessagingId] = [ { id, ts, senderMessagingId, ciphertextB64 } ]
let messagesByRecipient = {};

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

function keyInfoFromKeyObject(keyObj) {
  const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
  const sha256  = crypto.createHash('sha256').update(spkiDer).digest('base64');
  const details = keyObj.asymmetricKeyDetails || {};
  return { alg: keyObj.asymmetricKeyType, modulusBits: details.modulusLength || null, spkiSha256: sha256 };
}


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

// Register/bind a card to an email with proof-of-possession.
// Body: { email, spkiPem, challenge, signatureB64, scheme? }
// - spkiPem: the card's **public key PEM** (-----BEGIN PUBLIC KEY-----...)
// - challenge/signatureB64: must be the exact challenge from /card-challenge and a signature from THIS key
app.post('/card-register', (req, res) => {
  try {
    const emailNorm    = normalizeEmail(req.body?.email || '');
    const spkiPem      = String(req.body?.spkiPem || '').trim();
    const challenge    = String(req.body?.challenge || '');
    const signatureB64 = String(req.body?.signatureB64 || '');
    const scheme       = String(req.body?.scheme || 'PKCS1V15');

    if (!emailNorm || !spkiPem || !challenge || !signatureB64) {
      return res.status(400).json({ success: false, error: 'email, spkiPem, challenge, signatureB64 required' });
    }

    // Must be a valid pending challenge for this email
    const rec = pendingCardChallenges[emailNorm];
    if (!rec || rec.challenge !== challenge || Date.now() > rec.expiresAt) {
      return res.status(400).json({ success: false, error: 'unknown or expired challenge' });
    }

    // Build key object from PEM and verify proof-of-possession
    let keyObj;
    try { keyObj = crypto.createPublicKey(spkiPem); }
    catch (e) { return res.status(400).json({ success: false, error: 'bad spkiPem' }); }

    const ok = verifyCardSignature({ publicKey: keyObj, challenge, signatureB64, scheme });
    if (!ok) return res.status(400).json({ success: false, error: 'proof-of-possession failed' });

    const info = keyInfoFromKeyObject(keyObj);
    cardKeys[emailNorm] = { keyObj, spkiSha256: info.spkiSha256, pem: spkiPem };

    // One-time use
    delete pendingCardChallenges[emailNorm];

    // Start a live session (same TTL as extension)
    const TTL_MS = 2 * 60 * 60 * 1000;
    sessionApprovals[emailNorm] = Date.now() + TTL_MS;

    return res.json({ success: true, bound: true, spkiSha256: info.spkiSha256, sessionExpiresAt: sessionApprovals[emailNorm] });
  } catch (e) {
    console.error('❌ /card-register:', e);
    return res.status(500).json({ success: false, error: 'register failed' });
  }
});

// DROP-IN REPLACEMENT: /card-verify now prefers the **per-user** key if present; falls back to global env key for legacy.
app.post('/card-verify', (req, res) => {

  console.log('📥 RAW req.body.challenge:', req.body.challenge);
  console.log('📥 Challenge length:', String(req.body.challenge || '').length);

  try {
    const rawEmail     = String(req.body?.email || '');
    const emailNorm    = normalizeEmail(rawEmail);
    const challenge = String(req.body?.challenge || '');
    console.log('🔍 After String conversion, challenge length:', challenge.length);
    console.log('🔍 After String conversion, full challenge:', challenge);
    const signatureB64 = String(req.body?.signatureB64 || '');
    const scheme       = String(req.body?.scheme || 'PKCS1V15');

    console.log('🔐 /card-verify request:', { emailNorm, challenge: challenge.substring(0, 50), sigLen: signatureB64.length });

    if (!emailNorm || !challenge || !signatureB64) {
      console.log('❌ Missing fields');
      return res.status(400).json({ success: false, error: 'email, challenge, signatureB64 required' });
    }
    if (!challenge.startsWith('nftvault:card-auth|')) {
      console.log('❌ Bad challenge prefix');
      return res.status(400).json({ success: false, error: 'bad challenge prefix' });
    }

    // Must match issued challenge & be fresh
    const rec = pendingCardChallenges[emailNorm];
    if (!rec) {
      console.log('❌ No pending challenge for', emailNorm);
      return res.status(400).json({ success: false, error: 'unknown or expired challenge' });
    }
    if (rec.challenge !== challenge) {
      console.log('❌ Challenge mismatch');
      return res.status(400).json({ success: false, error: 'unknown or expired challenge' });
    }
    if (Date.now() > rec.expiresAt) {
      console.log('❌ Challenge expired');
      return res.status(400).json({ success: false, error: 'unknown or expired challenge' });
    }

    // Parse & check email + ts
    const fields = Object.fromEntries(
      challenge.split('|').slice(1).map(kv => {
        const i = kv.indexOf('=');
        return i === -1 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)];
      })
    );
    if (normalizeEmail(fields.email || '') !== emailNorm) {
      return res.status(400).json({ success: false, error: 'email mismatch' });
    }
    const ts = Number(fields.ts);
    if (!Number.isFinite(ts)) return res.status(400).json({ success: false, error: 'bad ts' });
    const now = Math.floor(Date.now() / 1000);
    const MAX_SKEW = 5 * 60;
    if (Math.abs(now - ts) > MAX_SKEW) {
      return res.status(400).json({ success: false, error: 'stale/future challenge', now, ts });
    }

    // Pick the right key: per-user bound key first; else legacy env key
    let verifyKey = null;
    if (cardKeys[emailNorm]?.keyObj) {
      verifyKey = cardKeys[emailNorm].keyObj;
    } else if (cardAuthKey) {
      verifyKey = cardAuthKey;
    } else {
      return res.status(503).json({ success: false, error: 'no verification key available' });
    }

    console.log('🔍 RIGHT BEFORE verifyCardSignature call, challenge:', challenge);
    console.log('🔍 RIGHT BEFORE verifyCardSignature call, challenge.length:', challenge.length);

    const ok = verifyCardSignature({ publicKey: verifyKey, challenge, signatureB64, scheme });
    
    console.log('🔐 Signature verification result:', ok);

    if (!ok) return res.status(400).json({ success: false, verified: false });

    delete pendingCardChallenges[emailNorm];

    // Start/refresh live session (2h)
    const TTL_MS = 2 * 60 * 60 * 1000;
    sessionApprovals[emailNorm] = Date.now() + TTL_MS;
    console.log(`🔓 Card session approved for ${emailNorm} until ${new Date(sessionApprovals[emailNorm]).toISOString()}`);

    return res.json({ success: true, verified: true, email: emailNorm, ts, nonce: fields.nonce || null, sessionExpiresAt: sessionApprovals[emailNorm] });
  } catch (e) {
    console.error('❌ /card-verify error:', e);
    return res.status(500).json({ success: false, error: 'verify failed' });
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
  userTokens[emailNorm] = deviceToken;

  // If the client passes a messagingId (Curve25519 pubkey), map it to this device token.
  if (messagingId.length > 0) {
    messagingRouting[messagingId] = {
      email: emailNorm,
      deviceToken
    };
    console.log(`💬 Registered messagingId for ${emailNorm} (len=${messagingId.length})`);
  }

  console.log(`💾 Saved token for ${emailNorm}`);
  res.json({ success: true });
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
  const emailNorm = normalizeEmail(req.body?.email || '');
  const websiteDomain = req.body?.websiteDomain || null;
  if (!emailNorm) return res.status(400).json({ error: 'Email required' });

  const requestId = uuidv4();
  pendingLogins[requestId] = {
    email: emailNorm,
    websiteDomain,
    status: 'pending',
    timestamp: Date.now(),
    devicePublicKeyJwk: null,
    extSession: null
  };

  const user = await db.getUserByEmail(emailNorm);
  const deviceToken = user?.deviceToken;
  if (!deviceToken) return res.status(404).json({ error: 'No device token registered' });

  const message = {
    token: deviceToken,
    notification: { title: 'NFT Auth Request', body: 'Approve or deny request' },
    data: { type: 'login_request', email: emailNorm, requestId, ...(websiteDomain ? { websiteDomain } : {}) },
    android: { priority: 'high' },
    apns: { payload: { aps: { sound: 'default', category: 'LOGIN_REQUEST' } } }
  };

  try {
    await admin.messaging().send(message);
    console.log(`✅ Push sent to ${emailNorm} (${requestId})`);
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
  res.json({ success: true, status: r.status, devicePublicKeyJwk: r.devicePublicKeyJwk || null, extSession: r.extSession || null });
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
app.post('/card-challenge', (req, res) => {
  try {
    if (!cardAuthKey) return res.status(503).json({ success: false, error: 'card key not loaded' });
    const emailNorm = normalizeEmail(req.body?.email || '');
    if (!emailNorm || !emailNorm.includes('@')) return res.status(400).json({ success: false, error: 'valid email required' });

    const now = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex');
    const challenge = `nftvault:card-auth|email=${emailNorm}|ts=${now}|nonce=${nonce}`;
    const ttlSec = 120;

    pendingCardChallenges[emailNorm] = { challenge, expiresAt: Date.now() + ttlSec * 1000 };

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
  const emailNorm = normalizeEmail(req.body?.email || '');
  const deviceId = String(req.body?.deviceId || '');
  const credentials = req.body?.credentials;
  if (!emailNorm || !deviceId || !Array.isArray(credentials)) {
    return res.status(400).json({ success: false, error: 'Missing or invalid fields' });
    }
  const hasLiveSession = sessionApprovals[emailNorm] && Date.now() < sessionApprovals[emailNorm];
  if (!verifiedEmails[emailNorm] && !hasLiveSession) {
    return res.status(403).json({ success: false, error: 'Session locked or expired' });
  }
  const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN;
  if (!token) return res.status(403).json({ success: false, error: 'Unregistered device' });

  userCredentials[emailNorm] = credentials;
  console.log(`💾 Stored ${credentials.length} encrypted credentials for ${emailNorm}`);
  return res.json({ success: true });
});

app.post('/get-credentials', (req, res) => {
  const emailNorm = normalizeEmail(req.body?.email || '');
  if (!emailNorm) return res.status(400).json({ error: 'Missing email' });

  const token = userTokens[emailNorm] || process.env.TEST_PUSH_TOKEN || null;
  if (!token) return res.status(403).json({ error: 'No registered device token' });

  const creds = userCredentials[emailNorm] || [];
  console.log(`📤 Returned ${creds.length} credentials for ${emailNorm}`);
  res.json({ success: true, credentials: creds });
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
const messagingTokensById = Object.create(null);

// Generic helper: fan-out a push to all FCM tokens registered for a messagingId
function pushToMessagingId(messagingId, { notification, data }) {
  const tokenSet = messagingTokensById[messagingId];
  if (!tokenSet || tokenSet.size === 0) {
    console.log(`ℹ️ No FCM tokens for messagingId ${messagingId.slice(0, 12)}…`);
    return;
  }

  const tokens = Array.from(tokenSet);
  console.log(`📡 pushToMessagingId ${messagingId.slice(0, 12)}… → ${tokens.length} tokens`);

  tokens.forEach((token) => {
    const msg = {
      token,
      android: { priority: 'high' },
      apns: { payload: { aps: { contentAvailable: 1 } } },
      ...(notification ? { notification } : {}),
      data: {
        // NEVER send undefined – only strings in data
        ...(data || {})
      }
    };

    admin
      .messaging()
      .send(msg)
      .then((id) => {
        console.log(`✅ FCM push → ${token.slice(0, 12)}… (${id})`);
      })
      .catch((err) => {
        console.warn('⚠️ FCM push failed:', err.message || err);
      });
  });
}


// ---------------------- E2EE Messaging relay (no plaintext stored) ----------------------

// POST /messages/send
// Body: { senderMessagingId, recipientMessagingId, messageId, timestamp, ciphertextB64 }
app.post('/messages/send', (req, res) => {
  try {
    const senderMessagingId    = String(req.body?.senderMessagingId || '').trim();
    const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
    const messageId            = String(req.body?.messageId || '').trim();
    const tsRaw                = req.body?.timestamp;
    const ciphertextB64        = String(req.body?.ciphertextB64 || '').trim();

    if (!senderMessagingId || !recipientMessagingId || !messageId || !ciphertextB64) {
      return res.status(400).json({ success: false, error: 'Missing fields' });
    }

    // Basic length sanity checks to avoid garbage
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
      // NO plaintext, NO alias, NO fromMe flag – clients infer everything
    };

    if (!messagesByRecipient[recipientMessagingId]) {
      messagesByRecipient[recipientMessagingId] = [];
    }

    // Append, but cap queue size per recipient to avoid unbounded growth
    messagesByRecipient[recipientMessagingId].push(msg);
    if (messagesByRecipient[recipientMessagingId].length > 200) {
      messagesByRecipient[recipientMessagingId].shift(); // drop oldest
    }

    console.log(
      `📨 Stored message for recipient ${recipientMessagingId.slice(
        0,
        12
      )}… (queue size=${messagesByRecipient[recipientMessagingId].length})`
    );

    // ==== NEW: fire-and-forget push notification for chat ====
    const tokenSet = messagingTokensById[recipientMessagingId];
    const count = tokenSet ? tokenSet.size : 0;
    console.log(
      `🔔 Chat push lookup for ${recipientMessagingId.slice(0, 12)}… tokens=${count}`
    );

    if (tokenSet && tokenSet.size > 0) {
      const tokens = Array.from(tokenSet);

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

      tokens.forEach((token) => {
        admin
          .messaging()
          .send({ token, ...baseMsg })
          .then((id) => {
            console.log(
              `📨 FCM chat push sent to ${token.slice(0, 12)}…: ${id}`
            );
          })
          .catch((err) => {
            console.warn(
              '⚠️ FCM chat push failed:',
              err.message || err
            );
          });
      });
    } else {
      console.log(
        `ℹ️ No registered messaging tokens for ${recipientMessagingId.slice(
          0,
          12
        )}…`
      );
    }
    // =========================================================

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ /messages/send crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});


// POST /messages/sync
// Body: { recipientMessagingId }
// Returns and *clears* all queued messages for that recipient
app.post('/messages/sync', (req, res) => {
  const recipientMessagingId = String(req.body?.recipientMessagingId || '').trim();
  if (!recipientMessagingId) {
    return res.status(400).json({ success: false, error: 'recipientMessagingId required' });
  }

  const list = messagesByRecipient[recipientMessagingId] || [];
  // Deliver-once: wipe after read
  delete messagesByRecipient[recipientMessagingId];

  // We do NOT log message contents
  console.log(`📤 Sync for recipient ${recipientMessagingId.slice(0, 12)}… returned=${list.length}`);

  res.setHeader('Cache-Control', 'no-store');
  return res.json({ success: true, messages: list });
});

// POST /messaging/register-device
// Body: { messagingId, deviceToken }
app.post('/messaging/register-device', (req, res) => {
  try {
    const messagingIdRaw = req.body && req.body.messagingId;
    const deviceTokenRaw = req.body && req.body.deviceToken;

    const messagingId = String(messagingIdRaw || '').trim();
    const deviceToken = String(deviceTokenRaw || '').trim();

    if (!messagingId || !deviceToken) {
      console.warn('⚠️ /messaging/register-device missing fields', req.body);
      return res
        .status(400)
        .json({ success: false, error: 'messagingId and deviceToken required' });
    }

    if (!messagingTokensById[messagingId]) {
      messagingTokensById[messagingId] = new Set();
    }
    messagingTokensById[messagingId].add(deviceToken);

    console.log(
      `💾 /messaging/register-device stored token for ${messagingId.slice(
        0,
        12
      )}… (count=${messagingTokensById[messagingId].size})`
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ /messaging/register-device crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});


// ---------------------- Call signaling (WebRTC-style) ----------------------

// POST /calls/offer
// Body: { callId?, fromMessagingId, toMessagingId, sdpOffer, displayName? }
app.post('/calls/offer', (req, res) => {
  try {
    const fromMessagingId = String(req.body?.fromMessagingId || '').trim();
    const toMessagingId   = String(req.body?.toMessagingId || '').trim();
    let   callId          = String(req.body?.callId || '').trim();
    const sdpOffer        = String(req.body?.sdpOffer || '').trim();
    const displayName     = String(req.body?.displayName || '').trim() || null;

    if (!fromMessagingId || !toMessagingId || !sdpOffer) {
      return res.status(400).json({ success: false, error: 'fromMessagingId, toMessagingId, sdpOffer required' });
    }

    if (!callId) {
      callId = uuidv4();
    }

    const now = Date.now();
    callsById[callId] = {
      id: callId,
      fromMessagingId,
      toMessagingId,
      status: 'ringing',
      sdpOffer,
      createdAt: now,
      lastUpdate: now
    };

    console.log(`📞 /calls/offer ${callId} from ${fromMessagingId.slice(0, 12)}… → ${toMessagingId.slice(0, 12)}…`);

    // Notify callee
    pushToMessagingId(toMessagingId, {
      notification: {
        title: displayName ? `Call from ${displayName}` : 'Incoming call',
        body: 'Tap to answer'
      },
      data: {
        type: 'call_offer',
        callId,
        fromMessagingId,
        toMessagingId,
        sdpOffer
      }
    });

    return res.json({ success: true, callId });
  } catch (err) {
    console.error('❌ /calls/offer crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});


// iOS sends POST /calls/answer with:
// {
//   callId: "uuid",
//   fromMessagingId: "callee pubkey",
//   toMessagingId: "caller pubkey",
//   sdpAnswer: "…"
// }
app.post("/calls/answer", async (req, res) => {
  try {
    const {
      callId,
      fromMessagingId,
      toMessagingId,
      sdpAnswer
    } = req.body || {};

    if (!callId || !fromMessagingId || !toMessagingId || !sdpAnswer) {
      console.error("❌ /calls/answer missing fields:", req.body);
      return res.status(400).json({ error: "missing required fields" });
    }

    // We are sending the answer back to the ORIGINAL caller,
    // so we look up tokens for `toMessagingId` (the caller).
    const tokens = await getDeviceTokensForMessagingId(toMessagingId);
    if (!tokens || tokens.length === 0) {
      console.warn("⚠️ /calls/answer: no device tokens for", toMessagingId);
      return res.status(404).json({ error: "no devices for caller" });
    }

    const dataPayload = {
      type: "call_answer",
      callId: String(callId),
      // optional, might be useful on caller side
      fromMessagingId: String(fromMessagingId),
      sdpAnswer: String(sdpAnswer)
    };

    const message = {
      tokens,
      data: dataPayload
    };

    const resp = await admin.messaging().sendMulticast(message);
    console.log("✅ /calls/answer FCM sent:", resp.successCount, "success,", resp.failureCount, "failure");

    return res.json({ ok: true, fcm: resp });
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

    const tokens = await getDeviceTokensForMessagingId(toMessagingId);
    if (!tokens || tokens.length === 0) {
      console.warn("⚠️ /calls/ice: no device tokens for", toMessagingId);
      return res.status(404).json({ error: "no devices for peer" });
    }

    const dataPayload = {
      type: "call_ice",
      callId: String(callId),
      sdp: String(sdp),
      // normalize to string so iOS can parse flexibly
      sdpMLineIndex: String(sdpMLineIndex),
      sdpMid: sdpMid != null ? String(sdpMid) : ""
    };

    const message = {
      tokens,
      data: dataPayload
    };

    const resp = await admin.messaging().sendMulticast(message);
    console.log("✅ /calls/ice FCM sent:", resp.successCount, "success,", resp.failureCount, "failure");

    return res.json({ ok: true, fcm: resp });
  } catch (err) {
    console.error("🔥 /calls/ice error:", err);
    return res.status(500).json({ error: "internal_error" });
  }
});


// POST /calls/candidate
// Body: { callId, fromMessagingId, toMessagingId, candidateJson }
// - candidateJson is a stringified ICE candidate (client just forwards it).
app.post('/calls/candidate', (req, res) => {
  try {
    const callId          = String(req.body?.callId || '').trim();
    const fromMessagingId = String(req.body?.fromMessagingId || '').trim();
    const toMessagingId   = String(req.body?.toMessagingId || '').trim();
    const candidateJson   = String(req.body?.candidateJson || '').trim();

    if (!callId || !fromMessagingId || !toMessagingId || !candidateJson) {
      return res.status(400).json({ success: false, error: 'callId, fromMessagingId, toMessagingId, candidateJson required' });
    }

    const call = callsById[callId];
    if (!call) {
      console.warn('⚠️ /calls/candidate unknown callId', callId);
      // still accept for stateless relaying
    } else {
      call.lastUpdate = Date.now();
    }

    // Relay ICE candidate to the peer
    pushToMessagingId(toMessagingId, {
      notification: null,
      data: {
        type: 'call_candidate',
        callId,
        fromMessagingId,
        toMessagingId,
        candidateJson
      }
    });

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ /calls/candidate crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});

// POST /calls/hangup
// Body: { callId, fromMessagingId, toMessagingId, reason? }
app.post('/calls/hangup', (req, res) => {
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
      call.status    = 'ended';
      call.endedAt   = Date.now();
      call.lastUpdate = call.endedAt;
    }

    console.log(`📵 /calls/hangup ${callId} from ${fromMessagingId.slice(0, 12)}… reason=${reason}`);

    // Notify peer
    pushToMessagingId(toMessagingId, {
      notification: null,
      data: {
        type: 'call_hangup',
        callId,
        fromMessagingId,
        toMessagingId,
        reason
      }
    });

    // We can drop the call immediately or let cleanup sweep it
    delete callsById[callId];

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ /calls/hangup crashed:', err);
    return res.status(500).json({ success: false, error: 'internal_error' });
  }
});



// === CALLS: outgoing offer ===
//
// iOS sends POST /calls/offer with:
// {
//   callId: "uuid",
//   fromMessagingId: "base64 pubkey",
//   toMessagingId: "base64 pubkey",
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

    const tokens = await getDeviceTokensForMessagingId(toMessagingId);
    if (!tokens || tokens.length === 0) {
      console.warn("⚠️ /calls/offer: no device tokens for", toMessagingId);
      return res.status(404).json({ error: "no devices for callee" });
    }

    const dataPayload = {
      type: "call_offer",
      callId: String(callId),
      callerMessagingId: String(fromMessagingId),
      callerDisplayName: displayName ? String(displayName) : "",
      sdpOffer: String(sdpOffer)
    };

    const message = {
      tokens,
      data: dataPayload
    };

    const resp = await admin.messaging().sendMulticast(message);
    console.log("✅ /calls/offer FCM sent:", resp.successCount, "success,", resp.failureCount, "failure");

    return res.json({ ok: true, fcm: resp });
  } catch (err) {
    console.error("🔥 /calls/offer error:", err);
    return res.status(500).json({ error: "internal_error" });
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
  for (const [email, exp] of Object.entries(sessionApprovals)) {
    if (Date.now() > exp) delete sessionApprovals[email];
  }
  // Cleanup stale card challenges
  for (const [email, rec] of Object.entries(pendingCardChallenges)) {
    if (!rec || now > (rec.expiresAt || 0)) delete pendingCardChallenges[email];
  }

  // Cleanup old messages (hard cap ~10 minutes in relay)
  const TTL = 10 * 60_000;
  for (const [recipientId, list] of Object.entries(messagesByRecipient)) {
    const fresh = list.filter(m => now - (m.ts || 0) <= TTL);
    if (fresh.length > 0) {
      messagesByRecipient[recipientId] = fresh;
    } else {
      delete messagesByRecipient[recipientId];
    }
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
app.post('/nft-owned-verify', async (req, res) => {
  try {
    if (!provider || !CONTRACT_ADDRESS) return res.status(503).json({ success: false, error: 'Read contract not configured' });
    const address = String(req.body?.address || '').trim();
    const email   = req.body?.email || null;
    const deviceFpr = req.body?.deviceFpr || null;
    if (!address || !ethers.utils.isAddress(address)) return res.status(400).json({ success: false, error: 'Valid address required' });

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
    const tidStr = tokenId?.toString?.() || String(tokenId || "0");
    if (tidStr === "0") return res.json({ success: true, owned: true, matched: false });

    const id = await personaRead.identityOf(tokenId);
    const onUser   = id.userIdHash || id[0];
    const onDevice = id.deviceHash || id[1];

    const emailOk  = email  ? (commitUserId(email).toLowerCase()   === String(onUser).toLowerCase())   : true;
    const deviceOk = deviceFpr ? (commitDevice(deviceFpr).toLowerCase() === String(onDevice).toLowerCase()) : true;

    return res.json({ success: true, owned: true, matched: !!(emailOk && deviceOk) });
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
