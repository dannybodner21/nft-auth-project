// security-logger.js
// Structured logging with sanitization and tamper-evident storage

const winston = require('winston');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================================
// CONFIGURATION
// ============================================================================

const LOG_DIR = process.env.LOG_DIR || '/var/log/nftauth';
const LOG_SECRET = process.env.LOG_HMAC_SECRET || 'CHANGE_ME_IN_PROD';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

// Ensure log directory exists
try {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
} catch (e) {
  console.error('Failed to create log directory:', LOG_DIR, e.message);
}

// ============================================================================
// SANITIZATION HELPERS
// ============================================================================

// Hash email for logs (first 8 chars of SHA256)
function hashEmail(email) {
  if (!email) return 'unknown';
  return crypto.createHash('sha256').update(String(email).toLowerCase().trim()).digest('hex').slice(0, 16);
}

// Truncate IP for privacy (keep first 2 octets for IPv4, first 4 groups for IPv6)
function truncateIP(ip) {
  if (!ip) return 'unknown';
  const s = String(ip).trim();
  if (s.includes('.')) {
    // IPv4: 192.168.1.1 -> 192.168.x.x
    const parts = s.split('.');
    return parts.slice(0, 2).join('.') + '.x.x';
  } else if (s.includes(':')) {
    // IPv6: truncate to first 4 groups
    const parts = s.split(':');
    return parts.slice(0, 4).join(':') + ':x:x:x:x';
  }
  return 'unknown';
}

// Redact sensitive fields from objects before logging
function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  
  const REDACT_KEYS = [
    'password', 'secret', 'token', 'signature', 'signatureB64', 'cardSignature',
    'privateKey', 'apiKey', 'challenge', 'nonce', 'salt', 'ciphertextB64',
    'sdpOffer', 'sdpAnswer', 'candidateJson', 'spkiPem', 'publicKeyPem',
    'deviceToken', 'fcmToken', 'loginToken', 'authToken', 'jwt',
    'code', 'verificationCode', 'otp'
  ];
  
  const HASH_KEYS = ['email', 'emailNorm', 'ownerEmail', 'to'];
  const TRUNCATE_KEYS = ['ip', 'ipAddress', 'clientIp'];
  
  const sanitized = {};
  
  for (const [key, value] of Object.entries(obj)) {
    const keyLower = key.toLowerCase();
    
    if (REDACT_KEYS.some(k => keyLower.includes(k.toLowerCase()))) {
      sanitized[key] = '[REDACTED]';
    } else if (HASH_KEYS.includes(key)) {
      sanitized[key] = hashEmail(value);
    } else if (TRUNCATE_KEYS.includes(key)) {
      sanitized[key] = truncateIP(value);
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

// ============================================================================
// TAMPER-EVIDENT LOG CHAIN
// ============================================================================

let lastLogHash = null;
const CHAIN_FILE = path.join(LOG_DIR, 'chain-state.json');

// Load last hash from disk on startup
try {
  if (fs.existsSync(CHAIN_FILE)) {
    const state = JSON.parse(fs.readFileSync(CHAIN_FILE, 'utf8'));
    lastLogHash = state.lastHash || null;
  }
} catch (e) {
  console.error('Failed to load chain state:', e.message);
}

// Compute HMAC for log entry (includes previous hash for chaining)
function computeLogHMAC(entry, prevHash) {
  const data = JSON.stringify({ entry, prevHash: prevHash || 'GENESIS' });
  return crypto.createHmac('sha256', LOG_SECRET).update(data).digest('hex');
}

// Save chain state periodically
function saveChainState() {
  try {
    fs.writeFileSync(CHAIN_FILE, JSON.stringify({ lastHash: lastLogHash, updatedAt: Date.now() }));
  } catch (e) {
    // Silently fail - don't disrupt logging
  }
}

// Save chain state every 60 seconds
setInterval(saveChainState, 60000).unref();

// ============================================================================
// WINSTON LOGGER SETUP
// ============================================================================

// Custom format that adds HMAC chain
const chainedFormat = winston.format((info) => {
  const hmac = computeLogHMAC(info, lastLogHash);
  info._hmac = hmac;
  info._prevHash = lastLogHash ? lastLogHash.slice(0, 16) : 'GENESIS';
  lastLogHash = hmac;
  return info;
});

// JSON format for structured logging
const jsonFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
  chainedFormat(),
  winston.format.json()
);

// Console format (more readable for dev)
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length > 0 ? ' ' + JSON.stringify(sanitizeObject(meta)) : '';
    return `${timestamp} [${level.toUpperCase()}] ${message}${metaStr}`;
  })
);

// Create logger
const logger = winston.createLogger({
  level: LOG_LEVEL,
  defaultMeta: { service: 'nftauth-server' },
  transports: [
    // Console output (always)
    new winston.transports.Console({
      format: process.env.NODE_ENV === 'production' ? jsonFormat : consoleFormat
    })
  ]
});

// Add file transport in production
if (process.env.NODE_ENV === 'production') {
  // Security events (append-only, tamper-evident)
  logger.add(new winston.transports.File({
    filename: path.join(LOG_DIR, 'security.log'),
    level: 'warn',
    format: jsonFormat,
    flags: 'a' // append only
  }));
  
  // All events
  logger.add(new winston.transports.File({
    filename: path.join(LOG_DIR, 'combined.log'),
    format: jsonFormat,
    flags: 'a'
  }));
  
  // Errors only
  logger.add(new winston.transports.File({
    filename: path.join(LOG_DIR, 'error.log'),
    level: 'error',
    format: jsonFormat,
    flags: 'a'
  }));
}

// ============================================================================
// SECURITY EVENT LOGGING
// ============================================================================

// Event types with severity levels
const EVENT_SEVERITY = {
  // Critical - immediate attention required
  'nonce_replay_attempt': 'critical',
  'invalid_device_signature': 'critical',
  'invalid_card_signature': 'critical',
  'recovery_address_mismatch': 'critical',
  'token_revoked': 'critical',
  'auto_revoke': 'critical',
  
  // High - security concern
  'rate_limit_exceeded': 'high',
  'invalid_email_code': 'high',
  'invalid_card_verify': 'high',
  'nft_ownership_failed': 'high',
  'challenge_expired': 'high',
  'origin_mismatch': 'high',
  
  // Medium - notable events
  'login_approved': 'medium',
  'login_denied': 'medium',
  'payment_approved': 'medium',
  'payment_denied': 'medium',
  'card_registered': 'medium',
  'device_key_registered': 'medium',
  'account_reset': 'medium',
  
  // Low - informational
  'login_requested': 'low',
  'challenge_issued': 'low',
  'token_issued': 'low',
  'email_code_sent': 'low'
};

/**
 * Log a security event with automatic sanitization and chain integrity
 * 
 * @param {string} eventType - Type of security event
 * @param {object} details - Event details (will be sanitized)
 * @param {object} req - Express request object (optional, for extracting IP/user-agent)
 */
async function logSecurityEvent(eventType, details = {}, req = null) {
  const severity = EVENT_SEVERITY[eventType] || 'medium';
  
  // Extract request context if provided
  let ip = details.ip;
  let userAgent = details.userAgent;
  
  if (req) {
    ip = ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    userAgent = userAgent || req.headers['user-agent'] || 'unknown';
  }
  
  const event = {
    eventType,
    severity,
    ip: truncateIP(ip),
    userAgent: userAgent ? userAgent.slice(0, 100) : undefined,
    ...sanitizeObject(details),
    timestamp: new Date().toISOString()
  };
  
  // Log at appropriate level
  switch (severity) {
    case 'critical':
      logger.error('SECURITY_CRITICAL', event);
      break;
    case 'high':
      logger.warn('SECURITY_HIGH', event);
      break;
    case 'medium':
      logger.info('SECURITY_MEDIUM', event);
      break;
    default:
      logger.debug('SECURITY_LOW', event);
  }
  
  return event;
}

// ============================================================================
// AUDIT TRAIL HELPERS
// ============================================================================

/**
 * Log authentication attempt (success or failure)
 */
function logAuthAttempt(success, details, req) {
  const eventType = success ? 'login_approved' : 'login_denied';
  return logSecurityEvent(eventType, { success, ...details }, req);
}

/**
 * Log rate limit hit
 */
function logRateLimitHit(endpoint, identifier, req) {
  return logSecurityEvent('rate_limit_exceeded', { endpoint, identifier }, req);
}

/**
 * Log token issuance
 */
function logTokenIssued(tokenType, details, req) {
  return logSecurityEvent('token_issued', { tokenType, ...details }, req);
}

/**
 * Log payment event
 */
function logPaymentEvent(approved, details, req) {
  const eventType = approved ? 'payment_approved' : 'payment_denied';
  return logSecurityEvent(eventType, { approved, ...details }, req);
}

// ============================================================================
// REQUEST LOGGING MIDDLEWARE
// ============================================================================

/**
 * Express middleware for request logging
 */
function requestLogger(req, res, next) {
  const start = Date.now();
  const requestId = crypto.randomBytes(8).toString('hex');
  
  req.requestId = requestId;
  
  // Log on response finish
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration,
      ip: truncateIP(req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip)
    };
    
    // Log errors at warn level, everything else at debug
    if (res.statusCode >= 400) {
      logger.warn('HTTP_REQUEST', logData);
    } else {
      logger.debug('HTTP_REQUEST', logData);
    }
  });
  
  next();
}

// ============================================================================
// CHAIN VERIFICATION
// ============================================================================

/**
 * Verify the integrity of a log file
 * Returns { valid: boolean, entries: number, errors: [] }
 */
function verifyLogChain(logFilePath) {
  const errors = [];
  let prevHash = null;
  let entries = 0;
  
  try {
    const content = fs.readFileSync(logFilePath, 'utf8');
    const lines = content.trim().split('\n');
    
    for (const line of lines) {
      if (!line.trim()) continue;
      
      try {
        const entry = JSON.parse(line);
        entries++;
        
        // Check chain continuity
        const expectedPrev = prevHash ? prevHash.slice(0, 16) : 'GENESIS';
        if (entry._prevHash !== expectedPrev) {
          errors.push({
            entry: entries,
            error: 'Chain break detected',
            expected: expectedPrev,
            found: entry._prevHash
          });
        }
        
        // Verify HMAC
        const entryWithoutHmac = { ...entry };
        delete entryWithoutHmac._hmac;
        delete entryWithoutHmac._prevHash;
        
        const expectedHmac = computeLogHMAC(entryWithoutHmac, prevHash);
        if (entry._hmac !== expectedHmac) {
          errors.push({
            entry: entries,
            error: 'HMAC mismatch - possible tampering',
            expected: expectedHmac.slice(0, 16),
            found: entry._hmac?.slice(0, 16)
          });
        }
        
        prevHash = entry._hmac;
      } catch (e) {
        errors.push({ entry: entries + 1, error: 'Parse error: ' + e.message });
      }
    }
  } catch (e) {
    errors.push({ error: 'File read error: ' + e.message });
  }
  
  return {
    valid: errors.length === 0,
    entries,
    errors
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  logger,
  logSecurityEvent,
  logAuthAttempt,
  logRateLimitHit,
  logTokenIssued,
  logPaymentEvent,
  requestLogger,
  verifyLogChain,
  
  // Sanitization helpers (for use in existing code)
  hashEmail,
  truncateIP,
  sanitizeObject
};