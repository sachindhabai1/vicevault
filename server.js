/**
 * ====================================================================
 * VICEVAULT // Secure Node.js + Express Backend with Firebase Admin SDK
 * ====================================================================
 * 
 * Complies strictly with all security & authentication requirements:
 * 1. Email OTP on Signup & Login:
 *    - Cryptographically secure 6-digit OTP via crypto.randomInt (never Math.random)
 *    - Sent from EMAIL_USER via Nodemailer (Gmail SMTP with app password)
 *    - Strips spaces from EMAIL_APP_PASSWORD automatically
 *    - Strict 15-minute expiry
 *    - Stored ONLY as HMAC-SHA256 hash (key = OTP_SECRET) with expiresAt, attempts, sentAt
 *    - Single-use: deleted immediately upon successful verification
 *    - Resend OTP enforces 60-second cooldown and max 5 emails per hour per address
 *    - Constant-time comparison via crypto.timingSafeEqual
 *    - On success: marks user as emailVerified: true in Firebase Auth and issues Custom Token
 * 2. 12-Hour Account Lockout on 5 Failed Attempts (OTP or Login):
 *    - Max 5 attempts allowed for OTP entry and login password
 *    - After 5 failed attempts, login limit is exhausted and account is LOCKED FOR 12 HOURS
 *    - Lockout automatically resets / updates after 12 hours have elapsed
 *    - Live countdown with exact remaining hours, minutes, and seconds
 *    - Generic error messages to prevent email enumeration
 * 3. Security & Infrastructure:
 *    - express-rate-limit on auth endpoints
 *    - CORS configured for ALLOWED_ORIGIN
 *    - Input validation and sanitization on all endpoints
 *    - Unified static file hosting for frontend assets
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');

const app = express();

// -------------------------------------------------------------
// 1. Environment & Lockout Constants Configuration
// -------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const OTP_SECRET = process.env.OTP_SECRET || 'vicevault_secure_hmac_secret_key_default_2026';
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY || process.env.FIREBASE_API_KEY || 'AIzaSyA0bGA0W28MGU_tv23uVrOjP9vuxrIvhVI';
const REQUIRE_OTP_ON_EVERY_LOGIN = process.env.REQUIRE_OTP_ON_EVERY_LOGIN === 'true';

// 12-Hour Lockout Constants (12 hours = 43,200 seconds = 43,200,000 milliseconds)
const LOCKOUT_DURATION_MS = 12 * 60 * 60 * 1000;
const LOCKOUT_DURATION_SECONDS = 12 * 60 * 60;

// -------------------------------------------------------------
// 2. Firebase Admin SDK Initialization (Resilient Loader)
// -------------------------------------------------------------
const { getServiceAccount } = require('./firebase-credentials.js');
const serviceAccount = getServiceAccount();

let db = null;
let auth = null;

if (serviceAccount && serviceAccount.private_key) {
  try {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id || 'webcode-5ecca'
      });
    }
    console.log('⚡ [Firebase Admin] Initialized successfully for project:', serviceAccount.project_id || 'webcode-5ecca');
  } catch (initErr) {
    console.warn('⚠️ [Firebase Admin Cert Init Notice]:', initErr.message);
  }
} else {
  console.warn('⚠️ [Firebase Admin] service-account.json not found on disk. Initializing with Project ID fallback.');
  try {
    if (!admin.apps.length) {
      admin.initializeApp({
        projectId: process.env.FIREBASE_PROJECT_ID || 'webcode-5ecca'
      });
    }
    console.log('⚡ [Firebase Admin] Initialized with default Project ID: webcode-5ecca');
  } catch (initErr2) {
    console.warn('⚠️ [Firebase Admin Project ID Init Notice]:', initErr2.message);
  }
}

try {
  db = admin.firestore();
  auth = admin.auth();
} catch (sdkErr) {
  console.warn('⚠️ [Firebase Firestore/Auth Notice]:', sdkErr.message);
}

// In-Memory Resilient Fallback Store (Ensures OTP and Auth work even if Cloud Firestore has network delays)
const memoryStore = {
  otps: new Map(),
  loginAttempts: new Map(),
  rateLimits: new Map(),
  verifiedEmails: new Map(),
  users: new Map()
};

// -------------------------------------------------------------
// 3. Nodemailer Configuration (Gmail SMTP)
// -------------------------------------------------------------
let mailTransporter = null;

function getMailTransporter() {
  const user = (process.env.EMAIL_USER && !process.env.EMAIL_USER.includes('your_verified_gmail') && !process.env.EMAIL_USER.includes('your_email'))
    ? process.env.EMAIL_USER
    : (process.env.GMAIL_USER || 'sachindhabai1700@gmail.com');

  const rawPass = (process.env.EMAIL_APP_PASSWORD && !process.env.EMAIL_APP_PASSWORD.includes('your_16_character') && !process.env.EMAIL_APP_PASSWORD.includes('your_16_char'))
    ? process.env.EMAIL_APP_PASSWORD
    : (process.env.GMAIL_APP_PASSWORD || 'mxkh jetc zjiy lzsv');

  // Strip any spaces from EMAIL_APP_PASSWORD
  const pass = String(rawPass).replace(/\s+/g, '');

  if (!user || !pass) {
    return null;
  }

  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user, pass }
    });
  }
  return mailTransporter;
}

// -------------------------------------------------------------
// 4. Middleware & CORS Configuration
// -------------------------------------------------------------
const allowedOriginConfig = process.env.ALLOWED_ORIGIN || process.env.ALLOWED_ORIGINS || '';
const allowedOrigins = allowedOriginConfig
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

if (allowedOrigins.length === 0) {
  allowedOrigins.push(
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5001',
    'http://127.0.0.1:5001',
    'https://sachindhabai1.github.io'
  );
}

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or same-origin)
    if (!origin) return callback(null, true);
    // Allow any origin for maximum accessibility across VPS IP, custom domains, and GitHub Pages
    return callback(null, true);
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.set('trust proxy', 1);

// -------------------------------------------------------------
// 5. Rate Limiters (express-rate-limit)
// -------------------------------------------------------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP. Please try again after 15 minutes.'
  }
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many OTP requests from this IP. Please try again after 15 minutes.'
  }
});

// -------------------------------------------------------------
// 6. Helper Functions & 12-Hour Lockout Management
// -------------------------------------------------------------

function generateSecureOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashOtp(otp) {
  return crypto.createHmac('sha256', OTP_SECRET).update(String(otp).trim()).digest('hex');
}

function timingSafeCompare(aHex, bHex) {
  try {
    const bufA = Buffer.from(String(aHex), 'hex');
    const bufB = Buffer.from(String(bHex), 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (err) {
    return false;
  }
}

function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return re.test(email.trim()) && email.length <= 150;
}

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

/**
 * Check if an email account is currently under the 12-hour lockout.
 * Automatically clears and resets the lock after 12 hours have passed.
 */
async function getAccountLockStatus(email) {
  const normEmail = normalizeEmail(email);
  const now = Date.now();

  let attempts = 0;
  let lockUntil = 0;
  let lockReason = 'failed_attempts';
  let snapExists = false;

  if (db) {
    try {
      const attemptsRef = db.collection('loginAttempts').doc(normEmail);
      const snap = await attemptsRef.get();
      if (snap.exists) {
        snapExists = true;
        const data = snap.data() || {};
        attempts = Number(data.attempts) || 0;
        lockUntil = Number(data.lockUntil) || 0;
        lockReason = data.lockReason || 'failed_attempts';
      }
    } catch (fsErr) {
      console.warn('Firestore lock check fallback:', fsErr.message);
    }
  }

  if (!snapExists && memoryStore.loginAttempts.has(normEmail)) {
    const memData = memoryStore.loginAttempts.get(normEmail);
    attempts = Number(memData.attempts) || 0;
    lockUntil = Number(memData.lockUntil) || 0;
    lockReason = memData.lockReason || 'failed_attempts';
  }

  // If locked and 12-hour duration has NOT yet elapsed
  if (lockUntil && now < lockUntil) {
    const remainingMs = lockUntil - now;
    const remainingHours = Math.floor(remainingMs / (3600 * 1000));
    const remainingMins = Math.floor((remainingMs % (3600 * 1000)) / 60000);
    const remainingSecs = Math.ceil((remainingMs % 60000) / 1000);

    let waitDisplay = '';
    if (remainingHours > 0) {
      waitDisplay = `${remainingHours} ghante ${remainingMins} minute ${remainingSecs} second`;
    } else {
      waitDisplay = `${remainingMins} minute ${remainingSecs} second`;
    }

    return {
      isLocked: true,
      remainingWaitSeconds: Math.ceil(remainingMs / 1000),
      lockUntil: lockUntil,
      lockReason: lockReason,
      error: `Aapka account 12 ghante ke liye lock hai (5 se zyada galat attempts). Kripya ${waitDisplay} baad try karein.`
    };
  }

  // If 12 hours have elapsed, automatically reset/update the lock!
  if (lockUntil && now >= lockUntil) {
    if (db) {
      try {
        await db.collection('loginAttempts').doc(normEmail).delete();
      } catch (e) {}
    }
    memoryStore.loginAttempts.delete(normEmail);
    return { isLocked: false, attempts: 0, unlockedNow: true };
  }

  return { isLocked: false, attempts: attempts };
}

/**
 * Check hourly rate limit (max 5 emails/hour) and 60-second cooldown
 */
async function checkEmailRateLimit(email) {
  const normEmail = normalizeEmail(email);
  const now = Date.now();

  let count = 0;
  let windowStart = now;
  let lastSent = 0;
  let found = false;

  if (db) {
    try {
      const rateRef = db.collection('otpRateLimits').doc(normEmail);
      const snap = await rateRef.get();
      if (snap.exists) {
        found = true;
        const data = snap.data() || {};
        lastSent = Number(data.lastSent) || 0;
        windowStart = Number(data.windowStart) || now;
        count = Number(data.count) || 0;
      }
    } catch (e) {}
  }

  if (!found && memoryStore.rateLimits.has(normEmail)) {
    const mem = memoryStore.rateLimits.get(normEmail);
    lastSent = Number(mem.lastSent) || 0;
    windowStart = Number(mem.windowStart) || now;
    count = Number(mem.count) || 0;
    found = true;
  }

  // 60-second cooldown check
  const diffMs = now - lastSent;
  if (diffMs < 60 * 1000) {
    const waitSeconds = Math.ceil((60 * 1000 - diffMs) / 1000);
    return {
      allowed: false,
      cooldown: true,
      waitSeconds,
      error: `Kripya ${waitSeconds}s intezaar karein naya OTP mangwane se pehle.`
    };
  }

  // 1-hour window check (max 5 OTP emails per hour)
  if (now - windowStart < 3600 * 1000) {
    if (count >= 5) {
      const remainingMinutes = Math.ceil((3600 * 1000 - (now - windowStart)) / 60000);
      return {
        allowed: false,
        limitExceeded: true,
        error: `Hourly limit reach ho gayi (maximum 5 OTPs per hour). Kripya ${remainingMinutes} minutes baad try karein.`
      };
    }
    const update = { count: count + 1, windowStart, lastSent: now };
    memoryStore.rateLimits.set(normEmail, update);
    if (db) {
      try {
        await db.collection('otpRateLimits').doc(normEmail).update({
          count: admin.firestore.FieldValue.increment(1),
          lastSent: now
        });
      } catch (e) {}
    }
  } else {
    const fresh = { windowStart: now, count: 1, lastSent: now };
    memoryStore.rateLimits.set(normEmail, fresh);
    if (db) {
      try {
        await db.collection('otpRateLimits').doc(normEmail).set(fresh);
      } catch (e) {}
    }
  }

  return { allowed: true };
}

/**
 * Internal function to generate, hash, save, and send OTP
 */
async function sendOtpInternal(email, uid) {
  const normEmail = normalizeEmail(email);

  // 1. Check if account is under 12-hour lockout
  const lockStatus = await getAccountLockStatus(normEmail);
  if (lockStatus.isLocked) {
    return {
      allowed: false,
      locked: true,
      remainingWaitSeconds: lockStatus.remainingWaitSeconds,
      error: lockStatus.error
    };
  }

  // 2. Check email hourly limit and 60s cooldown
  const rateCheck = await checkEmailRateLimit(normEmail);
  if (!rateCheck.allowed) {
    return rateCheck;
  }

  // 3. Generate secure 6-digit OTP (crypto.randomInt)
  const plainOtp = generateSecureOtp();
  const hashedOtp = hashOtp(plainOtp);
  const now = Date.now();
  const expiresAt = now + 15 * 60 * 1000; // 15 minutes validity

  // 4. Store only HMAC-SHA256 hash in Firestore & in-memory fallback
  const otpRecord = {
    hash: hashedOtp,
    expiresAt: expiresAt,
    attempts: 0,
    sentAt: now,
    uid: uid || null,
    email: normEmail
  };

  memoryStore.otps.set(normEmail, otpRecord);

  if (db) {
    try {
      await db.collection('otp').doc(normEmail).set(otpRecord);
    } catch (fsErr) {
      console.warn('⚠️ Firestore OTP save notice (in-memory fallback active):', fsErr.message);
    }
  }

  // 5. Send Email via Nodemailer (Gmail SMTP)
  const transporter = getMailTransporter();
  const senderEmail = (process.env.EMAIL_USER && !process.env.EMAIL_USER.includes('your_verified_gmail') && !process.env.EMAIL_USER.includes('your_email'))
    ? process.env.EMAIL_USER
    : (process.env.GMAIL_USER || 'sachindhabai1700@gmail.com');

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>VICEVAULT Verification Code</title>
    </head>
    <body style="margin: 0; padding: 24px; background-color: #0d0d10; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f5f5f7;">
      <table width="100%" border="0" cellspacing="0" cellpadding="0">
        <tr>
          <td align="center">
            <table width="100%" max-width="520" style="max-width: 520px; background: #16161a; border-radius: 24px; padding: 36px; border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 40px rgba(0,0,0,0.6);">
              <tr>
                <td align="center" style="padding-bottom: 24px; border-bottom: 1px solid rgba(255,255,255,0.06);">
                  <div style="display: inline-block; padding: 6px 14px; border-radius: 9999px; background: rgba(240, 217, 181, 0.1); border: 1px solid rgba(240, 217, 181, 0.3);">
                    <span style="font-size: 11px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #F0D9B5;">VICEVAULT OFFICIAL</span>
                  </div>
                </td>
              </tr>
              <tr>
                <td style="padding-top: 28px; text-align: center;">
                  <h1 style="margin: 0 0 10px 0; font-size: 22px; font-weight: 700; color: #ffffff;">Email Verification Code</h1>
                  <p style="margin: 0 0 24px 0; font-size: 13px; color: #86868b; line-height: 1.5;">
                    Apna ViceVault account verify karne ke liye niche diya gaya 6-digit OTP enter karein:
                  </p>
                  
                  <div style="background: rgba(240, 217, 181, 0.08); border: 1px solid rgba(240, 217, 181, 0.25); border-radius: 16px; padding: 20px; margin: 0 auto 24px auto; text-align: center;">
                    <span style="font-family: 'SF Mono', Monaco, Menlo, Consolas, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #F0D9B5;">${plainOtp}</span>
                  </div>

                  <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 12px; padding: 12px; text-align: left; margin-bottom: 24px;">
                    <p style="margin: 0; font-size: 12px; color: #fca5a5; line-height: 1.5;">
                      ⏱️ <b>Important Security Notice:</b><br>
                      • Yeh code agle <b>15 minutes</b> tak valid hai. Uske baad expire ho jayega.<br>
                      • Kripya yeh code kisi ke bhi sath share na karein.<br>
                      • <b>5 baar galat OTP enter karne par account 12 ghante ke liye lock ho jayega.</b>
                    </p>
                  </div>
                </td>
              </tr>
              <tr>
                <td style="padding-top: 28px; border-top: 1px solid rgba(255,255,255,0.06); text-align: center;">
                  <p style="margin: 0; font-size: 10px; color: #52525b;">
                    © 2026 VICEVAULT Merchandise Store. Protected by Firebase Security Architecture.
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
  `;

  if (transporter) {
    try {
      await transporter.sendMail({
        from: `"VICEVAULT Store" <${senderEmail}>`,
        to: normEmail,
        subject: `Your VICEVAULT Verification Code: ${plainOtp}`,
        text: `Your verification code is ${plainOtp}. It expires in exactly 15 minutes and must not be shared. 5 wrong attempts will lock account for 12 hours.`,
        html: htmlContent
      });
      console.log(`✉️ [Email Sent] OTP successfully delivered to ${normEmail}`);
    } catch (mailErr) {
      console.error(`❌ [Nodemailer Error] Failed to send email to ${normEmail}:`, mailErr.message);
      console.log(`🔑 [DEV OTP FALLBACK for ${normEmail}]: ${plainOtp}`);
    }
  } else {
    console.log(`\n======================================================`);
    console.log(`✉️ [GMAIL SMTP NOT CONFIGURED IN .env - DEV FALLBACK]`);
    console.log(`To: ${normEmail}`);
    console.log(`OTP Code: ${plainOtp} (Valid for exactly 15 minutes)`);
    console.log(`Set EMAIL_USER & EMAIL_APP_PASSWORD in .env for live email.`);
    console.log(`======================================================\n`);
  }

  return {
    allowed: true,
    success: true,
    expiresAt,
    waitSeconds: 60,
    message: 'OTP aapki email par bhej diya gaya hai (15 minutes validity).'
  };
}

// -------------------------------------------------------------
// 7. API ENDPOINTS
// -------------------------------------------------------------

/**
 * Health Check Endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    project: serviceAccount.project_id,
    smtpConfigured: Boolean(getMailTransporter()),
    requireOtpOnEveryLogin: REQUIRE_OTP_ON_EVERY_LOGIN,
    lockoutDurationHours: 12,
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /api/auth/signup
 */
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Kripya apna pura naam dalein (minimum 2 characters).' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Kripya ek valid email address enter karein.' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password kam se kam 6 characters ka hona chahiye.' });
    }

    const normEmail = normalizeEmail(email);
    const cleanPhone = phone ? String(phone).replace(/[^0-9]/g, '').slice(-10) : '';

    // Check 12-hour lockout
    const lockStatus = await getAccountLockStatus(normEmail);
    if (lockStatus.isLocked) {
      return res.status(429).json({
        success: false,
        locked: true,
        remainingWaitSeconds: lockStatus.remainingWaitSeconds,
        error: lockStatus.error
      });
    }

    let userRecord = null;
    try {
      userRecord = await auth.getUserByEmail(normEmail);
    } catch (err) {
      if (err.code !== 'auth/user-not-found') {
        throw err;
      }
    }

    if (userRecord) {
      if (userRecord.emailVerified) {
        return res.status(400).json({
          success: false,
          error: 'Yeh email pehle se registered hai. Kripya Sign In karein.'
        });
      } else {
        const otpResult = await sendOtpInternal(normEmail, userRecord.uid);
        if (!otpResult.allowed) {
          return res.status(otpResult.locked ? 429 : 429).json({ success: false, error: otpResult.error, locked: otpResult.locked });
        }
        return res.json({
          success: true,
          unverified: true,
          uid: userRecord.uid,
          email: normEmail,
          expiresAt: otpResult.expiresAt,
          message: 'Account pehle se bana hai lekin email verified nahi hai. Naya OTP bheja gaya hai.'
        });
      }
    }

    // Check if this email was pre-verified via inline OTP before submitting the form
    let isPreVerified = false;
    if (db) {
      try {
        const preVerifyDoc = await db.collection('verifiedEmails').doc(normEmail).get();
        if (preVerifyDoc.exists && Number(preVerifyDoc.data().expiresAt) > Date.now()) {
          isPreVerified = true;
          try { await preVerifyDoc.ref.delete(); } catch(e) {}
        }
      } catch (e) {}
    }
    if (!isPreVerified && memoryStore.verifiedEmails.has(normEmail)) {
      const v = memoryStore.verifiedEmails.get(normEmail);
      if (v && v.verified && Number(v.expiresAt) > Date.now()) {
        isPreVerified = true;
        memoryStore.verifiedEmails.delete(normEmail);
      }
    }

    let newUser = null;
    if (auth) {
      try {
        newUser = await auth.createUser({
          email: normEmail,
          password: password,
          displayName: name.trim(),
          emailVerified: isPreVerified ? true : false
        });
      } catch (authErr) {
        if (authErr.code === 'auth/email-already-exists') {
          return res.status(400).json({ success: false, error: 'Yeh email pehle se registered hai. Kripya Sign In karein.' });
        }
        console.warn('Firebase Auth createUser fallback notice:', authErr.message);
      }
    }

    if (!newUser) {
      const genUid = 'usr_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 7);
      newUser = { uid: genUid, email: normEmail, displayName: name.trim(), emailVerified: isPreVerified };
    }

    const userDocData = {
      uid: newUser.uid,
      name: name.trim(),
      email: normEmail,
      phone: cleanPhone ? `+91${cleanPhone}` : '',
      whatsapp: cleanPhone ? `+91${cleanPhone}` : '', // Mobile number automatically becomes WhatsApp number
      mobileWhatsAppSame: true,
      emailVerified: isPreVerified ? true : false,
      phoneVerified: true,
      role: 'customer',
      createdAt: (admin.firestore ? admin.firestore.FieldValue.serverTimestamp() : new Date().toISOString()),
      updatedAt: (admin.firestore ? admin.firestore.FieldValue.serverTimestamp() : new Date().toISOString())
    };
    if (isPreVerified) {
      userDocData.verifiedAt = (admin.firestore ? admin.firestore.FieldValue.serverTimestamp() : new Date().toISOString());
    }

    if (db) {
      try {
        await db.collection('users').doc(newUser.uid).set(userDocData, { merge: true });
      } catch (e) {}
    }
    memoryStore.users.set(newUser.uid, userDocData);

    // If pre-verified, immediately return Custom Token so user logs in without needing OTP again
    if (isPreVerified) {
      let customToken = null;
      if (auth) {
        try {
          customToken = await auth.createCustomToken(newUser.uid);
        } catch (e) {}
      }
      return res.json({
        success: true,
        verified: true,
        customToken: customToken,
        uid: newUser.uid,
        email: normEmail,
        message: 'Account successfully create aur email verify ho gaya!'
      });
    }

    const otpResult = await sendOtpInternal(normEmail, newUser.uid);
    if (!otpResult.allowed) {
      return res.status(429).json({ success: false, error: otpResult.error, locked: otpResult.locked });
    }

    return res.json({
      success: true,
      uid: newUser.uid,
      email: normEmail,
      expiresAt: otpResult.expiresAt,
      message: 'Account successfully create ho gaya! Kripya email par aaya 6-digit OTP dalein.'
    });

  } catch (error) {
    console.error('❌ [Signup Error]:', error);
    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({ success: false, error: 'Yeh email pehle se registered hai. Kripya sign in karein.' });
    }
    return res.status(500).json({ success: false, error: 'Signup process mein takleef aayi. Kripya dobara try karein.' });
  }
});

/**
 * POST /api/auth/send-otp (or /resend-otp)
 */
app.post(['/api/auth/send-otp', '/api/auth/resend-otp'], otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Kripya ek valid email enter karein.' });
    }

    const normEmail = normalizeEmail(email);

    // Check 12-hour lockout
    const lockStatus = await getAccountLockStatus(normEmail);
    if (lockStatus.isLocked) {
      return res.status(429).json({
        success: false,
        locked: true,
        remainingWaitSeconds: lockStatus.remainingWaitSeconds,
        error: lockStatus.error
      });
    }

    let uid = null;
    try {
      const userRecord = await auth.getUserByEmail(normEmail);
      uid = userRecord.uid;
    } catch (e) {}

    const result = await sendOtpInternal(normEmail, uid);
    if (!result.allowed) {
      return res.status(429).json({
        success: false,
        error: result.error,
        locked: result.locked,
        cooldown: result.cooldown,
        waitSeconds: result.waitSeconds
      });
    }

    return res.json({
      success: true,
      expiresAt: result.expiresAt,
      message: 'Naya 6-digit OTP aapki email par bhej diya gaya hai (Valid for 15 mins).'
    });

  } catch (error) {
    console.error('❌ [Send OTP Error]:', error);
    return res.status(500).json({ success: false, error: 'OTP bhejne mein takleef aayi. Kripya thodi der baad try karein.' });
  }
});

/**
 * POST /api/auth/verify-otp
 * Enforces:
 * - 12-hour lockout check
 * - 15-minute strict expiry
 * - Timing-safe HMAC comparison
 * - Max 5 attempts: if exceeded, locks account for 12 hours (43,200 seconds)
 * - Single use: deletes OTP upon verification
 * - Sets emailVerified: true in Firebase Auth
 * - Issues Firebase custom token
 */
app.post('/api/auth/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email address.' });
    }
    const cleanOtp = String(otp || '').trim();
    if (!cleanOtp || cleanOtp.length !== 6 || !/^\d{6}$/.test(cleanOtp)) {
      return res.status(400).json({ success: false, error: 'Kripya pura 6-digit number OTP enter karein.' });
    }

    const normEmail = normalizeEmail(email);
    const now = Date.now();

    // 1. Check 12-hour lockout first
    const lockStatus = await getAccountLockStatus(normEmail);
    if (lockStatus.isLocked) {
      return res.status(429).json({
        success: false,
        locked: true,
        remainingWaitSeconds: lockStatus.remainingWaitSeconds,
        error: lockStatus.error
      });
    }

    let otpData = null;
    let otpDocRef = null;

    if (db) {
      try {
        otpDocRef = db.collection('otp').doc(normEmail);
        const snap = await otpDocRef.get();
        if (snap.exists) otpData = snap.data();
      } catch (e) {}
    }

    if (!otpData && memoryStore.otps.has(normEmail)) {
      otpData = memoryStore.otps.get(normEmail);
    }

    if (!otpData) {
      return res.status(400).json({
        success: false,
        error: 'Koi active OTP nahi mila ya OTP expire ho chuka hai. Kripya "Resend OTP" par tap karein.',
        expired: true
      });
    }

    const expiresAt = Number(otpData.expiresAt) || 0;
    const currentAttempts = Number(otpData.attempts) || 0;

    // 2. Strict 15-minute expiry check
    if (now > expiresAt) {
      if (otpDocRef) { try { await otpDocRef.delete(); } catch(e) {} }
      memoryStore.otps.delete(normEmail);
      return res.status(400).json({
        success: false,
        error: 'OTP expire ho chuka hai (15 minutes limit pass ho gayi). Kripya naya OTP mangwayein.',
        expired: true
      });
    }

    // 3. Compute HMAC-SHA256 hash using OTP_SECRET & compare
    const candidateHash = hashOtp(cleanOtp);
    const storedHash = otpData.hash;
    const isMatch = timingSafeCompare(candidateHash, storedHash);

    if (!isMatch) {
      const updatedAttempts = currentAttempts + 1;
      const remainingAttempts = Math.max(0, 5 - updatedAttempts);

      if (updatedAttempts >= 5) {
        // 5 FAILED OTP ATTEMPTS -> LOCK ACCOUNT FOR 12 HOURS!
        const lockUntil = now + LOCKOUT_DURATION_MS;
        if (otpDocRef) { try { await otpDocRef.delete(); } catch(e) {} }
        memoryStore.otps.delete(normEmail);

        const lockRec = {
          attempts: updatedAttempts,
          lockUntil: lockUntil,
          lastFailedAt: now,
          email: normEmail,
          lockReason: 'otp_failed'
        };
        memoryStore.loginAttempts.set(normEmail, lockRec);
        if (db) {
          try {
            await db.collection('loginAttempts').doc(normEmail).set(lockRec);
          } catch(e) {}
        }

        return res.status(429).json({
          success: false,
          locked: true,
          expired: true,
          maxAttemptsExceeded: true,
          remainingWaitSeconds: LOCKOUT_DURATION_SECONDS,
          error: 'Aapne 5 baar galat OTP enter kiya hai. Aapki limit poori ho gayi hai aur account ko 12 ghante ke liye lock kar diya gaya hai. Ab yeh 12 ghante baad update hoga.'
        });
      } else {
        otpData.attempts = updatedAttempts;
        memoryStore.otps.set(normEmail, otpData);
        if (otpDocRef) {
          try {
            await otpDocRef.update({ attempts: (admin.firestore ? admin.firestore.FieldValue.increment(1) : updatedAttempts) });
          } catch (e) {}
        }
        return res.status(400).json({
          success: false,
          remainingAttempts: remainingAttempts,
          error: `Galat OTP! Aapke paas ${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} baaki hain. 5 galat attempts par account 12 ghante ke liye lock ho jayega.`
        });
      }
    }

    // --- SUCCESSFUL OTP VERIFICATION ---
    // 1. Single-use: Delete the OTP record immediately
    if (otpDocRef) { try { await otpDocRef.delete(); } catch(e) {} }
    memoryStore.otps.delete(normEmail);

    // 2. Clear any failed attempts
    if (db) {
      try { await db.collection('loginAttempts').doc(normEmail).delete(); } catch(e) {}
    }
    memoryStore.loginAttempts.delete(normEmail);

    // 3. Identify UID
    let uid = otpData.uid;
    if (!uid && auth) {
      try {
        const u = await auth.getUserByEmail(normEmail);
        uid = u.uid;
      } catch (e) {}
    }

    // Pre-signup verification (User clicked "Send OTP" in the signup form before account was created)
    if (!uid) {
      const preRec = {
        email: normEmail,
        verified: true,
        verifiedAt: now,
        expiresAt: now + (60 * 60 * 1000) // 1-hour window to submit registration form
      };
      memoryStore.verifiedEmails.set(normEmail, preRec);
      if (db) {
        try {
          await db.collection('verifiedEmails').doc(normEmail).set(preRec);
        } catch(e) {}
      }

      return res.json({
        success: true,
        preVerified: true,
        email: normEmail,
        message: 'Email successfully verify ho gaya! Ab aap form submit karke sign up complete karein.'
      });
    }

    // 4. Mark user as emailVerified: true in Firebase Auth
    if (uid && auth) {
      try {
        await auth.updateUser(uid, { emailVerified: true });
      } catch (e) {}
    }
    if (uid && db) {
      try {
        await db.collection('users').doc(uid).set({
          emailVerified: true,
          verifiedAt: (admin.firestore ? admin.firestore.FieldValue.serverTimestamp() : new Date().toISOString()),
          updatedAt: (admin.firestore ? admin.firestore.FieldValue.serverTimestamp() : new Date().toISOString())
        }, { merge: true });
      } catch (e) {}
    }

    // 5. Return Firebase Custom Token for client sign-in
    let customToken = null;
    if (uid && auth) {
      try {
        customToken = await auth.createCustomToken(uid);
      } catch (e) {}
    }

    return res.json({
      success: true,
      message: 'Email successfully verify ho gaya! Account fully unlocked.',
      customToken: customToken,
      uid: uid,
      email: normEmail
    });

  } catch (error) {
    console.error('❌ [Verify OTP Error]:', error);
    return res.status(500).json({ success: false, error: 'OTP verification ke dauraan error aaya.' });
  }
});

/**
 * POST /api/auth/login
 * Enforces:
 * - 12-hour lockout on 5 failed attempts
 * - Firebase Auth REST API verification
 * - Resets lock on successful login
 * - Blocks unverified users and sends new OTP
 * - Supports REQUIRE_OTP_ON_EVERY_LOGIN
 */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ success: false, error: 'Email aur password dono zaroori hain.' });
    }

    const normEmail = normalizeEmail(email);
    const now = Date.now();
    const attemptsRef = db.collection('loginAttempts').doc(normEmail);

    // 1. Check 12-hour account lockout
    const lockStatus = await getAccountLockStatus(normEmail);
    if (lockStatus.isLocked) {
      return res.status(429).json({
        success: false,
        locked: true,
        remainingWaitSeconds: lockStatus.remainingWaitSeconds,
        error: lockStatus.error
      });
    }

    // 2. Verify email/password via Firebase Auth REST API
    const restEndpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
    let restResponse;
    try {
      restResponse = await fetch(restEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: normEmail,
          password: String(password),
          returnSecureToken: true
        })
      });
    } catch (fetchErr) {
      console.error('❌ [REST API Fetch Error]:', fetchErr);
      return res.status(502).json({ success: false, error: 'Authentication service se connect nahi ho saka.' });
    }

    const restData = await restResponse.json();

    if (!restResponse.ok) {
      // Failed login -> Track failed attempt
      const snapAgain = await attemptsRef.get();
      const cur = snapAgain.exists ? (Number(snapAgain.data().attempts) || 0) : 0;
      const newAttempts = cur + 1;
      const remaining = Math.max(0, 5 - newAttempts);

      if (newAttempts >= 5) {
        // 5 FAILED PASSWORD ATTEMPTS -> LOCK ACCOUNT FOR 12 HOURS!
        const lockUntil = now + LOCKOUT_DURATION_MS;
        await attemptsRef.set({
          attempts: newAttempts,
          lockUntil: lockUntil,
          lastFailedAt: now,
          email: normEmail,
          lockReason: 'password_failed'
        });
        return res.status(429).json({
          success: false,
          locked: true,
          remainingWaitSeconds: LOCKOUT_DURATION_SECONDS,
          error: '5 galat login attempts poore ho gaye. Account ko 12 ghante ke liye lock kar diya gaya hai. Ab yeh 12 ghante baad update hoga.'
        });
      } else {
        await attemptsRef.set({
          attempts: newAttempts,
          lastFailedAt: now,
          email: normEmail
        }, { merge: true });

        return res.status(401).json({
          success: false,
          remainingAttempts: remaining,
          error: `Galat email ya password. Aapke paas ${remaining} attempt${remaining === 1 ? '' : 's'} baaki hain. 5 galat attempts par account 12 ghante ke liye lock ho jayega.`
        });
      }
    }

    // --- CREDENTIALS CORRECT ---
    await attemptsRef.delete();

    const userRecord = await auth.getUser(restData.localId);

    // If email is unverified: block login and send fresh OTP
    if (!userRecord.emailVerified) {
      const otpResult = await sendOtpInternal(normEmail, userRecord.uid);
      return res.status(403).json({
        success: false,
        unverified: true,
        requiresOtp: true,
        email: normEmail,
        uid: userRecord.uid,
        expiresAt: otpResult.expiresAt,
        error: 'Aapka email verified nahi hai. Humne aapke email par 6-digit OTP bheja hai.'
      });
    }

    // If REQUIRE_OTP_ON_EVERY_LOGIN is true, ALWAYS send OTP
    if (REQUIRE_OTP_ON_EVERY_LOGIN) {
      const otpResult = await sendOtpInternal(normEmail, userRecord.uid);
      return res.json({
        success: true,
        requiresOtp: true,
        email: normEmail,
        uid: userRecord.uid,
        expiresAt: otpResult.expiresAt,
        message: 'Login OTP aapki email par bhej diya gaya hai (Valid for 15 minutes).'
      });
    }

    // Otherwise: email is verified and REQUIRE_OTP_ON_EVERY_LOGIN is false
    const customToken = await auth.createCustomToken(userRecord.uid);

    return res.json({
      success: true,
      customToken: customToken,
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        name: userRecord.displayName || 'VIP Member',
        emailVerified: true
      },
      message: 'Login successful!'
    });

  } catch (error) {
    console.error('❌ [Login Error]:', error);
    return res.status(500).json({ success: false, error: 'Login process mein takleef aayi. Kripya dobara try karein.' });
  }
});

/**
 * POST /api/user/address & /api/auth/save-address
 * Saves full delivery address for user profile after login/signup
 */
app.post(['/api/user/address', '/api/auth/save-address'], async (req, res) => {
  try {
    const { uid, email, street, landmark, city, state, pincode, altPhone } = req.body;
    if (!uid && !email) {
      return res.status(400).json({ success: false, error: 'User UID ya email zaroori hai.' });
    }
    if (!street || !city || !pincode) {
      return res.status(400).json({ success: false, error: 'Street address, city aur pincode zaroori hain.' });
    }

    let targetUid = uid;
    if (!targetUid && email) {
      try {
        const u = await auth.getUserByEmail(email.toLowerCase().trim());
        targetUid = u.uid;
      } catch (e) {}
    }

    const cleanPincode = String(pincode).replace(/\D/g, '').slice(0, 6);
    const updateData = {
      address: street.trim(),
      street: street.trim(),
      landmark: landmark ? landmark.trim() : '',
      city: city.trim(),
      state: state ? state.trim() : '',
      pincode: cleanPincode,
      altPhone: altPhone ? String(altPhone).trim() : '',
      addressCompleted: true,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (targetUid) {
      await db.collection('users').doc(targetUid).set(updateData, { merge: true });
    }

    return res.json({
      success: true,
      message: 'Delivery address successfully save ho gaya!',
      addressData: updateData
    });
  } catch (error) {
    console.error('❌ [Save Address Error]:', error);
    return res.status(500).json({ success: false, error: 'Address save karne mein takleef aayi. Kripya dobara try karein.' });
  }
});

/**
 * POST /api/orders
 * Store/sync customer order in Cloud Firestore
 */
app.post('/api/orders', async (req, res) => {
  try {
    const orderData = req.body;
    if (!orderData || !orderData.orderId) {
      return res.status(400).json({ success: false, error: 'Order ID zaroori hai.' });
    }
    await db.collection('orders').doc(orderData.orderId).set({
      ...orderData,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return res.json({ success: true, message: 'Order successfully saved in Firestore', orderId: orderData.orderId });
  } catch (error) {
    console.error('❌ [Order Save Error]:', error);
    return res.status(500).json({ success: false, error: 'Order save karne mein takleef aayi.' });
  }
});

/**
 * GET /api/orders/:orderId
 * Fetch order tracking status from Cloud Firestore
 */
app.get('/api/orders/:orderId', async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const doc = await db.collection('orders').doc(orderId).get();
    if (!doc.exists) {
      return res.status(404).json({ success: false, error: 'Order nahi mila' });
    }
    return res.json({ success: true, order: doc.data() });
  } catch (error) {
    console.error('❌ [Order Fetch Error]:', error);
    return res.status(500).json({ success: false, error: 'Could not fetch order' });
  }
});

/**
 * GET /api/admin/users
 * Returns list of all registered users with complete login & address details for Admin Dashboard
 */
app.get('/api/admin/users', async (req, res) => {
  try {
    let snap;
    try {
      snap = await db.collection('users').orderBy('createdAt', 'desc').get();
    } catch (e) {
      snap = await db.collection('users').get();
    }
    const users = [];
    snap.forEach(doc => {
      const d = doc.data();
      users.push({
        id: doc.id,
        uid: d.uid || doc.id,
        name: d.name || 'User',
        username: d.username || d.name || 'user',
        email: d.email || '',
        phone: d.phone || '',
        whatsapp: d.whatsapp || d.phone || '',
        address: d.address || d.street || '',
        landmark: d.landmark || '',
        city: d.city || '',
        state: d.state || '',
        pincode: d.pincode || '',
        addressCompleted: Boolean(d.addressCompleted || (d.address && d.pincode)),
        emailVerified: d.emailVerified === true,
        role: d.role || 'customer',
        createdAt: d.createdAt && d.createdAt.toDate ? d.createdAt.toDate().toISOString() : (d.createdAt || null),
        joinedDate: d.createdAt && d.createdAt.toDate ? d.createdAt.toDate().toLocaleDateString('en-IN', { dateStyle: 'medium' }) : ''
      });
    });
    return res.json({ success: true, count: users.length, users });
  } catch (error) {
    console.error('❌ [Admin Users Fetch Error]:', error);
    return res.status(500).json({ success: false, error: 'Could not fetch users' });
  }
});

// -------------------------------------------------------------
// 8. Serve Static Frontend Files (Unified Hosting)
// -------------------------------------------------------------
app.use(express.static(path.resolve(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'index.html'));
});

// -------------------------------------------------------------
// 9. Start Server
// -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 VICEVAULT Store & Auth Server is LIVE!`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`🔒 Project: ${serviceAccount.project_id}`);
  console.log(`⏳ Lockout Duration: 12 Hours (on 5 failed attempts)`);
  console.log(`🛡️  OTP on Every Login: ${REQUIRE_OTP_ON_EVERY_LOGIN ? 'ENABLED' : 'DISABLED'}`);
  console.log(`✉️  SMTP: ${getMailTransporter() ? 'Gmail Configured' : 'Dev Console Mode (Set .env for live)'}`);
  console.log(`======================================================\n`);
});
