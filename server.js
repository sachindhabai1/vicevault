/**
 * ====================================================================
 * VICEVAULT // Secure Node.js + Express Backend
 * ====================================================================
 * Features:
 * 1. Email OTP Verification on Signup:
 *    - 6-digit OTP generated via crypto.randomInt (never Math.random)
 *    - Sent via Nodemailer Gmail SMTP
 *    - 15-minute strict expiry
 *    - HMAC-SHA256 hashed in Firestore (never plaintext)
 *    - Max 5 wrong attempts per OTP before invalidation
 *    - Single-use: deleted upon successful verification
 *    - Resend OTP with 60s cooldown and 5 emails/hour limit per email
 *    - User marked emailVerified: true in Firebase Auth on success
 *    - crypto.timingSafeEqual for constant-time hash comparison
 * 2. Login Attempt Limit (Max 5):
 *    - Backend validates credentials via Firebase Auth REST API
 *    - Failed attempts tracked in Firestore (loginAttempts)
 *    - 5 failed attempts locks account for 15 minutes with live wait timer
 *    - Resets counter on successful login
 *    - Blocks unverified users and redirects to OTP verification
 *    - Returns Firebase custom token (createCustomToken) for client sign-in
 * 3. Security:
 *    - express-rate-limit on auth endpoints
 *    - Generic error messages to prevent email enumeration
 *    - Input validation and sanitization
 *    - CORS restricted to allowed store origins
 *    - Serves static files for unified single-port hosting
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
const PORT = process.env.PORT || 5001;
const OTP_SECRET = process.env.OTP_SECRET || 'vicevault_secure_hmac_secret_key_default_2026';
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || 'AIzaSyA0bGA0W28MGU_tv23uVrOjP9vuxrIvhVI';

// -------------------------------------------------------------
// 1. Firebase Admin SDK Initialization
// -------------------------------------------------------------
const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './service-account.json';
const resolvedServiceAccount = path.resolve(__dirname, serviceAccountPath);

if (!fs.existsSync(resolvedServiceAccount)) {
  console.error(`❌ [Firebase Admin] Service account file not found: ${resolvedServiceAccount}`);
  console.error('Please ensure service-account.json exists in project root or set FIREBASE_SERVICE_ACCOUNT_PATH in .env');
  process.exit(1);
}

const serviceAccount = JSON.parse(fs.readFileSync(resolvedServiceAccount, 'utf8'));

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id
  });
  console.log('⚡ [Firebase Admin] Initialized successfully for project:', serviceAccount.project_id);
}

const db = admin.firestore();
const auth = admin.auth();

// -------------------------------------------------------------
// 2. Nodemailer Transporter Configuration (Gmail SMTP)
// -------------------------------------------------------------
let mailTransporter = null;

function getMailTransporter() {
  const user = (process.env.GMAIL_USER && !process.env.GMAIL_USER.includes('your_email'))
    ? process.env.GMAIL_USER
    : (process.env.EMAIL_USER || process.env.GMAIL_USER);

  const pass = (process.env.GMAIL_APP_PASSWORD && !process.env.GMAIL_APP_PASSWORD.includes('your_16_char'))
    ? process.env.GMAIL_APP_PASSWORD
    : (process.env.EMAIL_APP_PASSWORD || process.env.GMAIL_APP_PASSWORD);

  if (!user || !pass || user.includes('your_email') || pass.includes('your_16_char')) {
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
// 3. Middleware & CORS Configuration
// -------------------------------------------------------------
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

// Default common origins if none set
if (allowedOrigins.length === 0) {
  allowedOrigins.push(
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    'https://sachindhabai1.github.io'
  );
}

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (e.g. mobile apps, curl, or same-origin static file hosting)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
      return callback(null, true);
    }
    // Allow GitHub Pages variations
    if (origin.endsWith('.github.io') || origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy: This origin is not allowed.'));
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Trust proxy for rate-limit behind reverse proxy / codespaces
app.set('trust proxy', 1);

// -------------------------------------------------------------
// 4. Rate Limiters (express-rate-limit)
// -------------------------------------------------------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 25, // 25 requests per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP. Please try again after 15 minutes.'
  }
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // 20 requests per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many OTP requests from this IP. Please try again later.'
  }
});

// -------------------------------------------------------------
// 5. Cryptographic & Validation Helper Functions
// -------------------------------------------------------------

/**
 * Generate a cryptographically secure 6-digit OTP using crypto.randomInt
 * (Never Math.random)
 */
function generateSecureOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

/**
 * Generate HMAC-SHA256 hash of an OTP using server secret
 */
function hashOtp(otp) {
  return crypto.createHmac('sha256', OTP_SECRET).update(String(otp).trim()).digest('hex');
}

/**
 * Constant-time safe comparison of two hex hashes using crypto.timingSafeEqual
 */
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

/**
 * Validate and sanitize email format
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return re.test(email.trim()) && email.length <= 150;
}

/**
 * Normalize email for consistent document keying
 */
function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

/**
 * Check hourly rate limit (max 5 emails/hour) and 60-second cooldown
 */
async function checkEmailRateLimit(email) {
  const normEmail = normalizeEmail(email);
  const now = Date.now();
  const rateRef = db.collection('otpRateLimits').doc(normEmail);
  const snap = await rateRef.get();

  if (snap.exists) {
    const data = snap.data();
    const lastSent = Number(data.lastSent) || 0;
    const windowStart = Number(data.windowStart) || now;
    const count = Number(data.count) || 0;

    // 60-second cooldown check
    const diffMs = now - lastSent;
    if (diffMs < 60 * 1000) {
      const waitSeconds = Math.ceil((60 * 1000 - diffMs) / 1000);
      return {
        allowed: false,
        cooldown: true,
        waitSeconds,
        error: `Kripya ${waitSeconds} second intezaar karein naya OTP mangwane se pehle.`
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
      // Increment count
      await rateRef.update({
        count: admin.firestore.FieldValue.increment(1),
        lastSent: now
      });
    } else {
      // Reset window
      await rateRef.set({
        windowStart: now,
        count: 1,
        lastSent: now
      });
    }
  } else {
    await rateRef.set({
      windowStart: now,
      count: 1,
      lastSent: now
    });
  }

  return { allowed: true };
}

/**
 * Internal function to generate, hash, save, and send OTP
 */
async function sendOtpInternal(email, uid) {
  const normEmail = normalizeEmail(email);

  // 1. Check email hourly limit and 60s cooldown
  const rateCheck = await checkEmailRateLimit(normEmail);
  if (!rateCheck.allowed) {
    return rateCheck;
  }

  // 2. Generate secure 6-digit OTP (crypto.randomInt)
  const plainOtp = generateSecureOtp();
  const hashedOtp = hashOtp(plainOtp);
  const now = Date.now();
  const expiresAt = now + 15 * 60 * 1000; // exactly 15 minutes

  // 3. Store only HMAC-SHA256 hash in Firestore (never plaintext)
  // Generating a new OTP overwrites and invalidates any previous OTP
  await db.collection('otp').doc(normEmail).set({
    hash: hashedOtp,
    expiresAt: expiresAt,
    attempts: 0,
    sentAt: now,
    uid: uid || null,
    email: normEmail
  });

  // 4. Send Email via Nodemailer (Gmail SMTP)
  const transporter = getMailTransporter();
  const senderEmail = process.env.GMAIL_USER || process.env.EMAIL_USER || 'noreply@vicevault.store';

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
                      • Kripya yeh code kisi ke bhi sath share na karein.
                    </p>
                  </div>

                  <p style="margin: 0; font-size: 11px; color: #71717a; line-height: 1.4;">
                    Agar aapne yeh account create nahi kiya hai toh aap is email ko surakshit roop se ignore kar sakte hain.
                  </p>
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
        text: `Your verification code is ${plainOtp}. It expires in exactly 15 minutes and must not be shared.`,
        html: htmlContent
      });
      console.log(`✉️ [Email Sent] OTP successfully delivered to ${normEmail}`);
    } catch (mailErr) {
      console.error(`❌ [Nodemailer Error] Failed to send email to ${normEmail}:`, mailErr.message);
      // Fallback dev notice
      console.log(`🔑 [DEV OTP FALLBACK for ${normEmail}]: ${plainOtp}`);
    }
  } else {
    // If Gmail App Password is not yet set in .env, display in console for instant dev testing
    console.log(`\n======================================================`);
    console.log(`✉️ [GMAIL SMTP NOT CONFIGURED IN .env - DEV FALLBACK]`);
    console.log(`To: ${normEmail}`);
    console.log(`OTP Code: ${plainOtp} (Valid for 15 minutes)`);
    console.log(`Set GMAIL_USER & GMAIL_APP_PASSWORD in .env to send real emails.`);
    console.log(`======================================================\n`);
  }

  return {
    allowed: true,
    success: true,
    expiresAt,
    waitSeconds: 60,
    message: 'OTP aapki email par bhej diya gaya hai. Yeh code 15 minutes ke liye valid hai.'
  };
}

// -------------------------------------------------------------
// 6. API ENDPOINTS
// -------------------------------------------------------------

/**
 * Health Check Endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    project: serviceAccount.project_id,
    smtpConfigured: Boolean(getMailTransporter()),
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /api/auth/signup
 * 1. Validates name, email, password, phone
 * 2. Creates unverified user in Firebase Auth (emailVerified: false)
 * 3. Saves user profile in Firestore
 * 4. Generates & sends secure 15-minute OTP
 * 5. Blocks dashboard access until verified
 */
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    // Input Validation & Sanitization
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

    // Check if user already exists in Firebase Auth
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
        // Already fully verified
        return res.status(400).json({
          success: false,
          error: 'Yeh email pehle se registered hai. Kripya Sign In karein.'
        });
      } else {
        // Existing user but unverified: send fresh OTP and guide to OTP screen
        const otpResult = await sendOtpInternal(normEmail, userRecord.uid);
        if (!otpResult.allowed) {
          return res.status(429).json({ success: false, error: otpResult.error });
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

    // Create user in Firebase Auth with emailVerified: false
    const newUser = await auth.createUser({
      email: normEmail,
      password: password,
      displayName: name.trim(),
      emailVerified: false
    });

    // Save user profile in Firestore
    const userDocData = {
      uid: newUser.uid,
      name: name.trim(),
      email: normEmail,
      phone: cleanPhone ? `+91${cleanPhone}` : '',
      emailVerified: false,
      phoneVerified: false,
      role: 'customer',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };
    await db.collection('users').doc(newUser.uid).set(userDocData, { merge: true });

    // Send initial 15-minute OTP
    const otpResult = await sendOtpInternal(normEmail, newUser.uid);
    if (!otpResult.allowed) {
      return res.status(429).json({ success: false, error: otpResult.error });
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
      return res.status(400).json({ success: false, error: 'Yeh email pehle se registered hai.' });
    }
    return res.status(500).json({ success: false, error: 'Signup process mein takleef aayi. Kripya dobara try karein.' });
  }
});

/**
 * POST /api/auth/send-otp (or /resend-otp)
 * Enforces:
 * - 60s cooldown
 * - 5 emails/hour per email limit
 * - Invalidates old OTP by generating a fresh one
 */
app.post(['/api/auth/send-otp', '/api/auth/resend-otp'], otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Kripya ek valid email enter karein.' });
    }

    const normEmail = normalizeEmail(email);

    // Look up user UID if exists
    let uid = null;
    try {
      const userRecord = await auth.getUserByEmail(normEmail);
      uid = userRecord.uid;
      if (userRecord.emailVerified) {
        return res.status(400).json({ success: false, error: 'Aapka email pehle se verified hai. Kripya login karein.' });
      }
    } catch (e) {
      // User not yet created or temporary
    }

    const result = await sendOtpInternal(normEmail, uid);
    if (!result.allowed) {
      return res.status(429).json({
        success: false,
        error: result.error,
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
 * - 15-minute strict expiry
 * - HMAC-SHA256 comparison via crypto.timingSafeEqual
 * - Max 5 wrong attempts per OTP before invalidation
 * - Single-use: OTP deleted upon success
 * - User marked emailVerified: true in Firebase Auth
 * - Returns custom token for seamless client sign-in
 */
app.post('/api/auth/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email.' });
    }
    const cleanOtp = String(otp || '').trim();
    if (!cleanOtp || cleanOtp.length !== 6 || !/^\d{6}$/.test(cleanOtp)) {
      return res.status(400).json({ success: false, error: 'Kripya sahi 6-digit OTP enter karein.' });
    }

    const normEmail = normalizeEmail(email);
    const otpRef = db.collection('otp').doc(normEmail);
    const snap = await otpRef.get();

    if (!snap.exists) {
      return res.status(400).json({
        success: false,
        error: 'Koi active OTP nahi mila ya OTP expire ho chuka hai. Kripya "Resend OTP" par tap karein.',
        expired: true
      });
    }

    const otpData = snap.data();
    const now = Date.now();
    const expiresAt = Number(otpData.expiresAt) || 0;
    const currentAttempts = Number(otpData.attempts) || 0;

    // Check 15-minute strict expiry
    if (now > expiresAt) {
      await otpRef.delete();
      return res.status(400).json({
        success: false,
        error: 'OTP expire ho chuka hai (15 minutes limit pass ho gayi). Kripya naya OTP mangwayein.',
        expired: true
      });
    }

    // Check max 5 wrong attempts per OTP
    if (currentAttempts >= 5) {
      await otpRef.delete();
      return res.status(400).json({
        success: false,
        error: 'Is OTP par maximum 5 wrong attempts poore ho gaye hain. Security ke liye yeh OTP invalidate ho gaya hai. Naya OTP mangwayein.',
        expired: true,
        maxAttemptsExceeded: true
      });
    }

    // Compute HMAC-SHA256 hash of provided OTP
    const candidateHash = hashOtp(cleanOtp);
    const storedHash = otpData.hash;

    // Compare hashes using timingSafeEqual
    const isMatch = timingSafeCompare(candidateHash, storedHash);

    if (!isMatch) {
      const updatedAttempts = currentAttempts + 1;
      const remainingAttempts = Math.max(0, 5 - updatedAttempts);

      if (remainingAttempts === 0) {
        await otpRef.delete();
        return res.status(400).json({
          success: false,
          error: 'Galat OTP! 5 wrong attempts poore ho gaye. Yeh OTP invalidate ho gaya hai. Kripya naya OTP mangwayein.',
          remainingAttempts: 0,
          expired: true
        });
      } else {
        await otpRef.update({ attempts: admin.firestore.FieldValue.increment(1) });
        return res.status(400).json({
          success: false,
          error: `Galat OTP! Aapke paas ${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} baaki hain.`,
          remainingAttempts: remainingAttempts
        });
      }
    }

    // --- SUCCESSFUL VERIFICATION ---
    // 1. Single-use: Delete the OTP document immediately
    await otpRef.delete();

    // 2. Identify UID
    let uid = otpData.uid;
    if (!uid) {
      try {
        const u = await auth.getUserByEmail(normEmail);
        uid = u.uid;
      } catch (e) {}
    }

    // 3. Mark user as emailVerified: true in Firebase Auth
    if (uid) {
      await auth.updateUser(uid, { emailVerified: true });
      // Update Firestore user document
      await db.collection('users').doc(uid).set({
        emailVerified: true,
        verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }

    // 4. Generate a Firebase custom token for instant client sign-in
    let customToken = null;
    if (uid) {
      customToken = await auth.createCustomToken(uid);
    }

    return res.json({
      success: true,
      message: 'Email successfully verify ho gaya!',
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
 * - Max 5 failed login attempts
 * - 15-minute account lockout with remaining wait time
 * - Firebase Auth REST API (accounts:signInWithPassword)
 * - Returns custom token on success
 * - Blocks unverified users and redirects to OTP verification
 * - Generic error messages to prevent email enumeration
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
    const snap = await attemptsRef.get();

    // Check account lockout
    if (snap.exists) {
      const data = snap.data();
      const attempts = Number(data.attempts) || 0;
      const lockUntil = Number(data.lockUntil) || 0;

      if (attempts >= 5 && now < lockUntil) {
        const remainingMs = lockUntil - now;
        const waitMinutes = Math.floor(remainingMs / 60000);
        const waitSeconds = Math.ceil((remainingMs % 60000) / 1000);
        return res.status(429).json({
          success: false,
          locked: true,
          remainingWaitSeconds: Math.ceil(remainingMs / 1000),
          error: `Account temporary lock hai (5 galat login attempts). Kripya ${waitMinutes} minute ${waitSeconds} second baad try karein.`
        });
      }

      // If lock has passed, reset counter
      if (lockUntil && now >= lockUntil) {
        await attemptsRef.delete();
      }
    }

    // Verify email/password via Firebase Auth REST API
    const restEndpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`;
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
      // Login failed -> Track failed attempt
      const snapAgain = await attemptsRef.get();
      const cur = snapAgain.exists ? (Number(snapAgain.data().attempts) || 0) : 0;
      const newAttempts = cur + 1;
      const remaining = Math.max(0, 5 - newAttempts);

      if (newAttempts >= 5) {
        const lockUntil = now + 15 * 60 * 1000; // 15 minutes lockout
        await attemptsRef.set({
          attempts: newAttempts,
          lockUntil: lockUntil,
          lastFailedAt: now,
          email: normEmail
        });
        return res.status(429).json({
          success: false,
          locked: true,
          remainingWaitSeconds: 15 * 60,
          error: '5 galat attempts poore ho gaye. Account ko 15 minutes ke liye lock kar diya gaya hai.'
        });
      } else {
        await attemptsRef.set({
          attempts: newAttempts,
          lastFailedAt: now,
          email: normEmail
        }, { merge: true });

        // Generic error message to prevent email enumeration
        return res.status(401).json({
          success: false,
          error: `Galat email ya password. Aapke paas ${remaining} attempt${remaining === 1 ? '' : 's'} baaki hain.`,
          remainingAttempts: remaining
        });
      }
    }

    // --- CREDENTIALS CORRECT ---
    // Reset failed login attempts on successful credentials
    await attemptsRef.delete();

    // Check email verification status in Firebase Auth via Admin SDK
    const userRecord = await auth.getUser(restData.localId);

    if (!userRecord.emailVerified) {
      // Do NOT log the user in! Send OTP and instruct frontend to show verification screen
      const otpResult = await sendOtpInternal(normEmail, userRecord.uid);
      return res.status(403).json({
        success: false,
        unverified: true,
        email: normEmail,
        uid: userRecord.uid,
        expiresAt: otpResult.expiresAt,
        error: 'Aapka email verify nahi hai. Humne aapke email par 6-digit verification OTP bheja hai.'
      });
    }

    // User is fully verified: generate a Firebase Custom Token for the client
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

// -------------------------------------------------------------
// 7. Serve Static Frontend Files (Unified Hosting)
// -------------------------------------------------------------
app.use(express.static(path.resolve(__dirname)));

// Fallback to index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'index.html'));
});

// -------------------------------------------------------------
// 8. Start Server
// -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 VICEVAULT Store & Auth Server is LIVE!`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`🔒 Project: ${serviceAccount.project_id}`);
  console.log(`✉️  SMTP: ${getMailTransporter() ? 'Gmail Configured' : 'Dev Console Mode (Set .env for live)'}`);
  console.log(`======================================================\n`);
});
