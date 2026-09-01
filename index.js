const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const fetch = require("node-fetch");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(express.json({ limit: "15mb", verify: (req, res, buf) => { req.rawBody = buf; } }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("WARNING: JWT_SECRET is not set. Set it in Railway's Variables tab or tokens cannot be verified.");
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, isAdmin: !!user.is_admin, tokenVersion: user.token_version || 0 },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

// Reads and verifies a bearer token if present. Returns the decoded payload,
// or null if there's no token or it's invalid/expired — never throws.
function getRequester(req) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token || !JWT_SECRET) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Requires a valid token, AND re-checks the account against the database —
// not just the token's baked-in claims. Tokens last 30 days, so without
// this, suspending a user or revoking someone's admin access wouldn't
// actually take effect until their existing token expired on its own.
async function authenticate(req, res, next) {
  const requester = getRequester(req);
  if (!requester) return res.status(401).json({ error: "Sign in required" });
  try {
    const result = await pool.query(
      "SELECT is_admin, is_suspended, token_version FROM users WHERE id = $1",
      [requester.id]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Account no longer exists" });
    }
    if (result.rows[0].is_suspended) {
      return res.status(403).json({ error: "This account has been suspended" });
    }
    const currentVersion = result.rows[0].token_version || 0;
    if ((requester.tokenVersion || 0) !== currentVersion) {
      return res.status(401).json({ error: "Your session was signed out from another device — log in again" });
    }
    req.user = { ...requester, isAdmin: !!result.rows[0].is_admin };
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// Must follow authenticate(). Requires the token to belong to an admin.
function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: "Admin access required" });
  next();
}

// Simple in-memory cache so repeat requests from the same network within 24h
// don't burn through the IPQualityScore free-tier quota (1,000/month).
const vpnCheckCache = new Map();
const VPN_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.ip;
}

// Lightweight in-memory rate limiter — no external package needed. Tracks
// hits per IP within a rolling window; resets on redeploy, which is fine
// for this app's scale. Applied to auth-adjacent endpoints that would
// otherwise be brute-forceable (login, verification codes, signup).
function rateLimit({ windowMs, max, message }) {
  const hits = new Map();
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [key, entry] of hits) {
      if (entry.start < cutoff) hits.delete(key);
    }
  }, Math.max(windowMs, 60000)).unref();
  return (req, res, next) => {
    const key = getClientIp(req) || "unknown";
    const now = Date.now();
    const entry = hits.get(key);
    if (!entry || now - entry.start > windowMs) {
      hits.set(key, { start: now, count: 1 });
      return next();
    }
    entry.count++;
    if (entry.count > max) {
      return res.status(429).json({ error: message || "Too many attempts — please wait a bit and try again." });
    }
    next();
  };
}

const authRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: "Too many attempts — please wait 15 minutes and try again." });

// Fire-and-forget notification insert — failures are logged, never thrown,
// so a notification glitch can never break the actual action (a sale,
// a message, etc.) that triggered it.
async function createNotification(userId, type, message) {
  if (!userId) return;
  try {
    await pool.query("INSERT INTO notifications (user_id, type, message) VALUES ($1, $2, $3)", [userId, type, message]);
  } catch (err) {
    console.error("Failed to create notification:", err.message);
  }
}

const codeRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, message: "Too many attempts — please wait 15 minutes and try again." });

// Returns true (VPN/proxy/Tor detected), false (clean), or null (couldn't
// check — caller should fail open rather than lock everyone out over a
// third-party outage or missing API key).
async function isVpnOrProxy(ip) {
  if (!ip || ip === "::1" || ip === "127.0.0.1") return false; // local/dev testing
  const cached = vpnCheckCache.get(ip);
  if (cached && Date.now() - cached.checkedAt < VPN_CACHE_TTL_MS) return cached.result;

  if (!process.env.IPQS_API_KEY) {
    console.error("WARNING: IPQS_API_KEY is not set — VPN checks are being skipped.");
    return null;
  }

  try {
    const url = `https://www.ipqualityscore.com/api/json/ip/${process.env.IPQS_API_KEY}/${ip}?strictness=0&allow_public_access_points=true`;
    const response = await fetch(url);
    const data = await response.json();
    if (!data.success) return null;
    const result = !!(data.vpn || data.proxy || data.tor);
    vpnCheckCache.set(ip, { result, checkedAt: Date.now() });
    return result;
  } catch {
    return null;
  }
}

// Phone numbers are far more stable than IP/VPN status, so this cache lasts
// much longer (7 days) — same key as the VPN check, no extra setup needed.
const phoneCheckCache = new Map();
const PHONE_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Returns { blocked: boolean, reason: string } or null if the check couldn't
// run (missing key or API error) — callers should fail open in that case.
async function checkPhoneNumber(phone) {
  const cached = phoneCheckCache.get(phone);
  if (cached && Date.now() - cached.checkedAt < PHONE_CACHE_TTL_MS) return cached.result;

  if (!process.env.IPQS_API_KEY) {
    console.error("WARNING: IPQS_API_KEY is not set — phone validation is being skipped.");
    return null;
  }

  try {
    const url = `https://ipqualityscore.com/api/json/phone/${process.env.IPQS_API_KEY}/${encodeURIComponent(phone)}`;
    const response = await fetch(url);
    const data = await response.json();
    if (!data.success) return null;

    let result = null;
    if (data.valid === false) {
      result = { blocked: true, reason: "That doesn't look like a valid phone number." };
    } else if (data.recent_abuse) {
      result = { blocked: true, reason: "This phone number has been linked to recent abuse. Try a different number." };
    } else {
      result = { blocked: false, reason: "" };
    }
    phoneCheckCache.set(phone, { result, checkedAt: Date.now() });
    return result;
  } catch {
    return null;
  }
}

// In-memory store mapping phone -> Termii's pinId, so the frontend only ever
// has to deal with phone + code, same as before. Short TTL matching the OTP
// lifetime itself.
const termiiPinIds = new Map();
const TERMII_PIN_TTL_MS = 10 * 60 * 1000;

// Records phone numbers that passed /phone-verify/check, so a follow-up
// authenticated call can attach that verified number to an account —
// mirrors how verifiedEmails works for email.
const verifiedPhones = new Map();
const PHONE_VERIFIED_TTL_MS = 30 * 60 * 1000;

// Sends a real SMS one-time code via Termii — a Nigeria-founded provider with
// much better deliverability to Nigerian carriers (MTN, Airtel, Glo, 9mobile)
// than generic international providers, including DND bypass for OTPs.
app.post("/phone-verify/send", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "Missing phone number" });
    if (!process.env.TERMII_API_KEY) {
      return res.status(500).json({ error: "SMS verification isn't configured yet" });
    }

    const to = phone.replace(/[^0-9]/g, ""); // Termii wants digits only, no leading +
    const termiiRes = await fetch("https://api.ng.termii.com/api/sms/otp/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: process.env.TERMII_API_KEY,
        message_type: "NUMERIC",
        to,
        from: process.env.TERMII_SENDER_ID || "N-Alert",
        channel: "generic",
        pin_attempts: 3,
        pin_time_to_live: 10,
        pin_length: 6,
        pin_placeholder: "< 1234 >",
        message_text: "Your Stallyard verification code is < 1234 >. This code expires in 10 minutes. Do not share with anyone.",
        pin_type: "NUMERIC",
      }),
    });
    const data = await termiiRes.json();
    if (!termiiRes.ok || !data.pinId) {
      return res.status(400).json({ error: data.message || "Couldn't send that code — check the phone number and try again" });
    }
    termiiPinIds.set(phone, { pinId: data.pinId, sentAt: Date.now() });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Checks the code the user typed in against Termii's record for that number.
app.post("/phone-verify/check", async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) return res.status(400).json({ error: "Missing phone number or code" });
    if (!process.env.TERMII_API_KEY) {
      return res.status(500).json({ error: "SMS verification isn't configured yet" });
    }

    const stored = termiiPinIds.get(phone);
    if (!stored || Date.now() - stored.sentAt > TERMII_PIN_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }

    const termiiRes = await fetch("https://api.ng.termii.com/api/sms/otp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: process.env.TERMII_API_KEY,
        pin_id: stored.pinId,
        pin: code,
      }),
    });
    const data = await termiiRes.json();
    if (!termiiRes.ok) {
      return res.status(400).json({ error: data.message || "Couldn't check that code" });
    }
    const valid = data.verified === "True" || data.verified === true;
    if (valid) {
      termiiPinIds.delete(phone);
      verifiedPhones.set(phone, Date.now());
    }
    res.json({ valid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// In-memory store mapping email -> {code, sentAt}. Mirrors the Termii pinId
// bridge pattern used for phone, but simpler since we generate the code
// ourselves rather than relying on the provider to hold state for us.
const emailCodes = new Map();
const EMAIL_CODE_TTL_MS = 15 * 60 * 1000;

// Records emails that have actually passed /email-verify/check, so /signup
// can trust this instead of a client-supplied "emailVerified" flag — which
// could otherwise be sent as true directly via the API without ever
// checking a code. Entries are consumed (deleted) once used for a signup.
const verifiedEmails = new Map();
const EMAIL_VERIFIED_TTL_MS = 30 * 60 * 1000;

// Sends a real verification email via Resend. Phone/SMS verification is
// paused for now (Termii country-activation issues) — email is the primary
// verification channel while Stallyard focuses on Nigeria.
app.post("/email-verify/send", codeRateLimit, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email address" });
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Email verification isn't configured yet" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";

    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: fromAddress,
        to: [email],
        subject: `Your Stallyard verification code is ${code}`,
        html: `<p>Your Stallyard verification code is <strong>${code}</strong>.</p><p>This code expires in 15 minutes. If you didn't request this, you can ignore this email.</p>`,
      }),
    });
    const data = await resendRes.json();
    if (!resendRes.ok) {
      return res.status(400).json({ error: data.message || "Couldn't send that email — check the address and try again" });
    }
    emailCodes.set(email.toLowerCase(), { code, sentAt: Date.now() });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Checks the code the user typed in against our record for that email.
app.post("/email-verify/check", codeRateLimit, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Missing email or code" });

    const stored = emailCodes.get(email.toLowerCase());
    if (!stored || Date.now() - stored.sentAt > EMAIL_CODE_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }
    const valid = stored.code === String(code).trim();
    if (valid) {
      emailCodes.delete(email.toLowerCase());
      verifiedEmails.set(email.toLowerCase(), Date.now());
    }
    res.json({ valid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// In-memory store for password reset codes, mirroring the email-verify
// pattern above. Keyed by lowercased username.
const passwordResetCodes = new Map();
const PASSWORD_RESET_CODE_TTL_MS = 15 * 60 * 1000;

// Two-factor login codes — keyed by user id, since by this point in the
// login flow the account is already resolved.
const twoFactorCodes = new Map();
const TWO_FACTOR_CODE_TTL_MS = 10 * 60 * 1000;

// Pending bank-account changes awaiting email confirmation — only required
// when *changing* an existing account on file, not the first-time setup.
// Keyed by user id; holds the new details until the code is confirmed.
const pendingBankChanges = new Map();
const BANK_CHANGE_CODE_TTL_MS = 15 * 60 * 1000;

// Step 1: look up the account by username, email the code to the address
// on file. Deliberately doesn't reveal the email address itself in the
// response beyond a masked preview, and doesn't let the frontend supply
// its own code — everything here is server-generated and server-checked.
app.post("/password-reset/send", authRateLimit, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Enter your username" });
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Password reset isn't configured yet" });
    }
    const key = username.trim().toLowerCase();
    const result = await pool.query("SELECT email FROM users WHERE username = $1", [key]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "We couldn't find an account with that username" });
    }
    const email = result.rows[0].email;
    if (!email) {
      return res.status(400).json({ error: "This account has no email on file — contact support to recover it" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress,
        to: [email],
        subject: `Your Stallyard password reset code is ${code}`,
        html: `<p>Your Stallyard password reset code is <strong>${code}</strong>.</p><p>This code expires in 15 minutes. If you didn't request this, you can ignore this email — your password won't change.</p>`,
      }),
    });
    const data = await resendRes.json();
    if (!resendRes.ok) {
      return res.status(400).json({ error: data.message || "Couldn't send that email — try again" });
    }
    passwordResetCodes.set(key, { code, sentAt: Date.now() });
    const maskedEmail = email.replace(/^(.{1,2}).*(@.*)$/, (m, a, b) => `${a}***${b}`);
    res.json({ success: true, maskedEmail });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Step 2: check the code. On success, issues a short-lived reset token
// (10 min) rather than letting the frontend hold onto the raw code — the
// code itself is single-use and deleted here either way.
app.post("/password-reset/verify-code", codeRateLimit, async (req, res) => {
  try {
    const { username, code } = req.body;
    if (!username || !code) return res.status(400).json({ error: "Missing username or code" });
    const key = username.trim().toLowerCase();
    const stored = passwordResetCodes.get(key);
    if (!stored || Date.now() - stored.sentAt > PASSWORD_RESET_CODE_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    passwordResetCodes.delete(key);
    const userResult = await pool.query("SELECT id FROM users WHERE username = $1", [key]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const resetToken = jwt.sign({ type: "password_reset", userId: userResult.rows[0].id }, JWT_SECRET, { expiresIn: "10m" });
    res.json({ resetToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Step 3: the actual password change. Requires the short-lived reset token
// from step 2, not just a username — this is what makes the flow real,
// versus the old version which never touched the database at all.
app.post("/password-reset/confirm", authRateLimit, async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) return res.status(400).json({ error: "Missing reset token or new password" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    let decoded;
    try {
      decoded = jwt.verify(resetToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "That reset session has expired — start over" });
    }
    if (decoded.type !== "password_reset") {
      return res.status(401).json({ error: "Invalid reset token" });
    }
    const passwordHash = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id",
      [passwordHash, decoded.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/", (req, res) => {
  res.send("Stallyard backend is running!");
});

app.get("/db-check", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.send(`Database connected! Server time: ${result.rows[0].now}`);
  } catch (err) {
    res.status(500).send(`Database connection failed: ${err.message}`);
  }
});

// Migration endpoints are visited directly in the browser (no way to send
// an Authorization header that way), so they're protected by a shared key
// in the URL instead of the normal Bearer-token auth. Set MIGRATION_KEY in
// Railway's Variables tab, then visit /migrate/whatever?key=that-value.
function requireMigrationKey(req, res, next) {
  if (!process.env.MIGRATION_KEY) {
    return res.status(500).send("MIGRATION_KEY isn't set in Railway — add it under Variables before running migrations.");
  }
  if (req.query.key !== process.env.MIGRATION_KEY) {
    return res.status(403).send("Missing or incorrect ?key= — check MIGRATION_KEY in Railway's Variables tab.");
  }
  next();
}

// One-time migration: adds the columns needed for account type, ID
// verification documents, and admin-facing member data. Safe to visit
// more than once — IF NOT EXISTS means it won't duplicate anything.
app.get("/migrate/members-extra", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS account_type TEXT DEFAULT 'personal',
        ADD COLUMN IF NOT EXISTS id_type TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS id_country TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS license_number TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS license_photos JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS id_verification_exempt BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS has_applied_to_sell BOOLEAN DEFAULT false
    `);
    res.send("Migration complete: members-extra columns added.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

// One-time migration: creates the follows table (seller storefront follow/unfollow).
app.get("/migrate/follows", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS follows (
        id SERIAL PRIMARY KEY,
        follower_username TEXT NOT NULL,
        followed_username TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE (follower_username, followed_username)
      )
    `);
    res.send("Migration complete: follows table created.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

// One-time migration: adds every field a real listing needs (images, auctions,
// currency, fitment, status, featured flag) that the original listings table
// didn't have.
app.get("/migrate/listings-extra", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE listings
        ADD COLUMN IF NOT EXISTS emoji TEXT DEFAULT '📦',
        ADD COLUMN IF NOT EXISTS fit_make TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS fit_model TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS fit_year TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS listing_type TEXT DEFAULT 'fixed',
        ADD COLUMN IF NOT EXISTS currency TEXT DEFAULT 'USD',
        ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending',
        ADD COLUMN IF NOT EXISTS is_featured BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS auction_end_time TIMESTAMP,
        ADD COLUMN IF NOT EXISTS bid_history JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS highest_bidder_username TEXT
    `);
    res.send("Migration complete: listings-extra columns added.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

// One-time migration: real multi-seller cart orders, per-item payout tracking,
// and a withdrawals ledger with server-computed balances.
app.get("/migrate/orders-wallet", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE orders
        ADD COLUMN IF NOT EXISTS buyer_username TEXT,
        ADD COLUMN IF NOT EXISTS shipping_address JSONB DEFAULT '{}'::jsonb,
        ADD COLUMN IF NOT EXISTS subtotal NUMERIC DEFAULT 0,
        ADD COLUMN IF NOT EXISTS shipping_total NUMERIC DEFAULT 0,
        ADD COLUMN IF NOT EXISTS commission_rate NUMERIC DEFAULT 0.05,
        ADD COLUMN IF NOT EXISTS commission_amount NUMERIC DEFAULT 0,
        ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'held',
        ADD COLUMN IF NOT EXISTS is_disputed BOOLEAN DEFAULT false
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        listing_id INTEGER,
        title TEXT NOT NULL,
        emoji TEXT DEFAULT '📦',
        price NUMERIC NOT NULL,
        qty INTEGER NOT NULL DEFAULT 1,
        shipping_fee NUMERIC DEFAULT 0,
        seller_id INTEGER NOT NULL REFERENCES users(id),
        seller_username TEXT NOT NULL,
        seller_name TEXT,
        fulfillment_status TEXT DEFAULT 'new',
        tracking_number TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id SERIAL PRIMARY KEY,
        seller_id INTEGER NOT NULL REFERENCES users(id),
        seller_username TEXT NOT NULL,
        amount NUMERIC NOT NULL,
        status TEXT DEFAULT 'processing',
        failure_reason TEXT,
        paystack_transfer_code TEXT,
        requested_at TIMESTAMP DEFAULT NOW(),
        processed_at TIMESTAMP
      )
    `);
    res.send("Migration complete: orders-wallet columns and tables added.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

// One-time migration: cart and watchlist tables, so they follow the user
// across devices instead of living only in one browser's local storage.
app.get("/migrate/signup-stages", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS profile_complete BOOLEAN DEFAULT false
    `);
    // Phone is no longer required at stage one — SMS verification is
    // paused, and email is now the primary verification channel.
    await pool.query(`ALTER TABLE users ALTER COLUMN phone DROP NOT NULL`);
    res.send("Migration complete: signup-stages columns added, phone made optional.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/seller-verification", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS verification_status TEXT DEFAULT 'none',
        ADD COLUMN IF NOT EXISTS bank_statement_url TEXT,
        ADD COLUMN IF NOT EXISTS rejection_reason TEXT
    `);
    // Backfill verification_status from the existing is_approved /
    // has_applied_to_sell booleans so nobody's current state changes.
    await pool.query(`
      UPDATE users SET verification_status =
        CASE WHEN is_approved THEN 'approved'
             WHEN has_applied_to_sell THEN 'pending'
             ELSE 'none' END
      WHERE verification_status IS NULL OR verification_status = 'none'
    `);
    res.send("Migration complete: verification_status, bank_statement_url, rejection_reason columns added.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/listings-extra-fields", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE listings
        ADD COLUMN IF NOT EXISTS quantity INTEGER,
        ADD COLUMN IF NOT EXISTS sku TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS brand TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS state TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS shipping_methods JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS return_policy TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS vin TEXT DEFAULT ''
    `);
    res.send("Migration complete: quantity, sku, brand, state, shipping_methods, return_policy, vin columns added to listings.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/order-management", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS carrier TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS buyer_confirmed_at TIMESTAMP
    `);
    res.send("Migration complete: carrier and buyer_confirmed_at columns added to order_items.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/proof-of-delivery", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS proof_of_delivery_url TEXT DEFAULT ''
    `);
    res.send("Migration complete: proof_of_delivery_url column added to order_items.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/delivery-token", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS delivery_token TEXT,
        ADD COLUMN IF NOT EXISTS delivery_token_generated_at TIMESTAMP
    `);
    res.send("Migration complete: delivery_token and delivery_token_generated_at columns added to order_items.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/message-features", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE messages
        ADD COLUMN IF NOT EXISTS image_url TEXT,
        ADD COLUMN IF NOT EXISTS order_id INTEGER
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS message_reports (
        id SERIAL PRIMARY KEY,
        message_id INTEGER NOT NULL,
        thread_id INTEGER NOT NULL,
        reporter_id INTEGER NOT NULL,
        reason TEXT DEFAULT '',
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP
      )
    `);
    res.send("Migration complete: message image/order columns added, message_reports table created.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/returns", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS return_status TEXT,
        ADD COLUMN IF NOT EXISTS return_reason TEXT,
        ADD COLUMN IF NOT EXISTS return_note TEXT,
        ADD COLUMN IF NOT EXISTS return_requested_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS return_tracking_number TEXT,
        ADD COLUMN IF NOT EXISTS return_evidence_urls JSONB DEFAULT '[]'::jsonb
    `);
    res.send("Migration complete: return_status and related columns added to order_items.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/review-features", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE reviews
        ADD COLUMN IF NOT EXISTS seller_response TEXT,
        ADD COLUMN IF NOT EXISTS seller_response_at TIMESTAMP
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS review_reports (
        id SERIAL PRIMARY KEY,
        review_id INTEGER NOT NULL,
        reporter_id INTEGER NOT NULL,
        reason TEXT DEFAULT '',
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP
      )
    `);
    res.send("Migration complete: seller_response columns added to reviews, review_reports table created.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/store-profile", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS avatar_url TEXT,
        ADD COLUMN IF NOT EXISTS store_bio TEXT,
        ADD COLUMN IF NOT EXISTS store_policies TEXT
    `);
    res.send("Migration complete: avatar_url, store_bio, store_policies columns added to users.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/notifications", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS ship_reminder_sent_at TIMESTAMP
    `);
    res.send("Migration complete: notifications table created, ship_reminder_sent_at added to order_items.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/login-history", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ip TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    res.send("Migration complete: login_history table created.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/two-factor", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT false
    `);
    res.send("Migration complete: two_factor_enabled column added to users.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/phone-verified", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_phone_verified BOOLEAN DEFAULT false
    `);
    res.send("Migration complete: is_phone_verified column added to users.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/sessions", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS account_reports (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP
      )
    `);
    res.send("Migration complete: token_version added to users, account_reports table created.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/seller-performance", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE order_items ADD COLUMN IF NOT EXISTS shipped_at TIMESTAMP
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS seller_warnings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        admin_id INTEGER REFERENCES users(id),
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    res.send("Migration complete: shipped_at added to order_items, seller_warnings table created.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

app.get("/migrate/cart-watchlist", requireMigrationKey, async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER NOT NULL,
        qty INTEGER NOT NULL DEFAULT 1,
        offer_price NUMERIC,
        UNIQUE (user_id, listing_id)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS watchlist_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE (user_id, listing_id)
      )
    `);
    res.send("Migration complete: cart_items and watchlist_items tables added.");
  } catch (err) {
    res.status(500).send(`Migration failed: ${err.message}`);
  }
});

// Stage one: the fast, minimal sign-up. Just enough to create an account
// and log in — username, email, password. Everything else (name, country,
// account type, ID documents) is filled in later via /profile/complete, and
// the user can log in and resume that at any time since profile_complete
// starts false. Email must already be verified (via /email-verify/send +
// /email-verify/check) before this is called.
app.post("/signup", authRateLimit, async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    // Trust our own record of a passed /email-verify/check, not a
    // client-supplied "emailVerified" flag — that could be sent as true
    // directly via the API without ever checking a code.
    const verifiedAt = verifiedEmails.get(email.toLowerCase());
    if (!verifiedAt || Date.now() - verifiedAt > EMAIL_VERIFIED_TTL_MS) {
      return res.status(400).json({ error: "Verify your email before creating an account" });
    }

    const vpnDetected = await isVpnOrProxy(getClientIp(req));
    if (vpnDetected) {
      return res.status(403).json({ error: "Sign-ups aren't allowed over a VPN, proxy, or Tor connection. Please disable it and try again." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const countResult = await pool.query("SELECT COUNT(*) FROM users");
    const isFirstUser = Number(countResult.rows[0].count) === 0;

    const result = await pool.query(
      `INSERT INTO users (
         username, email, password_hash, display_name, is_admin, is_approved,
         is_email_verified, profile_complete
       )
       VALUES ($1, $2, $3, $4, $5, $6, true, false)
       RETURNING id, username, email, phone, display_name, first_name, last_name, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type,
         id_country, license_number, license_photos, id_verification_exempt,
         is_email_verified, profile_complete, created_at, token_version`,
      [username, email, passwordHash, displayName || username, isFirstUser, isFirstUser]
    );

    verifiedEmails.delete(email.toLowerCase());
    res.status(201).json({ user: result.rows[0], token: signToken(result.rows[0]) });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username or email already in use" });
    }
    res.status(500).json({ error: err.message });
  }
});

// Stage two: fill in the rest of the profile (name, phone, country, account
// type, ID documents). Can be called as many times as needed — a user can
// stop partway through and resume later, since nothing here is required to
// log in. Country/US-block and seller approval rules are evaluated here,
// once we actually know the country.
app.patch("/profile/complete", authenticate, async (req, res) => {
  try {
    const {
      firstName, lastName, phone, officeLocation, country, accountType,
      idType, idCountry, licenseNumber, licensePhotos, idVerificationExempt,
    } = req.body;

    const usAliases = ["united states", "united states of america", "usa", "us", "u.s.", "u.s.a."];
    const isUS = usAliases.includes((country || "").trim().toLowerCase());
    if (isUS) {
      return res.status(403).json({ error: "US sign-ups are coming soon — Stallyard is Nigeria-only for now" });
    }

    if (phone) {
      const phoneCheck = await checkPhoneNumber(phone);
      if (phoneCheck?.blocked) {
        return res.status(400).json({ error: phoneCheck.reason });
      }
    }

    const hasCore = firstName && lastName && country;
    const skipId = isUS;
    const hasId = skipId || !!idVerificationExempt || (idType && licenseNumber);
    const nowComplete = !!(hasCore && (accountType === "personal" || hasId));

    const result = await pool.query(
      `UPDATE users SET
         first_name = COALESCE($1, first_name),
         last_name = COALESCE($2, last_name),
         phone = COALESCE($3, phone),
         office_location = COALESCE($4, office_location),
         country = COALESCE($5, country),
         account_type = COALESCE($6, account_type),
         id_type = COALESCE($7, id_type),
         id_country = COALESCE($8, id_country),
         license_number = COALESCE($9, license_number),
         license_photos = COALESCE($10, license_photos),
         id_verification_exempt = COALESCE($11, id_verification_exempt),
         profile_complete = $12
       WHERE id = $13
       RETURNING id, username, email, phone, display_name, first_name, last_name, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type,
         id_country, license_number, license_photos, id_verification_exempt,
         is_email_verified, profile_complete, created_at`,
      [
        firstName || null, lastName || null, phone || null, officeLocation || null,
        country || null, accountType || null, idType || null, idCountry || null,
        licenseNumber || null, licensePhotos ? JSON.stringify(licensePhotos) : null,
        idVerificationExempt === undefined ? null : !!idVerificationExempt,
        nowComplete, req.user.id,
      ]
    );
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "That phone number is already in use" });
    }
    res.status(500).json({ error: err.message });
  }
});

// Updates the storefront-facing profile bits: photo, bio, and store
// policies. Deliberately separate from /profile/complete, which carries
// unrelated signup-completion and ID-verification logic — this endpoint
// is just simple, always-editable fields.
app.patch("/profile/store", authenticate, async (req, res) => {
  try {
    const { avatarUrl, storeBio, storePolicies } = req.body;
    const result = await pool.query(
      `UPDATE users SET
         avatar_url = COALESCE($1, avatar_url),
         store_bio = COALESCE($2, store_bio),
         store_policies = COALESCE($3, store_policies)
       WHERE id = $4
       RETURNING ${USER_RETURNING_FIELDS}`,
      [avatarUrl ?? null, storeBio ?? null, storePolicies ?? null, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change password while logged in — requires the current password, unlike
// the forgot-password flow which is for when you're locked out entirely.
app.patch("/profile/change-password", authenticate, authRateLimit, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Enter your current and new password" });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: "New password must be at least 8 characters" });
    }
    const result = await pool.query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const matches = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!matches) {
      return res.status(401).json({ error: "Current password doesn't match" });
    }
    const newHash = await bcrypt.hash(newPassword, 10);
    // Bumping token_version here signs out every other device using the old
    // password — standard practice, since a password change is often a
    // response to "something felt off." We issue this session a fresh
    // token immediately after so the person doesn't get logged out too.
    const updated = await pool.query(
      `UPDATE users SET password_hash = $1, token_version = COALESCE(token_version, 0) + 1
       WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [newHash, req.user.id]
    );
    res.json({ success: true, token: signToken(updated.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Signs out every other device/session by bumping the token version —
// all previously issued tokens instantly fail the version check in
// authenticate(). Issues a fresh token for this session so the person
// doing this stays logged in themselves.
app.post("/profile/sign-out-other-devices", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET token_version = COALESCE(token_version, 0) + 1
       WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    res.json({ token: signToken(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Turning it on requires the account to have a verified email on file —
// that's where codes go. Turning it off just requires being logged in
// (already a meaningful bar, since you're authenticated to call this).
app.patch("/profile/two-factor", authenticate, async (req, res) => {
  try {
    const { enabled } = req.body;
    if (enabled) {
      const check = await pool.query("SELECT email FROM users WHERE id = $1", [req.user.id]);
      if (!check.rows.length || !check.rows[0].email) {
        return res.status(400).json({ error: "Add a verified email to your account before turning this on" });
      }
    }
    const result = await pool.query(
      "UPDATE users SET two_factor_enabled = $1 WHERE id = $2 RETURNING two_factor_enabled",
      [!!enabled, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    res.json({ twoFactorEnabled: result.rows[0].two_factor_enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Attaches a verified email to the current account. Requires having
// already passed /email-verify/send + /email-verify/check for that exact
// address — this endpoint just checks that record and flips the flag.
app.patch("/profile/verify-email", authenticate, async (req, res) => {
  try {
    const check = await pool.query("SELECT email FROM users WHERE id = $1", [req.user.id]);
    if (!check.rows.length || !check.rows[0].email) {
      return res.status(400).json({ error: "Add an email to your account first" });
    }
    const email = check.rows[0].email.toLowerCase();
    const verifiedAt = verifiedEmails.get(email);
    if (!verifiedAt || Date.now() - verifiedAt > EMAIL_VERIFIED_TTL_MS) {
      return res.status(400).json({ error: "Verify the code we sent first" });
    }
    verifiedEmails.delete(email);
    await pool.query("UPDATE users SET is_email_verified = true WHERE id = $1", [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Same idea for phone — requires having passed /phone-verify/send +
// /phone-verify/check for that exact number first.
app.patch("/profile/verify-phone", authenticate, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "Missing phone number" });
    const verifiedAt = verifiedPhones.get(phone);
    if (!verifiedAt || Date.now() - verifiedAt > PHONE_VERIFIED_TTL_MS) {
      return res.status(400).json({ error: "Verify the code we sent first" });
    }
    verifiedPhones.delete(phone);
    await pool.query("UPDATE users SET phone = $1, is_phone_verified = true WHERE id = $2", [phone, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit (or resubmit) a seller application. Sets status back to "pending"
// so a previously-rejected member can try again after fixing whatever
// was wrong. bankStatementUrl is optional — a data URL from the frontend's
// file upload, same pattern as license photos.
app.post("/profile/apply-to-sell", authenticate, async (req, res) => {
  try {
    const { bankStatementUrl } = req.body;
    const result = await pool.query(
      `UPDATE users SET
         has_applied_to_sell = true,
         verification_status = 'pending',
         bank_statement_url = COALESCE($1, bank_statement_url),
         rejection_reason = NULL
       WHERE id = $2
       RETURNING ${USER_RETURNING_FIELDS}`,
      [bankStatementUrl || null, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Full member list for the admin dashboard. No password hashes returned.
// Fields visible to everyone — used for storefronts, follower lists, etc.
// Deliberately excludes email, phone, and ID/document fields.
const USER_PUBLIC_FIELDS = `id, username, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, verification_status, created_at,
  avatar_url, store_bio, store_policies`;

// Full fields — only returned to a signed-in admin. bank_statement_url and
// rejection_reason are sensitive/internal, so they stay out of USER_PUBLIC_FIELDS.
const USER_FULL_FIELDS = `id, username, email, phone, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, verification_status,
  bank_statement_url, rejection_reason, created_at, avatar_url, store_bio, store_policies, two_factor_enabled,
  is_email_verified, is_phone_verified`;

app.get("/users", async (req, res) => {
  try {
    const requester = getRequester(req);
    const fields = requester?.isAdmin ? USER_FULL_FIELDS : USER_PUBLIC_FIELDS;
    const result = await pool.query(`SELECT ${fields} FROM users ORDER BY display_name ASC`);
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const USER_RETURNING_FIELDS = `id, username, email, phone, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, verification_status,
  bank_statement_url, rejection_reason, created_at, avatar_url, store_bio, store_policies, two_factor_enabled,
  is_email_verified, is_phone_verified, token_version`;

app.patch("/users/:id/verify", authenticate, requireAdmin, async (req, res) => {
  try {
    const { isVerified } = req.body;
    const result = await pool.query(
      `UPDATE users SET is_verified = $1 WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [!!isVerified, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/users/:id/suspend", authenticate, requireAdmin, async (req, res) => {
  try {
    const { isSuspended } = req.body;
    const result = await pool.query(
      `UPDATE users SET is_suspended = $1 WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [!!isSuspended, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/users/:id/promote", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET is_admin = true WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/users/:id/approve", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET is_approved = true, verification_status = 'approved', rejection_reason = NULL
       WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/users/:id/reject", authenticate, requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const result = await pool.query(
      `UPDATE users SET is_approved = false, verification_status = 'rejected', rejection_reason = $1
       WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [reason || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    createNotification(
      req.params.id,
      "verification_problem",
      `Your seller verification needs attention${reason ? ": " + reason : ""}`
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/users/:id", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true });
  } catch (err) {
    // Postgres foreign-key-violation code — this member has order or
    // withdrawal history that references them, so a hard delete would
    // either fail or destroy financial records other users depend on.
    // Tell the frontend so it can offer suspending instead.
    if (err.code === "23503") {
      return res.status(409).json({
        error: "This member has order or payout history and can't be permanently deleted. Suspend them instead to block access while keeping records intact.",
        code: "HAS_HISTORY",
      });
    }
    res.status(500).json({ error: err.message });
  }
});

// Lets an admin create a real account directly (used by the admin "Add member" tool).
app.post("/admin/create-member", authenticate, requireAdmin, async (req, res) => {
  try {
    const { username, email, phone, password, displayName, isAdmin, isApproved, isVerified } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing username or password" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const approved = isApproved !== false;
    const result = await pool.query(
      `INSERT INTO users (username, email, phone, password_hash, display_name, is_admin, is_approved, is_verified, verification_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING ${USER_RETURNING_FIELDS}`,
      [
        username,
        email || "",
        phone || "",
        passwordHash,
        displayName || username,
        !!isAdmin,
        approved,
        !!isVerified,
        approved ? "approved" : "none",
      ]
    );

    res.status(201).json({ user: result.rows[0], token: signToken(result.rows[0]) });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username, email, or phone already in use" });
    }
    res.status(500).json({ error: err.message });
  }
});

// Follows — who follows whom on seller storefronts.
app.get("/follows", async (req, res) => {
  try {
    const result = await pool.query("SELECT follower_username, followed_username FROM follows");
    res.json({ follows: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/follows", authenticate, async (req, res) => {
  try {
    const followerUsername = req.user.username;
    const { followedUsername } = req.body;
    if (!followedUsername) {
      return res.status(400).json({ error: "Missing followedUsername" });
    }
    await pool.query(
      `INSERT INTO follows (follower_username, followed_username)
       VALUES ($1, $2)
       ON CONFLICT (follower_username, followed_username) DO NOTHING`,
      [followerUsername, followedUsername]
    );
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/follows", authenticate, async (req, res) => {
  try {
    const followerUsername = req.user.username;
    const { followedUsername } = req.body;
    if (!followedUsername) {
      return res.status(400).json({ error: "Missing followedUsername" });
    }
    await pool.query(
      "DELETE FROM follows WHERE follower_username = $1 AND followed_username = $2",
      [followerUsername, followedUsername]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cart and watchlist — always sent/returned as a whole list, matching the
// "replace the whole thing" pattern the frontend already uses.
app.get("/cart", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT listing_id, qty, offer_price FROM cart_items WHERE user_id = $1",
      [req.user.id]
    );
    res.json({ items: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/cart", authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { items } = req.body;
    if (!Array.isArray(items)) return res.status(400).json({ error: "items must be an array" });
    await client.query("BEGIN");
    await client.query("DELETE FROM cart_items WHERE user_id = $1", [req.user.id]);
    for (const item of items) {
      if (!item.listingId || !(Number(item.qty) > 0)) continue;
      await client.query(
        `INSERT INTO cart_items (user_id, listing_id, qty, offer_price)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, listing_id) DO UPDATE SET qty = $3, offer_price = $4`,
        [req.user.id, item.listingId, item.qty, item.offerPrice || null]
      );
    }
    await client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get("/watchlist", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT listing_id FROM watchlist_items WHERE user_id = $1",
      [req.user.id]
    );
    res.json({ listingIds: result.rows.map((r) => r.listing_id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/watchlist", authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { listingIds } = req.body;
    if (!Array.isArray(listingIds)) return res.status(400).json({ error: "listingIds must be an array" });
    await client.query("BEGIN");
    await client.query("DELETE FROM watchlist_items WHERE user_id = $1", [req.user.id]);
    for (const listingId of listingIds) {
      await client.query(
        "INSERT INTO watchlist_items (user_id, listing_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        [req.user.id, listingId]
      );
    }
    await client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post("/login", authRateLimit, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing username or password" });
    }

    const result = await pool.query(
      `SELECT id, username, email, phone, password_hash, display_name, first_name, last_name, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
         license_number, license_photos, id_verification_exempt, created_at, two_factor_enabled, token_version
       FROM users WHERE username = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Username or password doesn't match" });
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({ error: "Username or password doesn't match" });
    }

    if (user.is_suspended) {
      return res.status(403).json({ error: "This account has been suspended" });
    }

    const vpnDetected = await isVpnOrProxy(getClientIp(req));
    if (vpnDetected) {
      return res.status(403).json({ error: "Login isn't allowed over a VPN, proxy, or Tor connection. Please disable it and try again." });
    }

    if (user.two_factor_enabled) {
      if (!user.email) {
        return res.status(400).json({ error: "Two-factor is on but this account has no email on file — contact support." });
      }
      if (!process.env.RESEND_API_KEY) {
        return res.status(500).json({ error: "Two-factor login isn't configured yet" });
      }
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
      const resendRes = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
        body: JSON.stringify({
          from: fromAddress,
          to: [user.email],
          subject: `Your Stallyard login code is ${code}`,
          html: `<p>Your Stallyard login code is <strong>${code}</strong>.</p><p>This code expires in 10 minutes. If this wasn't you, change your password right away.</p>`,
        }),
      });
      if (!resendRes.ok) {
        return res.status(400).json({ error: "Couldn't send your login code — try again" });
      }
      twoFactorCodes.set(user.id, { code, sentAt: Date.now() });
      return res.json({ twoFactorRequired: true, userId: user.id });
    }

    delete user.password_hash;
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    pool
      .query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [user.id, ip, userAgent])
      .catch((err) => console.error("Failed to record login history:", err.message));
    res.json({ user, token: signToken(user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Step 2 of a two-factor login: check the emailed code, then actually
// issue the session token — mirrors what /login does for accounts without
// two-factor turned on, including recording login history.
app.post("/login/verify-2fa", authRateLimit, async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: "Missing userId or code" });
    const stored = twoFactorCodes.get(Number(userId));
    if (!stored || Date.now() - stored.sentAt > TWO_FACTOR_CODE_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — log in again to get a new one" });
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    twoFactorCodes.delete(Number(userId));
    const result = await pool.query(
      `SELECT id, username, email, phone, display_name, first_name, last_name, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
         license_number, license_photos, id_verification_exempt, created_at, token_version
       FROM users WHERE id = $1`,
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const user = result.rows[0];
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    pool
      .query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [user.id, ip, userAgent])
      .catch((err) => console.error("Failed to record login history:", err.message));
    res.json({ user, token: signToken(user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/listings", authenticate, async (req, res) => {
  try {
    const {
      title, description, price, category, condition, shippingFee,
      emoji, fitMake, fitModel, fitYear, images, listingType, currency,
      status, auctionEndTime, quantity, sku, brand, state, shippingMethods,
      returnPolicy, vin,
    } = req.body;
    const ownerId = req.user.id; // always the signed-in user — never trust a client-supplied owner

    if (!title || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // The frontend already hides the listing form until a seller is
    // approved, but that's only a UI convenience — enforce it here too,
    // since nothing stops someone from calling this endpoint directly.
    const sellerCheck = await pool.query("SELECT is_approved FROM users WHERE id = $1", [ownerId]);
    if (!sellerCheck.rows.length || !sellerCheck.rows[0].is_approved) {
      return res.status(403).json({ error: "Your seller account must be approved before you can list items." });
    }

    const result = await pool.query(
      `INSERT INTO listings (
         owner_id, title, description, price, category, condition, shipping_fee,
         emoji, fit_make, fit_model, fit_year, images, listing_type, currency,
         status, auction_end_time, quantity, sku, brand, state, shipping_methods,
         return_policy, vin
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
       RETURNING *`,
      [
        ownerId, title, description || "", price, category || "Other", condition || "New", shippingFee || 0,
        emoji || "📦", fitMake || "", fitModel || "", fitYear || "", JSON.stringify(images || []),
        listingType || "fixed", currency || "USD", status || "pending",
        auctionEndTime ? new Date(auctionEndTime) : null,
        quantity === "" || quantity === undefined || quantity === null ? null : Number(quantity),
        sku || "", brand || "", state || "", JSON.stringify(shippingMethods || []),
        returnPolicy || "", vin || "",
      ]
    );

    res.status(201).json({ listing: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/listings", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT listings.*, users.display_name AS seller_name, users.username AS owner_username
       FROM listings
       JOIN users ON listings.owner_id = users.id
       ORDER BY listings.created_at DESC`
    );
    res.json({ listings: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generic partial update — covers editing, admin approve/remove, feature toggle,
// and auction bid updates, all through one whitelisted column map.
const LISTING_FIELD_MAP = {
  title: "title",
  description: "description",
  price: "price",
  category: "category",
  condition: "condition",
  shippingFee: "shipping_fee",
  emoji: "emoji",
  fitMake: "fit_make",
  fitModel: "fit_model",
  fitYear: "fit_year",
  images: "images",
  listingType: "listing_type",
  currency: "currency",
  status: "status",
  isFeatured: "is_featured",
  auctionEndTime: "auction_end_time",
  bidHistory: "bid_history",
  highestBidderUsername: "highest_bidder_username",
  quantity: "quantity",
  sku: "sku",
  brand: "brand",
  state: "state",
  shippingMethods: "shipping_methods",
  returnPolicy: "return_policy",
  vin: "vin",
};
const LISTING_JSON_FIELDS = new Set(["images", "bidHistory", "shippingMethods"]);

app.patch("/listings/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT owner_id FROM listings WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Listing not found" });
    if (!req.user.isAdmin && existing.rows[0].owner_id !== req.user.id) {
      return res.status(403).json({ error: "You can only edit your own listings" });
    }
    const sets = [];
    const values = [];
    let i = 1;
    for (const [key, column] of Object.entries(LISTING_FIELD_MAP)) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        sets.push(`${column} = $${i}`);
        const raw = req.body[key];
        if (key === "quantity") {
          values.push(raw === "" || raw === undefined || raw === null ? null : Number(raw));
        } else {
          values.push(LISTING_JSON_FIELDS.has(key) ? JSON.stringify(raw) : raw);
        }
        i++;
      }
    }
    if (sets.length === 0) {
      return res.status(400).json({ error: "No valid fields to update" });
    }
    values.push(req.params.id);
    const result = await pool.query(
      `UPDATE listings SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Listing not found" });
    if (req.body.status === "rejected") {
      createNotification(existing.rows[0].owner_id, "listing_rejected", `Your listing "${result.rows[0].title}" was rejected`);
    }
    res.json({ listing: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/listings/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT owner_id FROM listings WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Listing not found" });
    if (!req.user.isAdmin && existing.rows[0].owner_id !== req.user.id) {
      return res.status(403).json({ error: "You can only remove your own listings" });
    }
    const result = await pool.query("DELETE FROM listings WHERE id = $1 RETURNING id", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Listing not found" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/listings/by-owner/:ownerId", authenticate, requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM listings WHERE owner_id = $1", [req.params.ownerId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
const PLATFORM_COMMISSION_RATE = 0.05;

// Real cart checkout — recomputes every price server-side from the live
// listings table rather than trusting whatever the cart claims, and creates
// one order with one order_items row per cart line, grouped by seller.
app.post("/checkout", authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { items, shippingAddress, currency } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Cart is empty" });
    }

    await client.query("BEGIN");

    let subtotal = 0;
    let shippingTotal = 0;
    const resolvedItems = [];

    for (const cartItem of items) {
      const qty = Number(cartItem.qty);
      if (!cartItem.listingId || !Number.isInteger(qty) || qty <= 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Each cart item needs a valid listingId and a positive quantity" });
      }

      const listingResult = await client.query(
        "SELECT * FROM listings WHERE id = $1 AND status = 'approved' FOR UPDATE",
        [cartItem.listingId]
      );
      if (listingResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: `Listing ${cartItem.listingId} isn't available` });
      }
      const listing = listingResult.rows[0];
      const price = Number(listing.price);
      const shippingFee = Number(listing.shipping_fee) || 0;
      if (!(price > 0)) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Listing has an invalid price" });
      }

      subtotal += price * qty;
      shippingTotal += shippingFee * qty;
      resolvedItems.push({ listing, qty, price, shippingFee });
    }

    const commissionRate = PLATFORM_COMMISSION_RATE;
    const commissionAmount = Math.round(subtotal * commissionRate * 100) / 100;
    const total = Math.round((subtotal + shippingTotal) * 100) / 100;

    const orderResult = await client.query(
      `INSERT INTO orders (
         buyer_id, buyer_username, total, currency, shipping_address, subtotal,
         shipping_total, commission_rate, commission_amount, payment_status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'held')
       RETURNING *`,
      [
        req.user.id, req.user.username, total, currency || "USD",
        JSON.stringify(shippingAddress || {}), subtotal, shippingTotal,
        commissionRate, commissionAmount,
      ]
    );
    const order = orderResult.rows[0];

    const insertedItems = [];
    for (const { listing, qty, price, shippingFee } of resolvedItems) {
      const sellerResult = await client.query("SELECT username, display_name FROM users WHERE id = $1", [listing.owner_id]);
      const seller = sellerResult.rows[0];
      const itemResult = await client.query(
        `INSERT INTO order_items (
           order_id, listing_id, title, emoji, price, qty, shipping_fee,
           seller_id, seller_username, seller_name, fulfillment_status
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'new')
         RETURNING *`,
        [
          order.id, listing.id, listing.title, listing.emoji, price, qty, shippingFee,
          listing.owner_id, seller?.username, seller?.display_name,
        ]
      );
      insertedItems.push(itemResult.rows[0]);
      await client.query("UPDATE listings SET status = 'sold' WHERE id = $1", [listing.id]);
      createNotification(
        listing.owner_id,
        "sale",
        `New sale: ${listing.title} (${qty}x) — $${(price * qty).toFixed(2)}. Payment is held until delivery is confirmed.`
      );
    }

    await client.query("COMMIT");
    res.status(201).json({ order: { ...order, items: insertedItems } });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

async function fetchOrdersWithItems(whereClause, params) {
  const ordersResult = await pool.query(
    `SELECT * FROM orders WHERE ${whereClause} ORDER BY created_at DESC`,
    params
  );
  const orders = ordersResult.rows;
  if (orders.length === 0) return [];
  const orderIds = orders.map((o) => o.id);
  const itemsResult = await pool.query(
    `SELECT * FROM order_items WHERE order_id = ANY($1) ORDER BY id ASC`,
    [orderIds]
  );
  return orders.map((o) => ({
    ...o,
    items: itemsResult.rows.filter((i) => i.order_id === o.id),
  }));
}

// A buyer's own purchase history.
app.get("/orders/mine", authenticate, async (req, res) => {
  try {
    const orders = await fetchOrdersWithItems("buyer_id = $1", [req.user.id]);
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// A seller's own sales — orders containing at least one of their items.
app.get("/orders/selling", authenticate, async (req, res) => {
  try {
    const orders = await fetchOrdersWithItems(
      "id IN (SELECT order_id FROM order_items WHERE seller_id = $1)",
      [req.user.id]
    );
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin view of every order.
app.get("/orders", authenticate, requireAdmin, async (req, res) => {
  try {
    const orders = await fetchOrdersWithItems("TRUE", []);
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/orders/:id/release", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE orders SET payment_status = 'released' WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Order not found" });
    const sellerIds = await pool.query(
      "SELECT DISTINCT seller_id FROM order_items WHERE order_id = $1",
      [req.params.id]
    );
    for (const row of sellerIds.rows) {
      createNotification(row.seller_id, "funds_released", "Funds released for order — payment is now in your available balance.");
    }
    res.json({ order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/orders/:id/refund", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE orders SET payment_status = 'refunded' WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Order not found" });
    res.json({ order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/orders/:id/dispute", authenticate, async (req, res) => {
  try {
    const { isDisputed } = req.body;
    const orderCheck = await pool.query("SELECT buyer_id FROM orders WHERE id = $1", [req.params.id]);
    if (orderCheck.rows.length === 0) return res.status(404).json({ error: "Order not found" });
    if (!req.user.isAdmin && orderCheck.rows[0].buyer_id !== req.user.id) {
      const sellerCheck = await pool.query(
        "SELECT 1 FROM order_items WHERE order_id = $1 AND seller_id = $2 LIMIT 1",
        [req.params.id, req.user.id]
      );
      if (sellerCheck.rows.length === 0) {
        return res.status(403).json({ error: "You can only dispute orders you're part of" });
      }
    }
    const result = await pool.query(
      "UPDATE orders SET is_disputed = $1 WHERE id = $2 RETURNING *",
      [!!isDisputed, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Order not found" });
    if (isDisputed) {
      const sellerIds = await pool.query(
        "SELECT DISTINCT seller_id FROM order_items WHERE order_id = $1",
        [req.params.id]
      );
      for (const row of sellerIds.rows) {
        createNotification(row.seller_id, "dispute_opened", "A dispute was opened on one of your orders.");
      }
    }
    res.json({ order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const ORDER_ITEM_STATUSES = new Set(["new", "preparing", "shipped", "delivered", "cancelled", "returned"]);

// Update one item's fulfillment status/tracking/carrier — only that item's seller or an admin.
app.patch("/order-items/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT seller_id FROM order_items WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    if (!req.user.isAdmin && existing.rows[0].seller_id !== req.user.id) {
      return res.status(403).json({ error: "You can only update your own items" });
    }
    const { fulfillmentStatus, trackingNumber, carrier, proofOfDeliveryUrl } = req.body;
    if (fulfillmentStatus && !ORDER_ITEM_STATUSES.has(fulfillmentStatus)) {
      return res.status(400).json({ error: "Invalid fulfillment status" });
    }
    const sets = [];
    const values = [];
    let i = 1;
    if (fulfillmentStatus) {
      sets.push(`fulfillment_status = $${i++}`);
      values.push(fulfillmentStatus);
      if (fulfillmentStatus === "shipped") {
        // Only set the first time — re-saving other fields shouldn't reset
        // the on-time-shipping clock.
        sets.push(`shipped_at = COALESCE(shipped_at, NOW())`);
      }
    }
    if (typeof trackingNumber === "string") {
      sets.push(`tracking_number = $${i++}`);
      values.push(trackingNumber);
    }
    if (typeof carrier === "string") {
      sets.push(`carrier = $${i++}`);
      values.push(carrier);
    }
    if (typeof proofOfDeliveryUrl === "string") {
      sets.push(`proof_of_delivery_url = $${i++}`);
      values.push(proofOfDeliveryUrl);
    }
    if (sets.length === 0) return res.status(400).json({ error: "No valid fields to update" });
    values.push(req.params.id);
    const result = await pool.query(
      `UPDATE order_items SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
      values
    );
    res.json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buyer confirms they received an item. Only the order's buyer can do this,
// and only once the seller has actually marked it shipped or delivered.
// Once every non-cancelled/non-returned item in the order is confirmed,
// the order's held payment auto-releases to the seller(s) — the same
// status flip the "Release payout" admin action performs.
// Shared by both the buyer's direct "Confirm receipt" click and a seller
// redeeming a buyer-given delivery token: marks one item as buyer-confirmed,
// then — once every non-cancelled/non-returned item in the order is
// confirmed — auto-releases the order's held payment, the same status flip
// the "Release payout" admin action performs.
async function markItemReceivedAndMaybeRelease(itemId) {
  const result = await pool.query(
    "UPDATE order_items SET buyer_confirmed_at = NOW(), delivery_token = NULL, delivery_token_generated_at = NULL WHERE id = $1 RETURNING *",
    [itemId]
  );
  const item = result.rows[0];
  createNotification(item.seller_id, "delivery_confirmed", `Buyer confirmed delivery for "${item.title}"`);
  const allItems = await pool.query("SELECT * FROM order_items WHERE order_id = $1", [item.order_id]);
  const relevant = allItems.rows.filter((r) => !["cancelled", "returned"].includes(r.fulfillment_status));
  const allConfirmed = relevant.length > 0 && relevant.every((r) => r.buyer_confirmed_at);
  let order = null;
  if (allConfirmed) {
    const orderRes = await pool.query(
      "UPDATE orders SET payment_status = 'released' WHERE id = $1 AND payment_status = 'held' RETURNING *",
      [item.order_id]
    );
    order = orderRes.rows[0] || null;
    if (order) {
      const sellerIds = [...new Set(relevant.map((r) => r.seller_id))];
      for (const sellerId of sellerIds) {
        createNotification(sellerId, "funds_released", `Funds released for order — payment is now in your available balance.`);
      }
    }
  }
  return { item, order };
}

// Buyer confirms they received an item. Only the order's buyer can do this,
// and only once the seller has actually marked it shipped or delivered.
app.patch("/order-items/:id/confirm-receipt", authenticate, async (req, res) => {
  try {
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id, o.payment_status
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can confirm receipt of this item" });
    }
    if (!["shipped", "delivered"].includes(item.fulfillment_status)) {
      return res.status(400).json({ error: "This item hasn't been shipped yet" });
    }
    const { item: updatedItem, order } = await markItemReceivedAndMaybeRelease(req.params.id);
    res.json({ item: updatedItem, order });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buyer requests a return on a shipped/delivered item, with a reason,
// optional note, and optional photo evidence (data URLs, same pattern as
// bank statements and proof-of-delivery photos elsewhere in the app).
app.post("/order-items/:id/request-return", authenticate, async (req, res) => {
  try {
    const { reason, note, evidenceUrls } = req.body;
    if (!reason) return res.status(400).json({ error: "Pick a reason for the return" });
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can request a return on this item" });
    }
    if (!["shipped", "delivered"].includes(item.fulfillment_status)) {
      return res.status(400).json({ error: "This item hasn't been shipped yet" });
    }
    if (item.return_status === "requested" || item.return_status === "approved") {
      return res.status(400).json({ error: "A return is already in progress for this item" });
    }
    const result = await pool.query(
      `UPDATE order_items SET
         return_status = 'requested', return_reason = $1, return_note = $2,
         return_requested_at = NOW(), return_evidence_urls = $3,
         return_tracking_number = NULL
       WHERE id = $4 RETURNING *`,
      [reason, note || "", JSON.stringify(evidenceUrls || []), req.params.id]
    );
    createNotification(item.seller_id, "return_opened", `Return requested for "${item.title}" — ${reason}`);
    res.json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Seller (or admin) accepts or denies a pending return request.
app.patch("/order-items/:id/return-response", authenticate, async (req, res) => {
  try {
    const { decision } = req.body;
    if (!["approved", "denied"].includes(decision)) {
      return res.status(400).json({ error: "Invalid decision" });
    }
    const existing = await pool.query("SELECT * FROM order_items WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (!req.user.isAdmin && item.seller_id !== req.user.id) {
      return res.status(403).json({ error: "You can only respond to returns on your own items" });
    }
    if (item.return_status !== "requested") {
      return res.status(400).json({ error: "This item doesn't have a pending return request" });
    }
    const result =
      decision === "approved"
        ? await pool.query(
            `UPDATE order_items SET return_status = 'approved', fulfillment_status = 'returned' WHERE id = $1 RETURNING *`,
            [req.params.id]
          )
        : await pool.query(`UPDATE order_items SET return_status = 'denied' WHERE id = $1 RETURNING *`, [req.params.id]);
    res.json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buyer adds tracking for shipping the item back, once their return's approved.
app.patch("/order-items/:id/return-tracking", authenticate, async (req, res) => {
  try {
    const { trackingNumber } = req.body;
    if (typeof trackingNumber !== "string") return res.status(400).json({ error: "Missing tracking number" });
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can add return tracking" });
    }
    if (item.return_status !== "approved") {
      return res.status(400).json({ error: "This item's return hasn't been approved yet" });
    }
    const result = await pool.query(
      "UPDATE order_items SET return_tracking_number = $1 WHERE id = $2 RETURNING *",
      [trackingNumber, req.params.id]
    );
    res.json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const DELIVERY_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Buyer generates a 10-digit code to hand to the seller in person as proof
// of a successful delivery — an alternative to tapping "Confirm receipt"
// themselves, useful for cash-on-delivery or in-person handoffs. Only the
// order's buyer can generate one, and only once the item's shipped.
app.post("/order-items/:id/generate-delivery-token", authenticate, async (req, res) => {
  try {
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can generate a delivery code for this item" });
    }
    if (!["shipped", "delivered"].includes(item.fulfillment_status)) {
      return res.status(400).json({ error: "This item hasn't been shipped yet" });
    }
    if (item.buyer_confirmed_at) {
      return res.status(400).json({ error: "This item has already been confirmed as received" });
    }
    const token = Math.floor(1000000000 + Math.random() * 9000000000).toString();
    await pool.query(
      "UPDATE order_items SET delivery_token = $1, delivery_token_generated_at = NOW() WHERE id = $2",
      [token, req.params.id]
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Seller enters the code the buyer gave them. On a match, this confirms
// receipt exactly like the buyer clicking "Confirm receipt" themselves —
// same auto-release-payment behavior — since the buyer generating and
// handing over the code IS their confirmation.
app.post("/order-items/:id/redeem-delivery-token", authenticate, codeRateLimit, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Enter the code the buyer gave you" });
    const existing = await pool.query("SELECT * FROM order_items WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (!req.user.isAdmin && item.seller_id !== req.user.id) {
      return res.status(403).json({ error: "You can only redeem codes for your own items" });
    }
    if (
      !item.delivery_token ||
      !item.delivery_token_generated_at ||
      Date.now() - new Date(item.delivery_token_generated_at).getTime() > DELIVERY_TOKEN_TTL_MS
    ) {
      return res.status(400).json({ error: "No active code for this item — ask the buyer to generate a new one" });
    }
    if (item.delivery_token !== String(token).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    const { item: updatedItem, order } = await markItemReceivedAndMaybeRelease(req.params.id);
    res.json({ item: updatedItem, order });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Pre-existing single-listing Paystack payment page flow (initiate → buyer pays
// on Paystack's hosted page → webhook below confirms and creates the order).
// Kept under its own path since /checkout is now the real cart-checkout endpoint.
app.post("/checkout/single-item-payment", authenticate, async (req, res) => {
  try {
    const { listingId, email } = req.body;

    if (!listingId || !email) {
      return res.status(400).json({ error: "Missing listingId or email" });
    }

    const listingResult = await pool.query(
      "SELECT * FROM listings WHERE id = $1 AND status != 'sold'",
      [listingId]
    );

    if (listingResult.rows.length === 0) {
      return res.status(404).json({ error: "Listing not found or already sold" });
    }

    const listing = listingResult.rows[0];
    const amountInKobo = Math.round(Number(listing.price) * 100);

    const paystackRes = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        amount: amountInKobo,
        metadata: { buyerId: req.user.id, listingId },
      }),
    });

    const paystackData = await paystackRes.json();

    if (!paystackData.status) {
      return res.status(500).json({ error: paystackData.message || "Paystack error" });
    }

    res.json({
      authorizationUrl: paystackData.data.authorization_url,
      reference: paystackData.data.reference,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
const crypto = require("crypto");

app.post("/webhook/paystack", async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"] || "";
    const expectedSignature = crypto
      .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
      .update(req.rawBody)
      .digest("hex");

    const signatureBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSignature);
    const validSignature =
      signatureBuf.length === expectedBuf.length && crypto.timingSafeEqual(signatureBuf, expectedBuf);
    if (!validSignature) {
      return res.status(401).send("Invalid signature");
    }

    const event = req.body;

    if (event.event === "charge.success") {
      const { buyerId, listingId } = event.data.metadata;
      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const listingResult = await client.query(
          "SELECT * FROM listings WHERE id = $1 AND status != 'sold'",
          [listingId]
        );

        if (listingResult.rows.length > 0) {
          const listing = listingResult.rows[0];

          await client.query(
            `INSERT INTO orders (buyer_id, total, currency, payment_status)
             VALUES ($1, $2, $3, 'released')`,
            [buyerId, listing.price, listing.currency]
          );

          await client.query(
            "UPDATE listings SET status = 'sold' WHERE id = $1",
            [listingId]
          );
        }

        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        console.error("Webhook processing error:", err.message);
      } finally {
        client.release();
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err.message);
    res.sendStatus(500);
  }
});
// Proxies Paystack's bank list so the frontend can show a dropdown instead of
// asking sellers to type a bank code by hand (typos there would silently fail).
app.get("/paystack/banks", authenticate, async (req, res) => {
  try {
    const banksRes = await fetch("https://api.paystack.co/bank?country=nigeria", {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });
    const banksData = await banksRes.json();
    if (!banksData.status) {
      return res.status(500).json({ error: banksData.message || "Couldn't load bank list" });
    }
    res.json({ banks: banksData.data.map((b) => ({ name: b.name, code: b.code })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Shared by both first-time setup (saves immediately) and a confirmed
// bank-account change (after the email code is verified) — actually
// creates the Paystack transfer recipient and saves it.
async function verifyAndSaveBankDetails(userId, bankCode, accountNumber) {
  const userResult = await pool.query("SELECT display_name FROM users WHERE id = $1", [userId]);
  if (userResult.rows.length === 0) {
    return { error: "User not found", status: 404 };
  }
  const recipientRes = await fetch("https://api.paystack.co/transferrecipient", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      type: "nuban",
      name: userResult.rows[0].display_name,
      account_number: accountNumber,
      bank_code: bankCode,
      currency: "NGN",
    }),
  });
  const recipientData = await recipientRes.json();
  if (!recipientData.status) {
    return { error: recipientData.message || "Could not verify bank details", status: 400 };
  }
  await pool.query(
    "UPDATE users SET bank_code = $1, account_number = $2, paystack_recipient_code = $3 WHERE id = $4",
    [bankCode, accountNumber, recipientData.data.recipient_code, userId]
  );
  return { recipientCode: recipientData.data.recipient_code };
}

app.post("/sellers/bank-details", authenticate, async (req, res) => {
  try {
    const { userId, bankCode, accountNumber } = req.body;

    if (!userId || !bankCode || !accountNumber) {
      return res.status(400).json({ error: "Missing userId, bankCode, or accountNumber" });
    }
    if (req.user.id !== Number(userId) && !req.user.isAdmin) {
      return res.status(403).json({ error: "You can only set your own bank details" });
    }

    // First-time setup saves immediately. Changing an account that's
    // already on file needs an emailed confirmation first — protects
    // against payouts getting silently redirected if a session's ever
    // compromised.
    const existing = await pool.query("SELECT account_number, email FROM users WHERE id = $1", [userId]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const hadAccountBefore = !!existing.rows[0].account_number;

    if (!hadAccountBefore || (req.user.isAdmin && req.user.id !== Number(userId))) {
      const result = await verifyAndSaveBankDetails(userId, bankCode, accountNumber);
      if (result.error) return res.status(result.status).json({ error: result.error });
      return res.json({ success: true, recipientCode: result.recipientCode });
    }

    const email = existing.rows[0].email;
    if (!email) {
      return res.status(400).json({ error: "No email on file to confirm this change — contact support" });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Bank-change confirmation isn't configured yet" });
    }
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress,
        to: [email],
        subject: `Confirm your bank account change — code ${code}`,
        html: `<p>Someone (hopefully you) is changing the bank account your Stallyard payouts go to.</p><p>Your confirmation code is <strong>${code}</strong>. It expires in 15 minutes.</p><p>If this wasn't you, change your password immediately and contact support.</p>`,
      }),
    });
    if (!resendRes.ok) {
      return res.status(400).json({ error: "Couldn't send a confirmation code — try again" });
    }
    pendingBankChanges.set(Number(userId), { code, sentAt: Date.now(), bankCode, accountNumber });
    res.json({ confirmationRequired: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/sellers/bank-details/confirm", authenticate, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Enter the code we emailed you" });
    const pending = pendingBankChanges.get(req.user.id);
    if (!pending || Date.now() - pending.sentAt > BANK_CHANGE_CODE_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — start the change again" });
    }
    if (pending.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    pendingBankChanges.delete(req.user.id);
    const result = await verifyAndSaveBankDetails(req.user.id, pending.bankCode, pending.accountNumber);
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json({ success: true, recipientCode: result.recipientCode });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Shared helper — actually moves money via Paystack. Used by both the
// automatic withdrawal flow and the admin manual-override endpoint below.
async function sendPaystackTransfer(recipientCode, amountInKobo, reason) {
  const transferRes = await fetch("https://api.paystack.co/transfer", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      source: "balance",
      amount: amountInKobo,
      recipient: recipientCode,
      reason: reason || "Stallyard seller payout",
    }),
  });
  return transferRes.json();
}

// Admin-only manual override — the normal path for sellers is POST /withdrawals,
// which validates their real balance server-side before calling the same
// transfer logic. This endpoint bypasses that balance check, so it's admin-only.
app.post("/sellers/payout", authenticate, requireAdmin, async (req, res) => {
  try {
    const { userId, amount, reason } = req.body;

    if (!userId || !(Number(amount) > 0)) {
      return res.status(400).json({ error: "Missing userId or amount must be a positive number" });
    }

    const userResult = await pool.query(
      "SELECT paystack_recipient_code FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0 || !userResult.rows[0].paystack_recipient_code) {
      return res.status(400).json({ error: "This seller hasn't added bank details yet" });
    }

    const recipientCode = userResult.rows[0].paystack_recipient_code;
    const amountInKobo = Math.round(Number(amount) * 100);
    const transferData = await sendPaystackTransfer(recipientCode, amountInKobo, reason);

    if (!transferData.status) {
      return res.status(400).json({ error: transferData.message || "Payout failed" });
    }

    res.json({ success: true, transfer: transferData.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// A seller's true available balance, computed entirely from real order data —
// released order items, minus commission, minus anything already withdrawn
// or currently mid-withdrawal. Never trusts a client-supplied number.
async function computeAvailableBalance(client, sellerId) {
  const releasedResult = await client.query(
    `SELECT COALESCE(SUM(
       CASE WHEN oi.fulfillment_status NOT IN ('cancelled', 'returned')
         THEN (oi.price * oi.qty) - (oi.price * oi.qty * o.commission_rate) + oi.shipping_fee
         ELSE 0
       END
     ), 0) AS released_total
     FROM order_items oi
     JOIN orders o ON oi.order_id = o.id
     WHERE oi.seller_id = $1 AND o.payment_status = 'released'`,
    [sellerId]
  );
  const reservedResult = await client.query(
    `SELECT COALESCE(SUM(amount), 0) AS reserved
     FROM withdrawals WHERE seller_id = $1 AND status IN ('processing', 'paid')`,
    [sellerId]
  );
  const released = Number(releasedResult.rows[0].released_total);
  const reserved = Number(reservedResult.rows[0].reserved);
  return Math.round((released - reserved) * 100) / 100;
}

// Sellers request their own withdrawal — no admin approval step. The balance
// check and the reservation happen in one locked transaction so two requests
// fired at once can't both succeed against the same money.
app.post("/withdrawals", authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const amount = Math.round(Number(req.body.amount) * 100) / 100;
    if (!(amount > 0)) {
      return res.status(400).json({ error: "Amount must be a positive number" });
    }

    await client.query("BEGIN");
    // Locks this seller's row for the duration of the transaction, so a
    // second concurrent request from the same seller has to wait its turn.
    await client.query("SELECT id, paystack_recipient_code FROM users WHERE id = $1 FOR UPDATE", [req.user.id]);

    const available = await computeAvailableBalance(client, req.user.id);
    if (amount > available) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: `You can't withdraw more than your available balance of $${available.toFixed(2)}` });
    }

    const userResult = await client.query("SELECT paystack_recipient_code FROM users WHERE id = $1", [req.user.id]);
    const recipientCode = userResult.rows[0]?.paystack_recipient_code;
    if (!recipientCode) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Add your bank details before requesting a withdrawal" });
    }

    const withdrawalResult = await client.query(
      `INSERT INTO withdrawals (seller_id, seller_username, amount, status)
       VALUES ($1, $2, $3, 'processing') RETURNING *`,
      [req.user.id, req.user.username, amount]
    );
    const withdrawal = withdrawalResult.rows[0];
    await client.query("COMMIT");

    // Money actually moves here, outside the DB transaction so the external
    // network call doesn't hold a lock open.
    try {
      const transferData = await sendPaystackTransfer(recipientCode, Math.round(amount * 100), "Stallyard seller withdrawal");
      if (transferData.status) {
        const updated = await pool.query(
          `UPDATE withdrawals SET status = 'paid', processed_at = NOW(), paystack_transfer_code = $1 WHERE id = $2 RETURNING *`,
          [transferData.data?.transfer_code || null, withdrawal.id]
        );
        createNotification(req.user.id, "payout_completed", `Payout of $${amount.toFixed(2)} completed`);
        return res.status(201).json({ withdrawal: updated.rows[0] });
      }
      const failed = await pool.query(
        `UPDATE withdrawals SET status = 'failed', processed_at = NOW(), failure_reason = $1 WHERE id = $2 RETURNING *`,
        [transferData.message || "Payout failed", withdrawal.id]
      );
      return res.status(400).json({ error: transferData.message || "Payout failed", withdrawal: failed.rows[0] });
    } catch (transferErr) {
      const failed = await pool.query(
        `UPDATE withdrawals SET status = 'failed', processed_at = NOW(), failure_reason = $1 WHERE id = $2 RETURNING *`,
        [transferErr.message, withdrawal.id]
      );
      return res.status(500).json({ error: "Payout failed — try again shortly", withdrawal: failed.rows[0] });
    }
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get("/withdrawals/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM withdrawals WHERE seller_id = $1 ORDER BY requested_at DESC",
      [req.user.id]
    );
    res.json({ withdrawals: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/withdrawals", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM withdrawals ORDER BY requested_at DESC");
    res.json({ withdrawals: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/wallet/balance", authenticate, async (req, res) => {
  try {
    const available = await computeAvailableBalance(pool, req.user.id);
    res.json({ available });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/threads", authenticate, async (req, res) => {
  try {
    const { listingId, buyerId, sellerId } = req.body;

    if (!listingId || !buyerId || !sellerId) {
      return res.status(400).json({ error: "Missing listingId, buyerId, or sellerId" });
    }
    if (req.user.id !== Number(buyerId) && req.user.id !== Number(sellerId)) {
      return res.status(403).json({ error: "You can only start a thread you're a part of" });
    }

    const existing = await pool.query(
      "SELECT * FROM threads WHERE listing_id = $1 AND buyer_id = $2 AND seller_id = $3",
      [listingId, buyerId, sellerId]
    );

    if (existing.rows.length > 0) {
      return res.json({ thread: existing.rows[0] });
    }

    const result = await pool.query(
      "INSERT INTO threads (listing_id, buyer_id, seller_id) VALUES ($1, $2, $3) RETURNING *",
      [listingId, buyerId, sellerId]
    );

    res.status(201).json({ thread: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/threads/:userId", authenticate, async (req, res) => {
  try {
    if (req.user.id !== Number(req.params.userId) && !req.user.isAdmin) {
      return res.status(403).json({ error: "You can only view your own threads" });
    }
    const result = await pool.query(
      "SELECT * FROM threads WHERE buyer_id = $1 OR seller_id = $1 ORDER BY created_at DESC",
      [req.params.userId]
    );
    res.json({ threads: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/messages", authenticate, async (req, res) => {
  try {
    const { threadId, body, messageType, offerAmount, imageUrl, orderId } = req.body;
    const senderId = req.user.id; // never trust a client-supplied sender

    if (!threadId) {
      return res.status(400).json({ error: "Missing threadId" });
    }
    const thread = await pool.query("SELECT buyer_id, seller_id FROM threads WHERE id = $1", [threadId]);
    if (thread.rows.length === 0) return res.status(404).json({ error: "Thread not found" });
    if (thread.rows[0].buyer_id !== senderId && thread.rows[0].seller_id !== senderId) {
      return res.status(403).json({ error: "You're not a part of this thread" });
    }

    const result = await pool.query(
      `INSERT INTO messages (thread_id, sender_id, message_type, body, offer_amount, offer_status, image_url, order_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        threadId,
        senderId,
        messageType || "text",
        body || "",
        offerAmount || null,
        messageType === "offer" ? "pending" : null,
        imageUrl || null,
        orderId || null,
      ]
    );

    res.status(201).json({ message: result.rows[0] });

    try {
      const recipientId = senderId === thread.rows[0].buyer_id ? thread.rows[0].seller_id : thread.rows[0].buyer_id;
      const senderInfo = await pool.query("SELECT display_name FROM users WHERE id = $1", [senderId]);
      createNotification(recipientId, "message", `New message from ${senderInfo.rows[0]?.display_name || "a buyer"}`);
    } catch (notifyErr) {
      console.error("Failed to notify about new message:", notifyErr.message);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/messages/:threadId", authenticate, async (req, res) => {
  try {
    const thread = await pool.query("SELECT buyer_id, seller_id FROM threads WHERE id = $1", [req.params.threadId]);
    if (thread.rows.length === 0) return res.status(404).json({ error: "Thread not found" });
    if (thread.rows[0].buyer_id !== req.user.id && thread.rows[0].seller_id !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: "You're not a part of this thread" });
    }
    const result = await pool.query(
      "SELECT * FROM messages WHERE thread_id = $1 ORDER BY created_at ASC",
      [req.params.threadId]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Accept or decline an offer — only the person who *received* it (not the
// one who sent it) can respond.
app.patch("/messages/:id/offer", authenticate, async (req, res) => {
  try {
    const { status } = req.body;
    if (!["accepted", "declined"].includes(status)) {
      return res.status(400).json({ error: "Status must be accepted or declined" });
    }
    const msgResult = await pool.query(
      "SELECT thread_id, sender_id, message_type FROM messages WHERE id = $1",
      [req.params.id]
    );
    if (msgResult.rows.length === 0) return res.status(404).json({ error: "Message not found" });
    const msg = msgResult.rows[0];
    if (msg.message_type !== "offer") return res.status(400).json({ error: "That message isn't an offer" });

    const threadResult = await pool.query("SELECT buyer_id, seller_id FROM threads WHERE id = $1", [msg.thread_id]);
    if (threadResult.rows.length === 0) return res.status(404).json({ error: "Thread not found" });
    const thread = threadResult.rows[0];
    const recipientId = msg.sender_id === thread.buyer_id ? thread.seller_id : thread.buyer_id;
    if (req.user.id !== recipientId && !req.user.isAdmin) {
      return res.status(403).json({ error: "Only the offer recipient can respond to it" });
    }

    const result = await pool.query(
      "UPDATE messages SET offer_status = $1 WHERE id = $2 RETURNING *",
      [status, req.params.id]
    );
    res.json({ message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// A buyer or seller reports a specific message as inappropriate. Only
// someone actually in that thread can report it — prevents a stranger
// from spamming reports on messages they were never party to.
app.post("/messages/:id/report", authenticate, async (req, res) => {
  try {
    const { reason } = req.body;
    const msgResult = await pool.query("SELECT thread_id FROM messages WHERE id = $1", [req.params.id]);
    if (msgResult.rows.length === 0) return res.status(404).json({ error: "Message not found" });
    const threadId = msgResult.rows[0].thread_id;
    const threadResult = await pool.query("SELECT buyer_id, seller_id FROM threads WHERE id = $1", [threadId]);
    if (threadResult.rows.length === 0) return res.status(404).json({ error: "Thread not found" });
    const thread = threadResult.rows[0];
    if (req.user.id !== thread.buyer_id && req.user.id !== thread.seller_id && !req.user.isAdmin) {
      return res.status(403).json({ error: "You're not a part of this conversation" });
    }
    const result = await pool.query(
      `INSERT INTO message_reports (message_id, thread_id, reporter_id, reason)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, threadId, req.user.id, reason || ""]
    );
    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin queue of reported messages — joined with the message body/image,
// who sent it, who reported it, and which listing the thread is about.
app.get("/message-reports", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mr.*,
         m.body AS message_body, m.image_url AS message_image_url, m.sender_id AS message_sender_id,
         sender.username AS sender_username, sender.display_name AS sender_display_name,
         reporter.username AS reporter_username, reporter.display_name AS reporter_display_name,
         t.listing_id, l.title AS listing_title
       FROM message_reports mr
       JOIN messages m ON mr.message_id = m.id
       JOIN threads t ON mr.thread_id = t.id
       LEFT JOIN users sender ON m.sender_id = sender.id
       LEFT JOIN users reporter ON mr.reporter_id = reporter.id
       LEFT JOIN listings l ON t.listing_id = l.id
       ORDER BY mr.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/message-reports/:id/resolve", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE message_reports SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json({ report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// All reviews, public — used to compute seller ratings across the whole app.
app.get("/reviews", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM reviews ORDER BY created_at DESC");
    res.json({ reviews: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/reviews", authenticate, async (req, res) => {
  try {
    const { orderId, listingId, sellerId, rating, comment } = req.body;
    const buyerId = req.user.id; // never trust a client-supplied reviewer identity

    if (!orderId || !listingId || !sellerId || !rating) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
    }

    // A review is only allowed if this buyer actually bought this exact item,
    // from this seller, in this order — no reviewing things you never bought.
    const purchase = await pool.query(
      `SELECT 1 FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       WHERE o.id = $1 AND o.buyer_id = $2 AND oi.listing_id = $3 AND oi.seller_id = $4`,
      [orderId, buyerId, listingId, sellerId]
    );
    if (purchase.rows.length === 0) {
      return res.status(403).json({ error: "You can only review items you've actually purchased" });
    }

    const existing = await pool.query(
      "SELECT 1 FROM reviews WHERE order_id = $1 AND listing_id = $2 AND buyer_id = $3",
      [orderId, listingId, buyerId]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "You've already reviewed this item" });
    }

    const result = await pool.query(
      `INSERT INTO reviews (order_id, listing_id, buyer_id, seller_id, rating, comment)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [orderId, listingId, buyerId, sellerId, rating, comment || null]
    );

    res.status(201).json({ review: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/reviews/:id", authenticate, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    if (rating != null && (rating < 1 || rating > 5)) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
    }
    const existing = await pool.query("SELECT buyer_id FROM reviews WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Review not found" });
    if (existing.rows[0].buyer_id !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: "You can only edit your own review" });
    }
    const result = await pool.query(
      "UPDATE reviews SET rating = COALESCE($1, rating), comment = COALESCE($2, comment) WHERE id = $3 RETURNING *",
      [rating ?? null, comment ?? null, req.params.id]
    );
    res.json({ review: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/listings/:id/reviews", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM reviews WHERE listing_id = $1 ORDER BY created_at DESC",
      [req.params.id]
    );
    res.json({ reviews: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/sellers/:id/reviews", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM reviews WHERE seller_id = $1 ORDER BY created_at DESC",
      [req.params.id]
    );
    res.json({ reviews: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Seller replies to a review left on one of their sales. One reply per
// review — resubmitting overwrites the previous response.
app.patch("/reviews/:id/respond", authenticate, async (req, res) => {
  try {
    const { response } = req.body;
    if (!response || !response.trim()) {
      return res.status(400).json({ error: "Write a response first" });
    }
    const existing = await pool.query("SELECT seller_id FROM reviews WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Review not found" });
    if (existing.rows[0].seller_id !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: "You can only respond to reviews on your own sales" });
    }
    const result = await pool.query(
      "UPDATE reviews SET seller_response = $1, seller_response_at = NOW() WHERE id = $2 RETURNING *",
      [response.trim(), req.params.id]
    );
    res.json({ review: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Anyone signed in can flag a review as abusive or fraudulent — not
// restricted to the seller it's about, since a false or malicious review
// could be spotted by anyone browsing.
app.post("/reviews/:id/report", authenticate, async (req, res) => {
  try {
    const { reason } = req.body;
    const existing = await pool.query("SELECT id FROM reviews WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Review not found" });
    const result = await pool.query(
      `INSERT INTO review_reports (review_id, reporter_id, reason) VALUES ($1, $2, $3) RETURNING *`,
      [req.params.id, req.user.id, reason || ""]
    );
    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin queue of reported reviews, joined with the review content and who
// wrote it/reported it.
app.get("/review-reports", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT rr.*,
         r.rating AS review_rating, r.comment AS review_comment, r.seller_id AS review_seller_id,
         buyer.username AS review_buyer_username, buyer.display_name AS review_buyer_display_name,
         seller.username AS review_seller_username, seller.display_name AS review_seller_display_name,
         reporter.username AS reporter_username, reporter.display_name AS reporter_display_name
       FROM review_reports rr
       JOIN reviews r ON rr.review_id = r.id
       LEFT JOIN users buyer ON r.buyer_id = buyer.id
       LEFT JOIN users seller ON r.seller_id = seller.id
       LEFT JOIN users reporter ON rr.reporter_id = reporter.id
       ORDER BY rr.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/review-reports/:id/resolve", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE review_reports SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json({ report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// A user reports something suspicious about their own account — an
// unrecognized login, a bank change they didn't make, anything that
// doesn't fit a more specific report flow.
app.post("/account-reports", authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Describe what happened first" });
    }
    const result = await pool.query(
      "INSERT INTO account_reports (user_id, message) VALUES ($1, $2) RETURNING *",
      [req.user.id, message.trim()]
    );
    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/account-reports", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ar.*, u.username, u.display_name
       FROM account_reports ar
       JOIN users u ON ar.user_id = u.id
       ORDER BY ar.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/account-reports/:id/resolve", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE account_reports SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json({ report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin issues a warning to a seller — a lighter-weight step than
// suspension, visible to both the admin team and the seller themselves.
app.post("/users/:id/warnings", authenticate, requireAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Write a message for the warning" });
    }
    const result = await pool.query(
      "INSERT INTO seller_warnings (user_id, admin_id, message) VALUES ($1, $2, $3) RETURNING *",
      [req.params.id, req.user.id, message.trim()]
    );
    res.status(201).json({ warning: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin views warning history for a specific seller.
app.get("/users/:id/warnings", authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM seller_warnings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.params.id]
    );
    res.json({ warnings: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// A seller views their own warning history.
app.get("/warnings/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM seller_warnings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ warnings: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public trust signal for a seller's storefront — just a count, no order
// details exposed. "Completed" = the item actually made it to the buyer.
app.get("/sellers/:username/completed-sales-count", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*) FROM order_items oi
       JOIN users u ON oi.seller_id = u.id
       WHERE u.username = $1 AND oi.fulfillment_status = 'delivered'`,
      [req.params.username]
    );
    res.json({ count: Number(result.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/login-history/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM login_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20",
      [req.user.id]
    );
    res.json({ history: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/notifications/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50",
      [req.user.id]
    );
    res.json({ notifications: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/notifications/:id/read", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE notifications SET read = true WHERE id = $1 AND user_id = $2 RETURNING *",
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Notification not found" });
    res.json({ notification: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/notifications/mark-all-read", authenticate, async (req, res) => {
  try {
    await pool.query("UPDATE notifications SET read = true WHERE user_id = $1 AND read = false", [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reminds sellers about items that have sat unshipped for 24+ hours.
// Checks hourly; each item is only reminded once (ship_reminder_sent_at
// gets stamped so it isn't repeated every hour after that).
async function sendShipReminders() {
  try {
    const result = await pool.query(
      `SELECT * FROM order_items
       WHERE fulfillment_status = 'new'
         AND ship_reminder_sent_at IS NULL
         AND created_at < NOW() - INTERVAL '24 hours'`
    );
    for (const item of result.rows) {
      createNotification(item.seller_id, "ship_reminder", `Reminder: "${item.title}" hasn't shipped yet`);
      await pool.query("UPDATE order_items SET ship_reminder_sent_at = NOW() WHERE id = $1", [item.id]);
    }
  } catch (err) {
    console.error("Ship reminder check failed:", err.message);
  }
}
setInterval(sendShipReminders, 60 * 60 * 1000).unref();
sendShipReminders(); // also run once on startup, in case items crossed the threshold while the server was offline

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
