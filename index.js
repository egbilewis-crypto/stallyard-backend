const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const fetch = require("node-fetch");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

// Production-safe internal error handling. Full technical details remain in
// Railway logs, while users receive only a branded-safe generic message.
function sendInternalError(res, err, context = "request") {
  const errorId = crypto.randomUUID();
  console.error(`[${errorId}] ${context}:`, err?.stack || err?.message || err);
  return res.status(500).json({
    error: "Something went wrong. Please try again in a moment.",
    code: "INTERNAL_ERROR",
    errorId,
  });
}

// Production security gate: never bring Stallyard online with missing or obviously
// unsafe secrets. Optional integrations (Termii, Sightengine, IPQS) remain
// health-checked separately and do not block startup.
function validateProductionSecrets() {
  if (process.env.NODE_ENV !== "production") return;

  const problems = [];
  const value = (name) => String(process.env[name] || "").trim();
  const looksPlaceholder = (v) => /^(changeme|change-me|replace-me|your[-_ ]?secret|your[-_ ]?key|example|placeholder|secret|password|test)$/i.test(v);

  const required = [
    "DATABASE_URL",
    "JWT_SECRET",
    "FIELD_ENCRYPTION_KEY",
    "PAYSTACK_SECRET_KEY",
    "SUPABASE_URL",
    "RESEND_API_KEY",
  ];
  for (const name of required) {
    const v = value(name);
    if (!v) problems.push(`${name} is missing`);
    else if (looksPlaceholder(v)) problems.push(`${name} still contains a placeholder value`);
  }

  const supabaseServiceKey = value("SUPABASE_SERVICE_ROLE_KEY") || value("SUPABASE_SECRET_KEY");
  if (!supabaseServiceKey) problems.push("SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) is missing");
  else if (looksPlaceholder(supabaseServiceKey)) problems.push("Supabase server secret still contains a placeholder value");

  const jwtSecret = value("JWT_SECRET");
  if (jwtSecret && jwtSecret.length < 32) problems.push("JWT_SECRET must be at least 32 characters in production");

  const encryptionKey = value("FIELD_ENCRYPTION_KEY");
  if (encryptionKey) {
    try {
      if (Buffer.from(encryptionKey, "base64").length !== 32) {
        problems.push("FIELD_ENCRYPTION_KEY must decode to exactly 32 bytes");
      }
    } catch {
      problems.push("FIELD_ENCRYPTION_KEY must be valid base64 for a 32-byte key");
    }
  }

  const databaseUrl = value("DATABASE_URL");
  if (databaseUrl && !/^postgres(?:ql)?:\/\//i.test(databaseUrl)) problems.push("DATABASE_URL is not a PostgreSQL connection URL");

  const supabaseUrl = value("SUPABASE_URL");
  if (supabaseUrl && !/^https:\/\/[^/]+\.supabase\.co\/?$/i.test(supabaseUrl)) problems.push("SUPABASE_URL must be the HTTPS Supabase project root URL");

  const paystackSecret = value("PAYSTACK_SECRET_KEY");
  if (paystackSecret && !/^sk_(?:test|live)_/i.test(paystackSecret)) problems.push("PAYSTACK_SECRET_KEY does not look like a Paystack secret key");

  const resendKey = value("RESEND_API_KEY");
  if (resendKey && !/^re_/i.test(resendKey)) problems.push("RESEND_API_KEY does not look like a Resend API key");

  if (problems.length) {
    console.error("SECURITY STARTUP CHECK FAILED — Stallyard will not start:");
    for (const problem of problems) console.error(` - ${problem}`);
    process.exit(1);
  }

  console.log("Production security startup check passed.");
}

validateProductionSecrets();

// Railway sits behind a reverse proxy. Trust only the first proxy hop.
app.set("trust proxy", 1);
app.disable("x-powered-by");

// Restrict browser API access to Stallyard frontends. Extra origins such as
// Vercel preview/admin hosts are supplied through Railway ALLOWED_ORIGINS.
const DEFAULT_ALLOWED_ORIGINS = [
  "https://stallyard.com",
  "https://www.stallyard.com",
  "https://admin.stallyard.com",
];
const EXTRA_ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = new Set([...DEFAULT_ALLOWED_ORIGINS, ...EXTRA_ALLOWED_ORIGINS]);

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Paystack-Signature"],
  credentials: true,
  maxAge: 86400,
}));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

app.use(express.json({ limit: "15mb", verify: (req, res, buf) => { req.rawBody = buf; } }));

// HttpOnly cookies protect tokens from JavaScript, but cookie authentication
// requires CSRF protection. Browser state-changing requests carrying the auth
// cookie must come from an explicitly allowed Stallyard origin. Paystack's
// server-to-server webhook is exempt and is independently HMAC-verified.
app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  if (req.path === "/webhooks/paystack") return next();
  const hasAuthCookie = Object.prototype.hasOwnProperty.call(parseCookies(req), AUTH_COOKIE_NAME);
  if (!hasAuthCookie) return next();
  const origin = req.headers.origin || "";
  if (origin && ALLOWED_ORIGINS.has(origin)) return next();
  return res.status(403).json({ error: "Request origin is not allowed", code: "CSRF_ORIGIN_REJECTED" });
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET && process.env.NODE_ENV !== "production") {
  console.warn("Development warning: JWT_SECRET is not set; authenticated routes will not work.");
}

const ADMIN_SERVER_SESSION_MS = 30 * 60 * 1000;
const ADMIN_SESSION_CLOCK_SKEW_MS = 5 * 60 * 1000;
const ADMIN_REAUTH_ALLOWED_PATHS = new Set([
  "/admin/reauth",
  "/admin/reauth/verify",
  "/admin/reauth/verify-email",
  "/session/me",
  "/logout",
]);

function signToken(user, options = {}) {
  const isAdmin = !!user.is_admin;
  const payload = {
    id: user.id,
    username: user.username,
    isAdmin,
    tokenVersion: user.token_version || 0,
  };
  if (isAdmin) {
    const verifiedAt = Number(options.adminVerifiedAt ?? user.adminVerifiedAt ?? 0);
    if (Number.isFinite(verifiedAt) && verifiedAt > 0) payload.adminVerifiedAt = verifiedAt;
  }
  return jwt.sign(payload, JWT_SECRET, { expiresIn: isAdmin ? "24h" : "30d" });
}

const AUTH_COOKIE_NAME = "stallyard_session";

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      out[key] = part.slice(idx + 1).trim();
    }
  }
  return out;
}

function setAuthCookie(res, user, options = {}) {
  const token = signToken(user, options);
  const production = process.env.NODE_ENV === "production";
  const parts = [
    `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    production ? "Secure" : "",
    "SameSite=Lax",
  ].filter(Boolean);
  // Marketplace sessions persist for 30 days. Admin cookies remain browser-session
  // cookies, while the backend independently enforces a 30-minute privileged
  // admin window using the adminVerifiedAt claim.
  if (!user.is_admin) parts.push(`Max-Age=${30 * 24 * 60 * 60}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearAuthCookie(res) {
  const production = process.env.NODE_ENV === "production";
  const parts = [
    `${AUTH_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    production ? "Secure" : "",
    "SameSite=Lax",
    "Max-Age=0",
  ].filter(Boolean);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function getRequester(req) {
  const token = parseCookies(req)[AUTH_COOKIE_NAME] || null;
  if (!token || !JWT_SECRET) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

async function authenticate(req, res, next) {
  const requester = getRequester(req);
  if (!requester) {
    if (parseCookies(req)[AUTH_COOKIE_NAME]) clearAuthCookie(res);
    return res.status(401).json({ error: "Sign in required" });
  }
  try {
    const result = await pool.query(
      "SELECT is_admin, is_suspended, token_version, admin_role, two_factor_enabled, country FROM users WHERE id = $1",
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
    req.user = {
      ...requester,
      isAdmin: !!result.rows[0].is_admin,
      adminRole: result.rows[0].admin_role || null,
      twoFactorEnabled: !!result.rows[0].two_factor_enabled,
      country: result.rows[0].country || "",
    };

    if (req.user.isAdmin) {
      const verifiedAt = Number(requester.adminVerifiedAt || 0);
      const age = verifiedAt ? Date.now() - verifiedAt : Number.POSITIVE_INFINITY;
      const invalidFutureTimestamp = verifiedAt > Date.now() + ADMIN_SESSION_CLOCK_SKEW_MS;
      const expired = !verifiedAt || invalidFutureTimestamp || age > ADMIN_SERVER_SESSION_MS;
      req.user.adminVerifiedAt = verifiedAt || null;
      req.user.adminSessionExpired = expired;

      // Admin identity may remain signed in at the browser level so it can
      // complete the mandatory password -> TOTP -> email re-auth flow, but no
      // privileged endpoint is usable after 30 minutes until that flow succeeds.
      if (expired && !ADMIN_REAUTH_ALLOWED_PATHS.has(req.path)) {
        return res.status(401).json({
          error: "Your 30-minute admin session expired — complete admin re-authentication to continue.",
          code: "ADMIN_SESSION_EXPIRED",
        });
      }
    }
    next();
  } catch (err) {
    sendInternalError(res, err);
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: "Admin access required" });
  if (req.user.adminSessionExpired) {
    return res.status(401).json({
      error: "Your 30-minute admin session expired — complete admin re-authentication to continue.",
      code: "ADMIN_SESSION_EXPIRED",
    });
  }
  if (!req.user.twoFactorEnabled) {
    return res.status(403).json({ error: "Two-factor authentication is required for admin accounts — enable it to continue.", code: "2FA_REQUIRED" });
  }
  next();
}

// Admin identities are staff-only accounts. They may operate the marketplace
// through authorized admin endpoints, but cannot act as buyers or sellers.
// This is enforced server-side so hiding marketplace controls in the admin UI
// is not the only protection.
function rejectAdminMarketplaceUse(req, res, next) {
  if (req.user?.isAdmin) {
    return res.status(403).json({
      error: "Admin accounts are staff-only and cannot use buyer or seller marketplace features.",
      code: "ADMIN_STAFF_ONLY",
    });
  }
  next();
}

function isNigeriaCountry(value) {
  return ["nigeria", "ng"].includes(String(value || "").trim().toLowerCase());
}

function requireNigeriaMarketplaceUser(req, res, next) {
  if (req.user?.isAdmin) return next();
  if (!isNigeriaCountry(req.user?.country)) {
    return res.status(403).json({
      error: "Stallyard marketplace transactions are available in Nigeria only. Complete your profile with Nigeria as your country of residence.",
      code: "NIGERIA_ONLY",
    });
  }
  next();
}

const ADMIN_ROLES = new Set([
  "super_admin", "seller_verification", "listing_moderator",
  "order_dispute", "finance", "customer_support",
]);

const ROLE_PERMISSIONS = {
  seller_verification: new Set(["seller_verification"]),
  listing_moderator: new Set(["listing_moderation"]),
  order_dispute: new Set(["dispute_resolution", "order_access", "order_management", "seller_report_review"]),
  finance: new Set(["finance", "order_access"]),
  customer_support: new Set(["support_tickets", "message_moderation", "seller_report_review"]),
};

function hasPermission(user, permission) {
  if (!user?.isAdmin) return false;
  if (!user.twoFactorEnabled) return false;
  if (!user.adminRole || user.adminRole === "super_admin") return true;
  const allowed = ROLE_PERMISSIONS[user.adminRole];
  return allowed ? allowed.has(permission) : false;
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (req.user?.isAdmin && !req.user.twoFactorEnabled) {
      return res.status(403).json({ error: "Two-factor authentication is required for admin accounts — enable it to continue.", code: "2FA_REQUIRED" });
    }
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ error: "You don't have permission to do that" });
    }
    next();
  };
}

function requireSuperAdmin(req, res, next) {
  if (!req.user?.isAdmin || !req.user.twoFactorEnabled || (req.user.adminRole && req.user.adminRole !== "super_admin")) {
    return res.status(403).json({ error: "Only an authenticated super admin may access identity-verification records" });
  }
  next();
}

const vpnCheckCache = new Map();
const VPN_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function getClientIp(req) {
  // Express is configured with `trust proxy = 1`, so req.ip is derived using
  // the trusted proxy chain instead of trusting a client-supplied
  // X-Forwarded-For value directly. This prevents spoofing rate-limit and
  // fraud/VPN checks by forging that header.
  const ip = typeof req.ip === "string" ? req.ip.trim() : "";
  return ip || req.socket?.remoteAddress || "";
}

// PostgreSQL-backed rate limiter. Security limits survive Railway restarts and
// are shared by every backend instance. Raw emails/phones/IP combinations are
// never stored as rate-limit keys; only a SHA-256 digest is persisted.
function rateLimit({ scope, windowMs, max, message, keyFn }) {
  if (!scope) throw new Error("A persistent rate limiter requires a scope");
  return async (req, res, next) => {
    try {
      const rawKey = keyFn ? keyFn(req) : (getClientIp(req) || "unknown");
      const rateKey = crypto.createHash("sha256").update(`${scope}:${rawKey}`).digest("hex");
      const result = await pool.query(
        `INSERT INTO security_rate_limits (rate_key, scope, hit_count, window_started_at, expires_at)
         VALUES ($1, $2, 1, NOW(), NOW() + ($3::bigint * INTERVAL '1 millisecond'))
         ON CONFLICT (rate_key) DO UPDATE SET
           hit_count = CASE
             WHEN security_rate_limits.expires_at <= NOW() THEN 1
             ELSE security_rate_limits.hit_count + 1
           END,
           window_started_at = CASE
             WHEN security_rate_limits.expires_at <= NOW() THEN NOW()
             ELSE security_rate_limits.window_started_at
           END,
           expires_at = CASE
             WHEN security_rate_limits.expires_at <= NOW() THEN NOW() + ($3::bigint * INTERVAL '1 millisecond')
             ELSE security_rate_limits.expires_at
           END
         RETURNING hit_count, expires_at`,
        [rateKey, scope, windowMs]
      );
      const row = result.rows[0];
      if (Number(row.hit_count) > max) {
        const retryAfterSeconds = Math.max(1, Math.ceil((new Date(row.expires_at).getTime() - Date.now()) / 1000));
        res.setHeader("Retry-After", String(retryAfterSeconds));
        return res.status(429).json({
          error: message || "Too many attempts — please wait a bit and try again.",
          retryAfterSeconds,
        });
      }
      // Opportunistic cleanup keeps the table compact without a separate worker.
      if (crypto.randomInt(0, 100) === 0) {
        pool.query("DELETE FROM security_rate_limits WHERE expires_at < NOW() - INTERVAL '1 day'")
          .catch((err) => console.error("Rate-limit cleanup failed:", err.message));
      }
      return next();
    } catch (err) {
      console.error(`Persistent rate limiter failed (${scope}):`, err.message);
      return res.status(503).json({ error: "Security checks are temporarily unavailable — please try again shortly." });
    }
  };
}

const authRateLimit = rateLimit({ scope: "auth", windowMs: 15 * 60 * 1000, max: 10, message: "Too many attempts — please wait 15 minutes and try again." });

async function createNotification(userId, type, message) {
  if (!userId) return;
  try {
    await pool.query("INSERT INTO notifications (user_id, type, message) VALUES ($1, $2, $3)", [userId, type, message]);
  } catch (err) {
    console.error("Failed to create notification:", err.message);
  }
}

function logAdminAction(adminId, action, details) {
  pool
    .query("INSERT INTO admin_audit_log (admin_id, action, details) VALUES ($1, $2, $3)", [adminId, action, details])
    .catch((err) => console.error("Failed to write audit log:", err.message));
}

const codeRateLimit = rateLimit({ scope: "security-code", windowMs: 15 * 60 * 1000, max: 8, message: "Too many attempts — please wait 15 minutes and try again." });

// Payout-bank changes are especially sensitive because they control where seller
// money is sent. Protect both code issuance and verification independently from
// the general authentication limiter.
const bankChangeSendUserRateLimit = rateLimit({
  scope: "bank-change-send-user",
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: "Too many bank-change confirmation codes requested — wait 15 minutes and try again.",
  keyFn: (req) => `bank-change-send:user:${req.user?.id || "unknown"}`,
});
const bankChangeSendIpRateLimit = rateLimit({
  scope: "bank-change-send-ip",
  windowMs: 15 * 60 * 1000,
  max: 6,
  message: "Too many bank-change confirmation requests from this connection — wait 15 minutes and try again.",
  keyFn: (req) => `bank-change-send:ip:${getClientIp(req) || "unknown"}`,
});
const bankChangeConfirmRateLimit = rateLimit({
  scope: "bank-change-confirm",
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: "Too many bank-change code attempts — wait 15 minutes and request a new code.",
  keyFn: (req) => `bank-change-confirm:${req.user?.id || "unknown"}:${getClientIp(req) || "unknown"}`,
});
const bankAccountResolveRateLimit = rateLimit({
  scope: "bank-account-resolve",
  windowMs: 15 * 60 * 1000,
  max: 12,
  message: "Too many bank-account checks — wait 15 minutes and try again.",
  keyFn: (req) => `user:${req.user?.id || "unknown"}:ip:${getClientIp(req) || "unknown"}`,
});
const BANK_CHANGE_RESEND_COOLDOWN_MS = 60 * 1000;
const BANK_CHANGE_MAX_CODE_ATTEMPTS = 5;

// Security-sensitive one-time codes must use a cryptographically secure RNG.
// randomInt is uniform over 100000-999999 and avoids Math.random(), which is
// not suitable for authentication, password-reset, or payout-verification codes.
function generateSecurityCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

// Generate a unique, unpredictable Paystack transaction reference.
// This value is created server-side and is also the primary key for the
// checkout intent, so never accept a client-supplied payment reference.
function generateCheckoutReference() {
  return `STL-${Date.now()}-${crypto.randomBytes(12).toString("hex")}`;
}

function formatMoneyServer(amount) {
  return `₦${Number(amount || 0).toFixed(2)}`;
}

function generateDeliveryTokenValue() {
  // Cryptographically strong 10-digit delivery code generated once payment succeeds.
  return crypto.randomInt(1000000000, 10000000000).toString();
}

async function createCheckoutIntent({ reference, buyerId, buyerUsername, buyerEmail, amountKobo, items, shippingAddress, saveCard = false }, client = pool) {
  await client.query(
    `INSERT INTO checkout_intents (
       reference, buyer_id, buyer_username, buyer_email, amount_kobo, currency,
       items, shipping_address, save_card, status
     ) VALUES ($1, $2, $3, $4, $5, 'NGN', $6, $7, $8, 'initialized')`,
    [
      reference, Number(buyerId), String(buyerUsername), String(buyerEmail).trim().toLowerCase(),
      Number(amountKobo), JSON.stringify(items || []), JSON.stringify(shippingAddress || {}), !!saveCard,
    ]
  );
}

const CHECKOUT_RESERVATION_MINUTES = 15;

async function reserveCheckoutListings(client, { buyerId, reference, items }) {
  const listingIds = [...new Set((items || []).map((item) => Number(item.listingId)))].filter(Number.isInteger).sort((a, b) => a - b);
  if (!listingIds.length) throw new Error("Checkout has no valid listings to reserve");

  for (const listingId of listingIds) {
    // Lock the listing row so two checkout transactions cannot reserve it simultaneously.
    const listingResult = await client.query(
      "SELECT id, status FROM listings WHERE id = $1 FOR UPDATE",
      [listingId]
    );
    if (!listingResult.rows.length || listingResult.rows[0].status !== "active") {
      const err = new Error(`Listing ${listingId} isn't available`);
      err.code = "LISTING_UNAVAILABLE";
      throw err;
    }

    // Expired reservations never block a new buyer.
    await client.query(
      "DELETE FROM listing_checkout_reservations WHERE listing_id = $1 AND expires_at <= NOW()",
      [listingId]
    );

    const existing = await client.query(
      "SELECT buyer_id, reference, expires_at FROM listing_checkout_reservations WHERE listing_id = $1 FOR UPDATE",
      [listingId]
    );
    if (existing.rows.length) {
      const err = new Error("One or more items are temporarily reserved by another checkout. Please try again shortly.");
      err.code = "LISTING_RESERVED";
      err.listingId = listingId;
      throw err;
    }

    await client.query(
      `INSERT INTO listing_checkout_reservations (listing_id, buyer_id, reference, expires_at)
       VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 minute'))`,
      [listingId, Number(buyerId), reference, CHECKOUT_RESERVATION_MINUTES]
    );
  }
}

async function releaseCheckoutReservations(reference, client = pool) {
  await client.query("DELETE FROM listing_checkout_reservations WHERE reference = $1", [reference]);
}

async function assertCheckoutReservationsOwned(client, intent) {
  const listingIds = [...new Set((Array.isArray(intent.items) ? intent.items : []).map((item) => Number(item.listingId)))].filter(Number.isInteger).sort((a, b) => a - b);
  if (!listingIds.length) throw new Error("Payment integrity check failed: checkout intent has no reservable listings");

  const reservations = await client.query(
    `SELECT listing_id, buyer_id, reference, expires_at
     FROM listing_checkout_reservations
     WHERE listing_id = ANY($1::int[])
     FOR UPDATE`,
    [listingIds]
  );
  const byListing = new Map(reservations.rows.map((row) => [Number(row.listing_id), row]));

  for (const listingId of listingIds) {
    const reservation = byListing.get(listingId);
    if (!reservation || String(reservation.reference) !== String(intent.reference) || Number(reservation.buyer_id) !== Number(intent.buyer_id)) {
      throw new Error(`Paid listing ${listingId} is no longer reserved for this checkout — payment requires manual review`);
    }
    if (new Date(reservation.expires_at).getTime() <= Date.now()) {
      throw new Error(`Paid listing ${listingId} reservation expired — payment requires manual review`);
    }
  }
}

async function loadCheckoutIntent(reference, client = pool) {
  const result = await client.query("SELECT * FROM checkout_intents WHERE reference = $1", [reference]);
  return result.rows[0] || null;
}

function assertPaystackMatchesCheckoutIntent(intent, paystackData) {
  if (!intent) throw new Error("Payment integrity check failed: checkout intent not found");
  if (!paystackData || paystackData.status !== "success") {
    throw new Error("Payment integrity check failed: Paystack transaction is not successful");
  }

  const actualReference = String(paystackData.reference || "");
  if (actualReference !== String(intent.reference)) {
    throw new Error("Payment integrity check failed: transaction reference does not match");
  }

  const actualAmountKobo = Number(paystackData.amount);
  if (!Number.isSafeInteger(actualAmountKobo) || actualAmountKobo !== Number(intent.amount_kobo)) {
    throw new Error("Payment integrity check failed: amount paid does not match the checkout total");
  }

  const actualCurrency = String(paystackData.currency || "").toUpperCase();
  if (actualCurrency !== "NGN" || actualCurrency !== String(intent.currency || "").toUpperCase()) {
    throw new Error("Payment integrity check failed: currency does not match NGN checkout");
  }

  const actualEmail = String(paystackData.customer?.email || "").trim().toLowerCase();
  const expectedEmail = String(intent.buyer_email || "").trim().toLowerCase();
  if (!actualEmail || actualEmail !== expectedEmail) {
    throw new Error("Payment integrity check failed: Paystack customer does not match the buyer");
  }

  const metadataBuyerId = Number(paystackData.metadata?.buyerId);
  if (paystackData.metadata?.buyerId != null && metadataBuyerId !== Number(intent.buyer_id)) {
    throw new Error("Payment integrity check failed: payment metadata buyer does not match");
  }
}

async function markCheckoutIntent(reference, status, failureReason = null, client = pool) {
  await client.query(
    `UPDATE checkout_intents
     SET status = $1, failure_reason = $2, finalized_at = CASE WHEN $1 = 'finalized' THEN NOW() ELSE finalized_at END
     WHERE reference = $3`,
    [status, failureReason ? String(failureReason).slice(0, 1000) : null, reference]
  );
}

async function finalizeOrderFromPaystackCharge(reference, paystackData) {
  const existing = await pool.query("SELECT * FROM orders WHERE paystack_reference = $1", [reference]);
  if (existing.rows.length) {
    const itemsResult = await pool.query("SELECT * FROM order_items WHERE order_id = $1 ORDER BY id ASC", [existing.rows[0].id]);
    return { order: existing.rows[0], items: itemsResult.rows, alreadyFinalized: true };
  }

  const intent = await loadCheckoutIntent(reference);
  assertPaystackMatchesCheckoutIntent(intent, paystackData);
  const cartItems = Array.isArray(intent.items) ? intent.items : [];
  if (!cartItems.length) throw new Error("Payment integrity check failed: checkout intent has no items");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await assertCheckoutReservationsOwned(client, intent);

    let subtotal = 0;
    let shippingTotal = 0;
    const resolvedItems = [];
    for (const cartItem of cartItems) {
      const qty = Number(cartItem.qty);
      const listingResult = await client.query(
        "SELECT * FROM listings WHERE id = $1 AND status = 'active' FOR UPDATE",
        [cartItem.listingId]
      );
      if (listingResult.rows.length === 0) {
        throw new Error(`Paid listing ${cartItem.listingId} is no longer available — payment requires manual review`);
      }
      const listing = listingResult.rows[0];
      const price = Number(cartItem.unitPrice);
      const shippingFee = Number(cartItem.shippingFee) || 0;
      if (!(price > 0)) throw new Error("Payment integrity check failed: invalid item price snapshot");
      subtotal += price * qty;
      shippingTotal += shippingFee * qty;
      resolvedItems.push({ listing, qty, price, shippingFee });
    }

    const commissionRate = await getCommissionRate();
    const commissionAmount = Math.round(subtotal * commissionRate * 100) / 100;
    const taxRate = await getTaxRate();
    const taxAmount = Math.round(subtotal * taxRate * 100) / 100;
    const total = Math.round((subtotal + shippingTotal + taxAmount) * 100) / 100;
    const recomputedAmountKobo = Math.round(total * 100);
    if (recomputedAmountKobo !== Number(intent.amount_kobo)) {
      throw new Error("Payment integrity check failed: stored checkout total no longer matches item snapshot");
    }
    const authorization = paystackData.authorization || {};

    const orderResult = await client.query(
      `INSERT INTO orders (
         buyer_id, buyer_username, total, currency, shipping_address, subtotal,
         shipping_total, commission_rate, commission_amount, tax_amount, payment_status,
         paystack_reference, payment_channel, payment_card_type, payment_bank, payment_last4
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'held', $11, $12, $13, $14, $15)
       RETURNING *`,
      [
        intent.buyer_id, intent.buyer_username, total, "NGN",
        JSON.stringify(intent.shipping_address || {}), subtotal, shippingTotal,
        commissionRate, commissionAmount, taxAmount,
        reference, paystackData.channel || null, authorization.card_type || null,
        authorization.bank || null, authorization.last4 || null,
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
           seller_id, seller_username, seller_name, fulfillment_status,
           delivery_token, delivery_token_generated_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'new', $11, NOW())
         RETURNING *`,
        [
          order.id, listing.id, listing.title, listing.emoji, price, qty, shippingFee,
          listing.owner_id, seller?.username, seller?.display_name,
          generateDeliveryTokenValue(),
        ]
      );
      insertedItems.push(itemResult.rows[0]);
      await client.query("UPDATE listings SET status = 'sold' WHERE id = $1", [listing.id]);
      createNotification(
        listing.owner_id,
        "sale",
        `New sale: ${listing.title} (${qty}x) — ${formatMoneyServer(price * qty, order.currency)}. Payment is held until delivery is confirmed.`
      );
    }

    await releaseCheckoutReservations(reference, client);
    await client.query("COMMIT");

    await markCheckoutIntent(reference, "finalized", null);

    if (intent.save_card && authorization.reusable && authorization.authorization_code) {
      try {
        await pool.query(
          `INSERT INTO saved_cards (user_id, authorization_code, authorization_code_hash, card_type, last4, bank, exp_month, exp_year, is_default)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
             NOT EXISTS (SELECT 1 FROM saved_cards WHERE user_id = $1))
           ON CONFLICT (user_id, authorization_code_hash) DO NOTHING`,
          [
            intent.buyer_id, encryptField(authorization.authorization_code), hashField(authorization.authorization_code),
            authorization.card_type || null, authorization.last4 || null, authorization.bank || null,
            authorization.exp_month || null, authorization.exp_year || null,
          ]
        );
      } catch (err) {
        console.error("Couldn't save card for future checkout:", err.message);
      }
    }
    return { order: { ...order, items: insertedItems }, items: insertedItems, alreadyFinalized: false };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function recordPaymentAttempt(userId, { reference = null, method = "checkout", status, amount = 0, currency = "NGN", message = "" }) {
  try {
    await pool.query(
      `INSERT INTO payment_attempts (user_id, reference, method, status, amount, currency, message)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, reference, method, status, amount, currency, String(message || "").slice(0, 1000)]
    );
  } catch (err) {
    // The buyer-risk migration may not have been run yet; checkout must never fail because telemetry failed.
    if (err.code !== "42P01") console.error("Couldn't record payment attempt:", err.message);
  }
}


function normalizePhoneForRateLimit(phone) {
  return String(phone || "").replace(/[^0-9]/g, "");
}

// SMS is a paid, abuse-sensitive channel, so protect it twice:
// 1) per IP, which limits one client from spraying many numbers; and
// 2) per phone number, which prevents repeatedly charging Stallyard to SMS the same person.
const smsSendIpRateLimit = rateLimit({
  scope: "sms-send-ip",
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many SMS code requests from this connection — wait 15 minutes and try again.",
});
const smsSendPhoneRateLimit = rateLimit({
  scope: "sms-send-phone",
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: "Too many SMS codes were requested for this phone number — wait 15 minutes and try again.",
  keyFn: (req) => `phone:${normalizePhoneForRateLimit(req.body?.phone) || "missing"}`,
});
const smsCheckRateLimit = rateLimit({
  scope: "sms-check",
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: "Too many verification attempts — wait 15 minutes and request a new code.",
  keyFn: (req) => `${getClientIp(req) || "unknown"}:phone:${normalizePhoneForRateLimit(req.body?.phone) || "missing"}`,
});

// Image uploads are authenticated but still cost bandwidth, moderation calls, and
// Supabase Storage. Layer burst and daily limits so a compromised account cannot
// hammer the upload endpoint or run up storage costs. These limits still allow
// two full 12-photo listings plus a few retries within 15 minutes.
const imageUploadUserBurstRateLimit = rateLimit({
  scope: "image-upload-user-burst",
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: "You've uploaded a lot of images recently — wait 15 minutes before uploading more.",
  keyFn: (req) => `user:${req.user?.id || "unknown"}`,
});
const imageUploadIpBurstRateLimit = rateLimit({
  scope: "image-upload-ip-burst",
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: "Too many image uploads from this connection — wait 15 minutes and try again.",
  keyFn: (req) => `ip:${getClientIp(req) || "unknown"}`,
});
const imageUploadUserDailyRateLimit = rateLimit({
  scope: "image-upload-user-daily",
  windowMs: 24 * 60 * 60 * 1000,
  max: 120,
  message: "Daily image upload limit reached — try again tomorrow or contact support if you need help.",
  keyFn: (req) => `user:${req.user?.id || "unknown"}`,
});
const MAX_IMAGE_UPLOAD_BYTES = 8 * 1024 * 1024;

// Homepage Ad 1 may use a short promotional video. Keep this much tighter than
// general file hosting so the admin tool cannot become an accidental large-file store.
const homepageVideoUserRateLimit = rateLimit({
  scope: "homepage-video-upload-user",
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many promotional video uploads — wait 15 minutes and try again.",
  keyFn: (req) => `user:${req.user?.id || "unknown"}`,
});
const homepageVideoIpRateLimit = rateLimit({
  scope: "homepage-video-upload-ip",
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many promotional video uploads from this connection — wait 15 minutes and try again.",
  keyFn: (req) => `ip:${getClientIp(req) || "unknown"}`,
});
const MAX_HOMEPAGE_VIDEO_BYTES = 40 * 1024 * 1024;

async function isVpnOrProxy(ip) {
  if (!ip || ip === "::1" || ip === "127.0.0.1") return false;
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

const phoneCheckCache = new Map();
const PHONE_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

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

const TERMII_PIN_TTL_MS = 10 * 60 * 1000;

const PHONE_VERIFIED_TTL_MS = 30 * 60 * 1000;

app.post("/phone-verify/send", smsSendIpRateLimit, smsSendPhoneRateLimit, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "Missing phone number" });
    if (!process.env.TERMII_API_KEY) {
      return res.status(500).json({ error: "SMS verification isn't configured yet" });
    }

    const to = phone.replace(/[^0-9]/g, "");
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
    await setSecurityState("phone-otp", phone, { pinId: data.pinId }, TERMII_PIN_TTL_MS);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/phone-verify/check", smsCheckRateLimit, async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) return res.status(400).json({ error: "Missing phone number or code" });
    if (!process.env.TERMII_API_KEY) {
      return res.status(500).json({ error: "SMS verification isn't configured yet" });
    }

    const stored = await getSecurityState("phone-otp", phone);
    if (!stored) {
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
      await deleteSecurityState("phone-otp", phone);
      await setSecurityState("phone-verified", phone, { verified: true }, PHONE_VERIFIED_TTL_MS);
    }
    res.json({ valid });
  } catch (err) {
    sendInternalError(res, err);
  }
});

const EMAIL_CODE_TTL_MS = 15 * 60 * 1000;

const EMAIL_VERIFIED_TTL_MS = 30 * 60 * 1000;

app.post("/email-verify/send", codeRateLimit, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email address" });
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Email verification isn't configured yet" });
    }

    const code = generateSecurityCode();
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
    await setSecurityState("email-otp", email.toLowerCase(), { code }, EMAIL_CODE_TTL_MS);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/email-verify/check", codeRateLimit, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Missing email or code" });

    const stored = await getSecurityState("email-otp", email.toLowerCase());
    if (!stored) {
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }
    const valid = stored.code === String(code).trim();
    if (valid) {
      await deleteSecurityState("email-otp", email.toLowerCase());
      await setSecurityState("email-verified", email.toLowerCase(), { verified: true }, EMAIL_VERIFIED_TTL_MS);
    }
    res.json({ valid });
  } catch (err) {
    sendInternalError(res, err);
  }
});

const PASSWORD_RESET_CODE_TTL_MS = 15 * 60 * 1000;

// Tracks an admin who used a Super-Admin-issued temporary password for step 1.
// The temporary password itself is stored only as a bcrypt hash in PostgreSQL;
// this short-lived marker only carries the recovery state through TOTP + email.
const ADMIN_TEMP_PASSWORD_TTL_MS = 10 * 60 * 1000;

const TWO_FACTOR_CODE_TTL_MS = 10 * 60 * 1000;


const TOTP_VERIFIED_MARKER_TTL_MS = 10 * 60 * 1000;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = "";
  for (const byte of buffer) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder) {
    output += BASE32_ALPHABET[parseInt(bits.slice(bits.length - remainder).padEnd(5, "0"), 2)];
  }
  return output;
}

function base32Decode(input) {
  const clean = String(input || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpCodeForCounter(secretBuffer, counter) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % 1000000).padStart(6, "0");
}

function verifyTotpCode(base32Secret, code) {
  const cleanCode = String(code || "").trim();
  if (!/^\d{6}$/.test(cleanCode)) return false;
  const secretBuffer = base32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let drift = -1; drift <= 1; drift++) {
    if (totpCodeForCounter(secretBuffer, counter + drift) === cleanCode) return true;
  }
  return false;
}

function getFieldEncryptionKey() {
  const raw = process.env.FIELD_ENCRYPTION_KEY;
  if (!raw) return null;
  const key = Buffer.from(raw, "base64");
  return key.length === 32 ? key : null;
}

function encryptField(plaintext) {
  const key = getFieldEncryptionKey();
  if (!key || plaintext === null || plaintext === undefined) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString("base64")}:${authTag.toString("base64")}:${ciphertext.toString("base64")}`;
}

function decryptFieldSafe(value) {
  if (!value || !String(value).startsWith("enc:v1:")) return value;
  const key = getFieldEncryptionKey();
  if (!key) {
    throw new Error("FIELD_ENCRYPTION_KEY isn't set — can't decrypt a stored value that was encrypted with it");
  }
  const [, , ivB64, authTagB64, ciphertextB64] = String(value).split(":");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(authTagB64, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertextB64, "base64")),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}


function decryptTotpSecret(value) {
  const secret = decryptFieldSafe(value);
  return secret ? String(secret) : "";
}

// Minimal local QR encoder for authenticator setup. Keeping generation inside
// Stallyard means the otpauth URI/TOTP secret never has to be sent to a
// third-party QR service. This implementation emits a Version 10-L QR code,
// which comfortably fits Stallyard's otpauth URI.
function makeLocalTotpQrDataUrl(text) {
  const VERSION = 10;
  const MODULE_COUNT = VERSION * 4 + 17; // 57
  const DATA_CODEWORDS = 274; // QR Version 10, error correction L
  const RS_BLOCKS = [
    { total: 86, data: 68 },
    { total: 86, data: 68 },
    { total: 87, data: 69 },
    { total: 87, data: 69 },
  ];
  const ALIGNMENT = [6, 28, 50];

  const bytes = Buffer.from(String(text), "utf8");
  if (bytes.length > 271) throw new Error("Authenticator setup URI is too long for the local QR encoder");

  const bits = [];
  const putBits = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push(((value >>> i) & 1) === 1);
  };
  putBits(0b0100, 4); // byte mode
  putBits(bytes.length, 16); // version 10-40 byte-mode length field
  for (const byte of bytes) putBits(byte, 8);
  const capacityBits = DATA_CODEWORDS * 8;
  for (let i = 0; i < Math.min(4, capacityBits - bits.length); i++) bits.push(false);
  while (bits.length % 8) bits.push(false);
  const dataCodewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j++) value = (value << 1) | (bits[i + j] ? 1 : 0);
    dataCodewords.push(value);
  }
  let pad = true;
  while (dataCodewords.length < DATA_CODEWORDS) {
    dataCodewords.push(pad ? 0xec : 0x11);
    pad = !pad;
  }

  const EXP = new Array(512).fill(0);
  const LOG = new Array(256).fill(0);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
  const generator = (degree) => {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], EXP[i]);
      }
      poly = next;
    }
    return poly;
  };
  const rsRemainder = (data, ecCount) => {
    const gen = generator(ecCount);
    const msg = data.concat(new Array(ecCount).fill(0));
    for (let i = 0; i < data.length; i++) {
      const factor = msg[i];
      if (!factor) continue;
      for (let j = 0; j < gen.length; j++) msg[i + j] ^= gfMul(gen[j], factor);
    }
    return msg.slice(data.length);
  };

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (const block of RS_BLOCKS) {
    const d = dataCodewords.slice(offset, offset + block.data);
    offset += block.data;
    dataBlocks.push(d);
    ecBlocks.push(rsRemainder(d, block.total - block.data));
  }
  const codewords = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i++) for (const block of dataBlocks) if (i < block.length) codewords.push(block[i]);
  const maxEc = Math.max(...ecBlocks.map((b) => b.length));
  for (let i = 0; i < maxEc; i++) for (const block of ecBlocks) if (i < block.length) codewords.push(block[i]);

  const bchDigit = (n) => { let d = 0; while (n) { d++; n >>>= 1; } return d; };
  const bchTypeInfo = (data) => {
    let d = data << 10;
    const g = 0x537;
    while (bchDigit(d) - bchDigit(g) >= 0) d ^= g << (bchDigit(d) - bchDigit(g));
    return ((data << 10) | d) ^ 0x5412;
  };
  const bchTypeNumber = (data) => {
    let d = data << 12;
    const g = 0x1f25;
    while (bchDigit(d) - bchDigit(g) >= 0) d ^= g << (bchDigit(d) - bchDigit(g));
    return (data << 12) | d;
  };

  const buildMatrix = (maskPattern) => {
    const modules = Array.from({ length: MODULE_COUNT }, () => Array(MODULE_COUNT).fill(null));
    const finder = (row, col) => {
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
        const rr = row + r, cc = col + c;
        if (rr < 0 || rr >= MODULE_COUNT || cc < 0 || cc >= MODULE_COUNT) continue;
        modules[rr][cc] =
          (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
          (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
          (r >= 2 && r <= 4 && c >= 2 && c <= 4);
      }
    };
    finder(0, 0); finder(MODULE_COUNT - 7, 0); finder(0, MODULE_COUNT - 7);

    for (const row of ALIGNMENT) for (const col of ALIGNMENT) {
      if (modules[row][col] !== null) continue;
      for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) {
        modules[row + r][col + c] = Math.max(Math.abs(r), Math.abs(c)) !== 1;
      }
    }
    for (let i = 8; i < MODULE_COUNT - 8; i++) {
      if (modules[i][6] === null) modules[i][6] = i % 2 === 0;
      if (modules[6][i] === null) modules[6][i] = i % 2 === 0;
    }

    const versionBits = bchTypeNumber(VERSION);
    for (let i = 0; i < 18; i++) {
      const bit = ((versionBits >> i) & 1) === 1;
      modules[Math.floor(i / 3)][(i % 3) + MODULE_COUNT - 11] = bit;
      modules[(i % 3) + MODULE_COUNT - 11][Math.floor(i / 3)] = bit;
    }

    const formatBits = bchTypeInfo((1 << 3) | maskPattern); // L = 1
    for (let i = 0; i < 15; i++) {
      const bit = ((formatBits >> i) & 1) === 1;
      let r;
      if (i < 6) r = i;
      else if (i < 8) r = i + 1;
      else r = MODULE_COUNT - 15 + i;
      modules[r][8] = bit;

      let c;
      if (i < 8) c = MODULE_COUNT - i - 1;
      else if (i < 9) c = 15 - i;
      else c = 15 - i - 1;
      modules[8][c] = bit;
    }
    modules[MODULE_COUNT - 8][8] = true;

    const mask = (r, c) => {
      switch (maskPattern) {
        case 0: return (r + c) % 2 === 0;
        case 1: return r % 2 === 0;
        case 2: return c % 3 === 0;
        case 3: return (r + c) % 3 === 0;
        case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
        case 5: return (r * c) % 2 + (r * c) % 3 === 0;
        case 6: return ((r * c) % 2 + (r * c) % 3) % 2 === 0;
        default: return ((r * c) % 3 + (r + c) % 2) % 2 === 0;
      }
    };

    let row = MODULE_COUNT - 1;
    let inc = -1;
    let bitIndex = 7;
    let byteIndex = 0;
    for (let col = MODULE_COUNT - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      while (true) {
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (modules[row][cc] !== null) continue;
          let dark = false;
          if (byteIndex < codewords.length) dark = ((codewords[byteIndex] >>> bitIndex) & 1) === 1;
          if (mask(row, cc)) dark = !dark;
          modules[row][cc] = dark;
          bitIndex--;
          if (bitIndex < 0) { byteIndex++; bitIndex = 7; }
        }
        row += inc;
        if (row < 0 || row >= MODULE_COUNT) { row -= inc; inc = -inc; break; }
      }
    }
    return modules;
  };

  const lostPoint = (m) => {
    let score = 0;
    for (let r = 0; r < MODULE_COUNT; r++) for (let c = 0; c < MODULE_COUNT; c++) {
      let same = 0;
      const dark = m[r][c];
      for (let dr = -1; dr <= 1; dr++) for (let dc = -1; dc <= 1; dc++) {
        if ((!dr && !dc) || r + dr < 0 || r + dr >= MODULE_COUNT || c + dc < 0 || c + dc >= MODULE_COUNT) continue;
        if (m[r + dr][c + dc] === dark) same++;
      }
      if (same > 5) score += 3 + same - 5;
    }
    for (let r = 0; r < MODULE_COUNT - 1; r++) for (let c = 0; c < MODULE_COUNT - 1; c++) {
      const count = [m[r][c], m[r + 1][c], m[r][c + 1], m[r + 1][c + 1]].filter(Boolean).length;
      if (count === 0 || count === 4) score += 3;
    }
    for (let r = 0; r < MODULE_COUNT; r++) for (let c = 0; c < MODULE_COUNT - 6; c++) {
      if (m[r][c] && !m[r][c+1] && m[r][c+2] && m[r][c+3] && m[r][c+4] && !m[r][c+5] && m[r][c+6]) score += 40;
    }
    for (let c = 0; c < MODULE_COUNT; c++) for (let r = 0; r < MODULE_COUNT - 6; r++) {
      if (m[r][c] && !m[r+1][c] && m[r+2][c] && m[r+3][c] && m[r+4][c] && !m[r+5][c] && m[r+6][c]) score += 40;
    }
    const darkCount = m.flat().filter(Boolean).length;
    score += Math.floor(Math.abs(100 * darkCount / (MODULE_COUNT * MODULE_COUNT) - 50) / 5) * 10;
    return score;
  };

  let best = null, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const matrix = buildMatrix(mask);
    const score = lostPoint(matrix);
    if (score < bestScore) { best = matrix; bestScore = score; }
  }
  const quiet = 4;
  const size = MODULE_COUNT + quiet * 2;
  const cells = [];
  for (let r = 0; r < MODULE_COUNT; r++) for (let c = 0; c < MODULE_COUNT; c++) {
    if (best[r][c]) cells.push(`<rect x="${c + quiet}" y="${r + quiet}" width="1" height="1"/>`);
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="white"/><g fill="black">${cells.join("")}</g></svg>`;
  return `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
}

async function encryptLegacyTotpSecrets() {
  const result = await pool.query(
    `SELECT id, totp_secret FROM users
     WHERE totp_secret IS NOT NULL AND totp_secret <> '' AND totp_secret NOT LIKE 'enc:v1:%'`
  );
  if (!result.rows.length) return;
  for (const row of result.rows) {
    await pool.query("UPDATE users SET totp_secret = $1 WHERE id = $2", [encryptField(row.totp_secret), row.id]);
  }
  console.log(`Encrypted ${result.rows.length} legacy authenticator secret(s) at rest.`);
}

function hashField(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

const BANK_CHANGE_CODE_TTL_MS = 15 * 60 * 1000;

function securityStateKey(namespace, subject) {
  return crypto.createHash("sha256").update(`${namespace}:${subject}`).digest("hex");
}

async function setSecurityState(namespace, subject, payload, ttlMs, client = pool) {
  const stateKey = securityStateKey(namespace, subject);
  const encryptedPayload = encryptField(JSON.stringify(payload));
  await client.query(
    `INSERT INTO security_ephemeral_state (state_key, namespace, payload_encrypted, expires_at, updated_at)
     VALUES ($1, $2, $3, NOW() + ($4::bigint * INTERVAL '1 millisecond'), NOW())
     ON CONFLICT (state_key) DO UPDATE SET
       namespace = EXCLUDED.namespace,
       payload_encrypted = EXCLUDED.payload_encrypted,
       expires_at = EXCLUDED.expires_at,
       updated_at = NOW()`,
    [stateKey, namespace, encryptedPayload, ttlMs]
  );
}

async function getSecurityState(namespace, subject, client = pool) {
  const stateKey = securityStateKey(namespace, subject);
  const result = await client.query(
    `SELECT payload_encrypted, expires_at
     FROM security_ephemeral_state
     WHERE state_key = $1 AND namespace = $2`,
    [stateKey, namespace]
  );
  if (!result.rows.length) return null;
  const row = result.rows[0];
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await client.query("DELETE FROM security_ephemeral_state WHERE state_key = $1", [stateKey]);
    return null;
  }
  try {
    return JSON.parse(decryptFieldSafe(row.payload_encrypted));
  } catch (err) {
    console.error(`Failed to read security state (${namespace}):`, err.message);
    await client.query("DELETE FROM security_ephemeral_state WHERE state_key = $1", [stateKey]);
    return null;
  }
}

async function deleteSecurityState(namespace, subject, client = pool) {
  const stateKey = securityStateKey(namespace, subject);
  await client.query("DELETE FROM security_ephemeral_state WHERE state_key = $1 AND namespace = $2", [stateKey, namespace]);
}

app.post("/password-reset/send", authRateLimit, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Enter your username" });
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Password reset isn't configured yet" });
    }

    const key = username.trim().toLowerCase();
    const genericResponse = {
      success: true,
      message: "If that account is eligible for public password recovery, a reset code will be sent to its email address.",
    };

    // Public recovery must never reveal whether a username exists or whether it
    // belongs to an administrator. Admin recovery is handled only through the
    // dedicated Super Admin temporary-password flow.
    const result = await pool.query(
      "SELECT id, email, is_admin FROM users WHERE username = $1",
      [key]
    );
    if (result.rows.length === 0 || result.rows[0].is_admin) {
      await deleteSecurityState("password-reset", key);
      return res.json(genericResponse);
    }

    const { id: userId, email } = result.rows[0];
    if (!email) {
      await deleteSecurityState("password-reset", key);
      return res.json(genericResponse);
    }

    const code = generateSecurityCode();
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

    await setSecurityState("password-reset", key, { code, userId }, PASSWORD_RESET_CODE_TTL_MS);
    const maskedEmail = email.replace(/^(.{1,2}).*(@.*)$/, (m, a, b) => `${a}***${b}`);
    res.json({ ...genericResponse, maskedEmail });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/password-reset/verify-code", codeRateLimit, async (req, res) => {
  try {
    const { username, code } = req.body;
    if (!username || !code) return res.status(400).json({ error: "Missing username or code" });
    const key = username.trim().toLowerCase();
    const stored = await getSecurityState("password-reset", key);
    if (!stored) {
      await deleteSecurityState("password-reset", key);
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }

    // Re-check account status from PostgreSQL at verification time. This closes
    // the door if an account was promoted to admin after the code was issued.
    const userResult = await pool.query(
      "SELECT id, is_admin FROM users WHERE id = $1 AND username = $2",
      [stored.userId, key]
    );
    if (userResult.rows.length === 0 || userResult.rows[0].is_admin) {
      await deleteSecurityState("password-reset", key);
      return res.status(400).json({ error: "That reset request is no longer valid" });
    }

    await deleteSecurityState("password-reset", key);
    const resetToken = jwt.sign(
      { type: "password_reset", userId: userResult.rows[0].id },
      JWT_SECRET,
      { expiresIn: "10m" }
    );
    res.json({ resetToken });
  } catch (err) {
    sendInternalError(res, err);
  }
});

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

    // Public reset tokens can never reset an administrator, even if the account
    // changed roles after the token was issued.
    const account = await pool.query("SELECT id, is_admin FROM users WHERE id = $1", [decoded.userId]);
    if (account.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    if (account.rows[0].is_admin) {
      return res.status(403).json({ error: "This reset session is not valid" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      `UPDATE users
       SET password_hash = $1,
           token_version = COALESCE(token_version, 0) + 1
       WHERE id = $2 AND COALESCE(is_admin, false) = false
       RETURNING id`,
      [passwordHash, decoded.userId]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: "This reset session is not valid" });

    // Every pre-reset JWT is now invalid because token_version advanced. Clear
    // any cookie in this browser as well so the client immediately reflects it.
    clearAuthCookie(res);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/", (req, res) => {
  res.send("Stallyard backend is running!");
});

app.get("/db-check", async (req, res) => {
  // Do not expose database diagnostics publicly in production. The protected
  // Admin System Health page is the supported production diagnostic surface.
  if (process.env.NODE_ENV === "production") {
    return res.status(404).json({ error: "Not found" });
  }
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (err) {
    sendInternalError(res, err, "development database check");
  }
});

// Database schema migrations are versioned and applied automatically at backend startup.
// This replaces the old public /migrate/... URLs and keeps migration secrets out of browser history/logs.
// Each migration is idempotent, and schema_migrations records completed versions so later deploys only run new work.
const SCHEMA_MIGRATIONS = [
  { version: 1, name: "members-extra", statements: [
    `
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS account_type TEXT DEFAULT 'personal',
        ADD COLUMN IF NOT EXISTS id_type TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS id_country TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS license_number TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS license_photos JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS id_verification_exempt BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS has_applied_to_sell BOOLEAN DEFAULT false
    `,
  ] },
  { version: 2, name: "follows", statements: [
    `
      CREATE TABLE IF NOT EXISTS follows (
        id SERIAL PRIMARY KEY,
        follower_username TEXT NOT NULL,
        followed_username TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE (follower_username, followed_username)
      )
    `,
  ] },
  { version: 3, name: "listings-extra", statements: [
    `
      ALTER TABLE listings
        ADD COLUMN IF NOT EXISTS emoji TEXT DEFAULT '📦',
        ADD COLUMN IF NOT EXISTS fit_make TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS fit_model TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS fit_year TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS images JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS listing_type TEXT DEFAULT 'fixed',
        ADD COLUMN IF NOT EXISTS currency TEXT DEFAULT 'NGN',
        ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending',
        ADD COLUMN IF NOT EXISTS is_featured BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS auction_end_time TIMESTAMP,
        ADD COLUMN IF NOT EXISTS bid_history JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS highest_bidder_username TEXT
    `,
  ] },
  { version: 4, name: "orders-wallet", statements: [
    `
      ALTER TABLE orders
        ADD COLUMN IF NOT EXISTS buyer_username TEXT,
        ADD COLUMN IF NOT EXISTS shipping_address JSONB DEFAULT '{}'::jsonb,
        ADD COLUMN IF NOT EXISTS subtotal NUMERIC DEFAULT 0,
        ADD COLUMN IF NOT EXISTS shipping_total NUMERIC DEFAULT 0,
        ADD COLUMN IF NOT EXISTS commission_rate NUMERIC DEFAULT 0.05,
        ADD COLUMN IF NOT EXISTS commission_amount NUMERIC DEFAULT 0,
        ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'held',
        ADD COLUMN IF NOT EXISTS is_disputed BOOLEAN DEFAULT false
    `,
    `
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
    `,
    `
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
    `,
  ] },
  { version: 5, name: "signup-stages", statements: [
    `
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS profile_complete BOOLEAN DEFAULT false
    `,
    `ALTER TABLE users ALTER COLUMN phone DROP NOT NULL`,
  ] },
  { version: 6, name: "seller-verification", statements: [
    `
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS verification_status TEXT DEFAULT 'none',
        ADD COLUMN IF NOT EXISTS bank_statement_url TEXT,
        ADD COLUMN IF NOT EXISTS rejection_reason TEXT
    `,
    `
      UPDATE users SET verification_status =
        CASE WHEN is_approved THEN 'approved'
             WHEN has_applied_to_sell THEN 'pending'
             ELSE 'none' END
      WHERE verification_status IS NULL OR verification_status = 'none'
    `,
  ] },
  { version: 7, name: "listings-extra-fields", statements: [
    `
      ALTER TABLE listings
        ADD COLUMN IF NOT EXISTS quantity INTEGER,
        ADD COLUMN IF NOT EXISTS sku TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS brand TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS state TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS shipping_methods JSONB DEFAULT '[]'::jsonb,
        ADD COLUMN IF NOT EXISTS return_policy TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS vin TEXT DEFAULT ''
    `,
  ] },
  { version: 8, name: "order-management", statements: [
    `
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS carrier TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS buyer_confirmed_at TIMESTAMP
    `,
  ] },
  { version: 9, name: "proof-of-delivery", statements: [
    `
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS proof_of_delivery_url TEXT DEFAULT ''
    `,
  ] },
  { version: 10, name: "delivery-token", statements: [
    `
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS delivery_token TEXT,
        ADD COLUMN IF NOT EXISTS delivery_token_generated_at TIMESTAMP
    `,
  ] },
  { version: 11, name: "message-features", statements: [
    `
      ALTER TABLE messages
        ADD COLUMN IF NOT EXISTS image_url TEXT,
        ADD COLUMN IF NOT EXISTS order_id INTEGER
    `,
    `
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
    `,
  ] },
  { version: 12, name: "returns", statements: [
    `
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS return_status TEXT,
        ADD COLUMN IF NOT EXISTS return_reason TEXT,
        ADD COLUMN IF NOT EXISTS return_note TEXT,
        ADD COLUMN IF NOT EXISTS return_requested_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS return_tracking_number TEXT,
        ADD COLUMN IF NOT EXISTS return_evidence_urls JSONB DEFAULT '[]'::jsonb
    `,
  ] },
  { version: 13, name: "review-features", statements: [
    `
      ALTER TABLE reviews
        ADD COLUMN IF NOT EXISTS seller_response TEXT,
        ADD COLUMN IF NOT EXISTS seller_response_at TIMESTAMP
    `,
    `
      CREATE TABLE IF NOT EXISTS review_reports (
        id SERIAL PRIMARY KEY,
        review_id INTEGER NOT NULL,
        reporter_id INTEGER NOT NULL,
        reason TEXT DEFAULT '',
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP
      )
    `,
  ] },
  { version: 14, name: "store-profile", statements: [
    `
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS avatar_url TEXT,
        ADD COLUMN IF NOT EXISTS store_bio TEXT,
        ADD COLUMN IF NOT EXISTS store_policies TEXT
    `,
  ] },
  { version: 15, name: "notifications", statements: [
    `
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      ALTER TABLE order_items
        ADD COLUMN IF NOT EXISTS ship_reminder_sent_at TIMESTAMP
    `,
  ] },
  { version: 16, name: "login-history", statements: [
    `
      CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ip TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
  ] },
  { version: 17, name: "two-factor", statements: [
    `
      ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT false
    `,
  ] },
  { version: 18, name: "totp", statements: [
    `
      ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT
    `,
  ] },
  { version: 19, name: "addresses", statements: [
    `
      CREATE TABLE IF NOT EXISTS user_addresses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        label TEXT DEFAULT '',
        street TEXT DEFAULT '',
        city TEXT DEFAULT '',
        state TEXT DEFAULT '',
        zip TEXT DEFAULT '',
        country TEXT DEFAULT '',
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_user_addresses_user_id ON user_addresses(user_id)
    `,
  ] },
  { version: 20, name: "paystack-checkout", statements: [
    `
      ALTER TABLE orders
        ADD COLUMN IF NOT EXISTS paystack_reference TEXT,
        ADD COLUMN IF NOT EXISTS payment_channel TEXT,
        ADD COLUMN IF NOT EXISTS payment_card_type TEXT,
        ADD COLUMN IF NOT EXISTS payment_bank TEXT,
        ADD COLUMN IF NOT EXISTS payment_last4 TEXT
    `,
    `
      CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_paystack_reference
      ON orders(paystack_reference) WHERE paystack_reference IS NOT NULL
    `,
  ] },
  { version: 21, name: "refunds", statements: [
    `
      ALTER TABLE orders
        ADD COLUMN IF NOT EXISTS refund_status TEXT,
        ADD COLUMN IF NOT EXISTS paystack_refund_id BIGINT,
        ADD COLUMN IF NOT EXISTS refund_previous_payment_status TEXT,
        ADD COLUMN IF NOT EXISTS refund_requested_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS refund_failure_reason TEXT
    `,
  ] },
  { version: 22, name: "refund-management", statements: [
    `
      ALTER TABLE orders
        ADD COLUMN IF NOT EXISTS refund_reason TEXT,
        ADD COLUMN IF NOT EXISTS refund_requested_by INTEGER REFERENCES users(id)
    `,
  ] },
  { version: 23, name: "partial-refunds", statements: [
    `
      ALTER TABLE orders
        ADD COLUMN IF NOT EXISTS refund_type TEXT,
        ADD COLUMN IF NOT EXISTS refund_amount NUMERIC DEFAULT 0
    `,
  ] },
  { version: 24, name: "saved-cards", statements: [
    `
      CREATE TABLE IF NOT EXISTS saved_cards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        authorization_code TEXT NOT NULL,
        authorization_code_hash TEXT,
        card_type TEXT,
        last4 TEXT,
        bank TEXT,
        exp_month TEXT,
        exp_year TEXT,
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `ALTER TABLE saved_cards ADD COLUMN IF NOT EXISTS authorization_code_hash TEXT`,
    `DROP INDEX IF EXISTS idx_saved_cards_user_auth`,
    `
      CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_cards_user_auth_hash
      ON saved_cards(user_id, authorization_code_hash) WHERE authorization_code_hash IS NOT NULL
    `,
  ] },
  { version: 25, name: "ships-to-usa", statements: [
    `ALTER TABLE listings ADD COLUMN IF NOT EXISTS ships_to_usa BOOLEAN DEFAULT false`,
  ] },
  { version: 26, name: "tax-rate", statements: [
    `ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS tax_rate NUMERIC DEFAULT 0`,
    `ALTER TABLE orders ADD COLUMN IF NOT EXISTS tax_amount NUMERIC DEFAULT 0`,
  ] },
  { version: 27, name: "flagged-images", statements: [
    `ALTER TABLE listings ADD COLUMN IF NOT EXISTS flagged_images JSONB DEFAULT '[]'::jsonb`,
  ] },
  { version: 28, name: "hidden-images", statements: [
    `ALTER TABLE listings ADD COLUMN IF NOT EXISTS hidden_image_urls JSONB DEFAULT '[]'::jsonb`,
  ] },
  { version: 29, name: "phone-verified", statements: [
    `
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_phone_verified BOOLEAN DEFAULT false
    `,
  ] },
  { version: 30, name: "sessions", statements: [
    `
      ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0
    `,
    `
      CREATE TABLE IF NOT EXISTS account_reports (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP
      )
    `,
  ] },
  { version: 31, name: "seller-performance", statements: [
    `
      ALTER TABLE order_items ADD COLUMN IF NOT EXISTS shipped_at TIMESTAMP
    `,
    `
      CREATE TABLE IF NOT EXISTS seller_warnings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        admin_id INTEGER REFERENCES users(id),
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
  ] },
  { version: 32, name: "buyer-risk", statements: [
    `
      CREATE TABLE IF NOT EXISTS payment_attempts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reference TEXT,
        method TEXT DEFAULT 'checkout',
        status TEXT NOT NULL,
        amount NUMERIC DEFAULT 0,
        currency TEXT DEFAULT 'NGN',
        message TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_payment_attempts_user_id ON payment_attempts(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_payment_attempts_reference ON payment_attempts(reference)`,
  ] },
  { version: 33, name: "admin-roles", statements: [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_role TEXT`,
    `UPDATE users SET admin_role = 'super_admin' WHERE is_admin = true AND admin_role IS NULL`,
    `
      CREATE TABLE IF NOT EXISTS admin_audit_log (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(id),
        action TEXT NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
  ] },
  { version: 34, name: "admin-staff-management", statements: [
    `
      CREATE TABLE IF NOT EXISTS admin_role_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        changed_by INTEGER REFERENCES users(id),
        old_role TEXT,
        new_role TEXT,
        reason TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_admin_role_history_user_id ON admin_role_history(user_id, created_at DESC)`,
  ] },
  { version: 35, name: "admin-temporary-passwords", statements: [
    `
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS admin_temp_password_hash TEXT,
        ADD COLUMN IF NOT EXISTS admin_temp_password_expires_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS admin_temp_password_created_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS admin_temp_password_created_by INTEGER REFERENCES users(id)
    `,
  ] },
  { version: 36, name: "site-settings", statements: [
    `
      CREATE TABLE IF NOT EXISTS site_settings (
        id INTEGER PRIMARY KEY DEFAULT 1,
        commission_rate NUMERIC DEFAULT 0.05,
        auth_image TEXT DEFAULT '',
        CHECK (id = 1)
      )
    `,
    `INSERT INTO site_settings (id, commission_rate) VALUES (1, 0.05) ON CONFLICT (id) DO NOTHING`,
  ] },
  { version: 37, name: "dispute-cases", statements: [
    `
      CREATE TABLE IF NOT EXISTS dispute_cases (
        id SERIAL PRIMARY KEY,
        order_id INTEGER NOT NULL UNIQUE REFERENCES orders(id) ON DELETE CASCADE,
        opened_by_id INTEGER REFERENCES users(id),
        reason TEXT DEFAULT '',
        buyer_statement TEXT DEFAULT '',
        seller_statement TEXT DEFAULT '',
        evidence_urls JSONB DEFAULT '[]'::jsonb,
        status TEXT DEFAULT 'open',
        resolution TEXT,
        resolution_note TEXT DEFAULT '',
        admin_notes TEXT DEFAULT '',
        resolved_by_id INTEGER REFERENCES users(id),
        opened_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        resolved_at TIMESTAMP
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_dispute_cases_status ON dispute_cases(status)`,
    `CREATE INDEX IF NOT EXISTS idx_dispute_cases_order_id ON dispute_cases(order_id)`,
    `
      INSERT INTO dispute_cases (order_id, opened_by_id, reason, status, opened_at, updated_at)
      SELECT id, buyer_id, 'Legacy dispute — add case details during review', 'open', created_at, NOW()
      FROM orders
      WHERE COALESCE(is_disputed, false) = true
      ON CONFLICT (order_id) DO NOTHING
    `,
  ] },
  { version: 38, name: "help-support", statements: [
    `
      CREATE TABLE IF NOT EXISTS banners (
        id SERIAL PRIMARY KEY,
        message TEXT NOT NULL,
        tone TEXT DEFAULT 'info',
        is_active BOOLEAN DEFAULT true,
        media_type TEXT DEFAULT 'none',
        image_url TEXT DEFAULT '',
        video_url TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS help_articles (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS help_faqs (
        id SERIAL PRIMARY KEY,
        question TEXT NOT NULL,
        answer TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS marketplace_policies (
        category TEXT PRIMARY KEY,
        body TEXT DEFAULT '',
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      INSERT INTO marketplace_policies (category, body) VALUES
        ('seller_rules', ''), ('prohibited_items', ''), ('fees', ''),
        ('payment_rules', ''), ('shipping_rules', ''), ('returns_disputes', '')
      ON CONFLICT (category) DO NOTHING
    `,
    `
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS support_ticket_messages (
        id SERIAL PRIMARY KEY,
        ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
        sender_id INTEGER NOT NULL REFERENCES users(id),
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
  ] },
  { version: 39, name: "cart-watchlist", statements: [
    `
      CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER NOT NULL,
        qty INTEGER NOT NULL DEFAULT 1,
        offer_price NUMERIC,
        UNIQUE (user_id, listing_id)
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS watchlist_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE (user_id, listing_id)
      )
    `,
  ] },
  { version: 40, name: "admin-notes", statements: [
    `
      CREATE TABLE IF NOT EXISTS admin_notes (
        id SERIAL PRIMARY KEY,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        admin_id INTEGER NOT NULL REFERENCES users(id),
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        CHECK (entity_type IN ('member', 'listing', 'order', 'dispute', 'support_ticket'))
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_admin_notes_entity ON admin_notes(entity_type, entity_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_admin_notes_admin ON admin_notes(admin_id, created_at DESC)`,
  ] },
  { version: 41, name: "nigeria-only-cleanup", statements: [
    `ALTER TABLE listings ALTER COLUMN currency SET DEFAULT 'NGN'`,
    `UPDATE listings SET currency = 'NGN' WHERE currency IS NULL OR UPPER(currency) <> 'NGN'`,
    `UPDATE orders SET currency = 'NGN' WHERE currency IS NULL OR UPPER(currency) <> 'NGN'`,
    `UPDATE payment_attempts SET currency = 'NGN' WHERE currency IS NULL OR UPPER(currency) <> 'NGN'`,
    `ALTER TABLE listings DROP COLUMN IF EXISTS ships_to_usa`,
  ] },
  { version: 42, name: "canonical-active-listing-status", statements: [
    `UPDATE listings SET status = 'active' WHERE status = 'approved'`,
  ] },
  { version: 43, name: "checkout-payment-integrity", statements: [
    `
      CREATE TABLE IF NOT EXISTS checkout_intents (
        reference TEXT PRIMARY KEY,
        buyer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        buyer_username TEXT NOT NULL,
        buyer_email TEXT NOT NULL,
        amount_kobo BIGINT NOT NULL CHECK (amount_kobo > 0),
        currency TEXT NOT NULL DEFAULT 'NGN',
        items JSONB NOT NULL DEFAULT '[]'::jsonb,
        shipping_address JSONB NOT NULL DEFAULT '{}'::jsonb,
        save_card BOOLEAN DEFAULT false,
        status TEXT NOT NULL DEFAULT 'initialized',
        failure_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        finalized_at TIMESTAMP
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_checkout_intents_buyer ON checkout_intents(buyer_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_checkout_intents_status ON checkout_intents(status, created_at DESC)`,
  ] },
  { version: 44, name: "checkout-listing-reservations", statements: [
    `
      CREATE TABLE IF NOT EXISTS listing_checkout_reservations (
        listing_id INTEGER PRIMARY KEY REFERENCES listings(id) ON DELETE CASCADE,
        buyer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reference TEXT NOT NULL REFERENCES checkout_intents(reference) ON DELETE CASCADE,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_listing_checkout_reservations_reference ON listing_checkout_reservations(reference)`,
    `CREATE INDEX IF NOT EXISTS idx_listing_checkout_reservations_expires ON listing_checkout_reservations(expires_at)`,
  ] },
  { version: 45, name: "persistent-security-state", statements: [
    `
      CREATE TABLE IF NOT EXISTS security_rate_limits (
        rate_key TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        hit_count INTEGER NOT NULL DEFAULT 0,
        window_started_at TIMESTAMP NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_security_rate_limits_expires ON security_rate_limits(expires_at)`,
    `CREATE INDEX IF NOT EXISTS idx_security_rate_limits_scope ON security_rate_limits(scope, expires_at)`,
    `
      CREATE TABLE IF NOT EXISTS security_ephemeral_state (
        state_key TEXT PRIMARY KEY,
        namespace TEXT NOT NULL,
        payload_encrypted TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `,
    `CREATE INDEX IF NOT EXISTS idx_security_ephemeral_state_expires ON security_ephemeral_state(expires_at)`,
    `CREATE INDEX IF NOT EXISTS idx_security_ephemeral_state_namespace ON security_ephemeral_state(namespace, expires_at)`,
  ] },
  { version: 46, name: "homepage-ads", statements: [
    `
      CREATE TABLE IF NOT EXISTS homepage_ads (
        slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 3),
        image_url TEXT NOT NULL DEFAULT '',
        link_url TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
      )
    `,
    `INSERT INTO homepage_ads (slot) VALUES (1), (2), (3) ON CONFLICT (slot) DO NOTHING`,
  ] },
  { version: 47, name: "homepage-ad-video", statements: [
    `ALTER TABLE homepage_ads ADD COLUMN IF NOT EXISTS media_type TEXT NOT NULL DEFAULT 'image'`,
    `ALTER TABLE homepage_ads ADD COLUMN IF NOT EXISTS poster_url TEXT NOT NULL DEFAULT ''`,
    `UPDATE homepage_ads SET media_type = 'image' WHERE slot IN (2, 3) OR media_type NOT IN ('image', 'video')`,
  ] },
  { version: 48, name: "listing-subcategories", statements: [
    `ALTER TABLE listings ADD COLUMN IF NOT EXISTS subcategory TEXT NOT NULL DEFAULT ''`,
    `CREATE INDEX IF NOT EXISTS idx_listings_category_subcategory ON listings(category, subcategory)`,
  ] },  { version: 49, name: "delivery-token-after-buyer-confirmation", statements: [
    `UPDATE order_items oi
       SET delivery_token = NULL, delivery_token_generated_at = NULL
      FROM orders o
      WHERE o.id = oi.order_id
        AND o.payment_status = 'held'
        AND oi.buyer_confirmed_at IS NULL
        AND oi.delivery_token IS NOT NULL`,
  ] },
  { version: 50, name: "private-delivery-location-details", statements: [
    `ALTER TABLE user_addresses
       ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT '',
       ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT '',
       ADD COLUMN IF NOT EXISTS delivery_instructions TEXT NOT NULL DEFAULT '',
       ADD COLUMN IF NOT EXISTS preferred_delivery_time TEXT NOT NULL DEFAULT '',
       ADD COLUMN IF NOT EXISTS location_photos JSONB NOT NULL DEFAULT '[]'::jsonb`,
  ] },
  { version: 51, name: "automatic-seller-payouts", statements: [
    `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS delivery_token_redeemed_at TIMESTAMP`,
    `UPDATE order_items oi SET delivery_token_redeemed_at = COALESCE(oi.buyer_confirmed_at, NOW())
      FROM orders o WHERE o.id = oi.order_id AND o.payment_status = 'released'
        AND oi.buyer_confirmed_at IS NOT NULL AND COALESCE(oi.proof_of_delivery_url, '') <> ''
        AND oi.delivery_token_redeemed_at IS NULL`,
    `CREATE TABLE IF NOT EXISTS seller_payouts (
       id SERIAL PRIMARY KEY,
       order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
       seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
       amount NUMERIC NOT NULL CHECK (amount > 0),
       currency TEXT NOT NULL DEFAULT 'NGN',
       status TEXT NOT NULL DEFAULT 'queued',
       paystack_reference TEXT NOT NULL UNIQUE,
       paystack_transfer_code TEXT,
       failure_reason TEXT,
       initiated_at TIMESTAMP,
       completed_at TIMESTAMP,
       reversed_at TIMESTAMP,
       created_at TIMESTAMP NOT NULL DEFAULT NOW(),
       updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
       UNIQUE(order_id, seller_id)
     )`,
    `CREATE INDEX IF NOT EXISTS idx_seller_payouts_seller ON seller_payouts(seller_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_seller_payouts_order ON seller_payouts(order_id)`,
  ] },
  { version: 52, name: "delivery-token-created-after-payment", statements: [
    `SELECT 1`,
  ] },
  { version: 53, name: "buyer-token-visible-after-payment", statements: [
    `SELECT 1`,
  ] },
  { version: 54, name: "buyer-sends-delivery-token-to-seller", statements: [
    `ALTER TABLE order_items ADD COLUMN IF NOT EXISTS delivery_token_sent_at TIMESTAMP`,
  ] },
  { version: 55, name: "buyer-cancellation-requests", statements: [
    `ALTER TABLE order_items
       ADD COLUMN IF NOT EXISTS cancellation_status TEXT,
       ADD COLUMN IF NOT EXISTS cancellation_reason TEXT,
       ADD COLUMN IF NOT EXISTS cancellation_requested_at TIMESTAMP,
       ADD COLUMN IF NOT EXISTS cancellation_responded_at TIMESTAMP`,
  ] },
  { version: 56, name: "close-buyer-claims-after-payment-release", statements: [
    `SELECT 1`,
  ] },
  { version: 57, name: "automatic-buyer-refund-with-cancellation-fee", statements: [
    `ALTER TABLE orders
       ADD COLUMN IF NOT EXISTS cancellation_fee NUMERIC NOT NULL DEFAULT 0,
       ADD COLUMN IF NOT EXISTS buyer_exit_type TEXT`,
  ] },
  { version: 58, name: "estimated-delivery-window", statements: [
    `ALTER TABLE order_items
       ADD COLUMN IF NOT EXISTS estimated_delivery_start DATE,
       ADD COLUMN IF NOT EXISTS estimated_delivery_end DATE`,
  ] },
  { version: 59, name: "seller-live-delivery-location", statements: [
    `ALTER TABLE order_items
       ADD COLUMN IF NOT EXISTS live_location_enabled BOOLEAN NOT NULL DEFAULT FALSE,
       ADD COLUMN IF NOT EXISTS live_location_latitude NUMERIC,
       ADD COLUMN IF NOT EXISTS live_location_longitude NUMERIC,
       ADD COLUMN IF NOT EXISTS live_location_accuracy NUMERIC,
       ADD COLUMN IF NOT EXISTS live_location_updated_at TIMESTAMP,
       ADD COLUMN IF NOT EXISTS live_location_expires_at TIMESTAMP`,
  ] },
  { version: 60, name: "permanent-order-status-history", statements: [
    `CREATE TABLE IF NOT EXISTS order_item_status_events (
       id SERIAL PRIMARY KEY,
       order_item_id INTEGER NOT NULL REFERENCES order_items(id) ON DELETE CASCADE,
       event_type TEXT NOT NULL,
       label TEXT NOT NULL,
       details JSONB NOT NULL DEFAULT '{}'::jsonb,
       created_at TIMESTAMP NOT NULL DEFAULT NOW()
     )`,
    `CREATE INDEX IF NOT EXISTS idx_order_item_status_events_item_time
       ON order_item_status_events(order_item_id, created_at, id)`,
    `INSERT INTO order_item_status_events (order_item_id, event_type, label, created_at)
       SELECT oi.id, 'order_placed', 'Order placed', COALESCE(oi.created_at, o.created_at, NOW())
       FROM order_items oi JOIN orders o ON o.id = oi.order_id
       WHERE NOT EXISTS (SELECT 1 FROM order_item_status_events e WHERE e.order_item_id = oi.id)`,
    `INSERT INTO order_item_status_events (order_item_id, event_type, label, created_at)
       SELECT oi.id, oi.fulfillment_status,
         CASE oi.fulfillment_status WHEN 'preparing' THEN 'Seller is preparing the order' WHEN 'shipped' THEN 'Order shipped'
           WHEN 'delivered' THEN 'Marked delivered' WHEN 'cancelled' THEN 'Order cancelled'
           WHEN 'returned' THEN 'Order returned' ELSE 'Order status updated' END,
         COALESCE(oi.shipped_at, NOW())
       FROM order_items oi
       WHERE oi.fulfillment_status <> 'new'
         AND NOT EXISTS (SELECT 1 FROM order_item_status_events e WHERE e.order_item_id = oi.id AND e.event_type = oi.fulfillment_status)`,
    `CREATE OR REPLACE FUNCTION record_order_item_status_event() RETURNS TRIGGER AS $$
     BEGIN
       IF TG_OP = 'INSERT' THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label, created_at)
         VALUES (NEW.id, 'order_placed', 'Order placed', COALESCE(NEW.created_at, NOW()));
         RETURN NEW;
       END IF;
       IF NEW.fulfillment_status IS DISTINCT FROM OLD.fulfillment_status THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label)
         VALUES (NEW.id, NEW.fulfillment_status,
           CASE NEW.fulfillment_status WHEN 'preparing' THEN 'Seller is preparing the order' WHEN 'shipped' THEN 'Order shipped'
             WHEN 'delivered' THEN 'Marked delivered' WHEN 'cancelled' THEN 'Order cancelled'
             WHEN 'returned' THEN 'Order returned' ELSE 'Order status updated' END);
       END IF;
       IF ROW(NEW.estimated_delivery_start, NEW.estimated_delivery_end) IS DISTINCT FROM ROW(OLD.estimated_delivery_start, OLD.estimated_delivery_end) THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label, details)
         VALUES (NEW.id,
           CASE WHEN OLD.estimated_delivery_end IS NOT NULL AND NEW.estimated_delivery_end > OLD.estimated_delivery_end THEN 'delivery_delayed' ELSE 'delivery_estimate_updated' END,
           CASE WHEN OLD.estimated_delivery_end IS NOT NULL AND NEW.estimated_delivery_end > OLD.estimated_delivery_end THEN 'Estimated delivery delayed' ELSE 'Estimated delivery updated' END,
           jsonb_build_object('start', NEW.estimated_delivery_start, 'end', NEW.estimated_delivery_end));
       END IF;
       IF NEW.live_location_enabled IS DISTINCT FROM OLD.live_location_enabled THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label)
         VALUES (NEW.id, CASE WHEN NEW.live_location_enabled THEN 'out_for_delivery' ELSE 'location_sharing_stopped' END,
           CASE WHEN NEW.live_location_enabled THEN 'Out for delivery — location sharing started' ELSE 'Live location sharing stopped' END);
       END IF;
       IF NEW.proof_of_delivery_url IS NOT NULL AND OLD.proof_of_delivery_url IS NULL THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label) VALUES (NEW.id, 'delivery_proof_uploaded', 'Delivery photo uploaded');
       END IF;
       IF NEW.delivery_token_sent_at IS NOT NULL AND OLD.delivery_token_sent_at IS NULL THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label) VALUES (NEW.id, 'delivery_token_sent', 'Buyer sent delivery token to seller');
       END IF;
       IF NEW.delivery_token_redeemed_at IS NOT NULL AND OLD.delivery_token_redeemed_at IS NULL THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label) VALUES (NEW.id, 'delivery_token_redeemed', 'Delivery token verified');
       END IF;
       IF NEW.buyer_confirmed_at IS NOT NULL AND OLD.buyer_confirmed_at IS NULL THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label) VALUES (NEW.id, 'buyer_confirmed', 'Buyer confirmed receipt');
       END IF;
       IF NEW.cancellation_status IS DISTINCT FROM OLD.cancellation_status AND NEW.cancellation_status IS NOT NULL THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label)
         VALUES (NEW.id, 'cancellation_' || NEW.cancellation_status, 'Cancellation ' || NEW.cancellation_status);
       END IF;
       IF NEW.return_status IS DISTINCT FROM OLD.return_status AND NEW.return_status IS NOT NULL THEN
         INSERT INTO order_item_status_events(order_item_id, event_type, label)
         VALUES (NEW.id, 'return_' || NEW.return_status, 'Return ' || NEW.return_status);
       END IF;
       RETURN NEW;
     END; $$ LANGUAGE plpgsql`,
    `DROP TRIGGER IF EXISTS trg_order_item_status_event ON order_items`,
    `CREATE TRIGGER trg_order_item_status_event AFTER INSERT OR UPDATE ON order_items
       FOR EACH ROW EXECUTE FUNCTION record_order_item_status_event()`,
    `CREATE OR REPLACE FUNCTION record_order_payment_status_event() RETURNS TRIGGER AS $$
     DECLARE item_id INTEGER; event_name TEXT; event_label TEXT;
     BEGIN
       IF NEW.payment_status IS DISTINCT FROM OLD.payment_status OR NEW.refund_status IS DISTINCT FROM OLD.refund_status THEN
         event_name := CASE WHEN NEW.payment_status = 'released' THEN 'payment_released'
           WHEN NEW.payment_status = 'refunded' OR NEW.refund_status = 'processed' THEN 'refund_completed'
           WHEN NEW.refund_status = 'failed' THEN 'refund_failed'
           WHEN NEW.refund_type = 'buyer_cancellation' AND NEW.payment_status = 'refund_pending' AND OLD.payment_status IS DISTINCT FROM NEW.payment_status THEN 'cancellation_submitted'
           WHEN NEW.payment_status = 'refund_pending' THEN 'refund_processing' ELSE 'payment_updated' END;
         event_label := CASE event_name WHEN 'payment_released' THEN 'Payment released to seller'
           WHEN 'refund_completed' THEN 'Refund completed' WHEN 'refund_failed' THEN 'Refund failed — action required'
           WHEN 'cancellation_submitted' THEN 'Cancellation submitted — refund started'
           WHEN 'refund_processing' THEN 'Refund submitted to Paystack' ELSE 'Payment status updated' END;
         FOR item_id IN SELECT id FROM order_items WHERE order_id = NEW.id LOOP
           INSERT INTO order_item_status_events(order_item_id, event_type, label, details)
           VALUES (item_id, event_name, event_label, jsonb_build_object('paymentStatus', NEW.payment_status, 'refundStatus', NEW.refund_status));
         END LOOP;
       END IF;
       RETURN NEW;
     END; $$ LANGUAGE plpgsql`,
    `DROP TRIGGER IF EXISTS trg_order_payment_status_event ON orders`,
    `CREATE TRIGGER trg_order_payment_status_event AFTER UPDATE ON orders
       FOR EACH ROW EXECUTE FUNCTION record_order_payment_status_event()`,
    `CREATE OR REPLACE FUNCTION record_dispute_status_event() RETURNS TRIGGER AS $$
     DECLARE item_id INTEGER;
     BEGIN
       IF TG_OP = 'INSERT' OR NEW.status IS DISTINCT FROM OLD.status THEN
         FOR item_id IN SELECT id FROM order_items WHERE order_id = NEW.order_id LOOP
           INSERT INTO order_item_status_events(order_item_id, event_type, label)
           VALUES (item_id, CASE WHEN TG_OP = 'INSERT' THEN 'dispute_opened' ELSE 'dispute_' || NEW.status END,
             CASE WHEN TG_OP = 'INSERT' THEN 'Dispute opened — payment locked' ELSE 'Dispute ' || NEW.status END);
         END LOOP;
       END IF;
       RETURN NEW;
     END; $$ LANGUAGE plpgsql`,
    `DROP TRIGGER IF EXISTS trg_dispute_status_event ON dispute_cases`,
    `CREATE TRIGGER trg_dispute_status_event AFTER INSERT OR UPDATE ON dispute_cases
       FOR EACH ROW EXECUTE FUNCTION record_dispute_status_event()`,
  ] },
  { version: 61, name: "buyer-seller-reports", statements: [
    `CREATE TABLE IF NOT EXISTS seller_reports (
       id SERIAL PRIMARY KEY,
       reference TEXT NOT NULL UNIQUE,
       reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
       reported_seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
       order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
       reason TEXT NOT NULL,
       details TEXT NOT NULL,
       evidence_urls JSONB NOT NULL DEFAULT '[]'::jsonb,
       status TEXT NOT NULL DEFAULT 'open',
       admin_note TEXT,
       reviewed_by INTEGER REFERENCES users(id),
       created_at TIMESTAMP NOT NULL DEFAULT NOW(),
       updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
       resolved_at TIMESTAMP
     )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_seller_report
       ON seller_reports(reporter_id, reported_seller_id, COALESCE(order_id, 0))
       WHERE status IN ('open', 'in_review')`,
    `CREATE INDEX IF NOT EXISTS idx_seller_reports_admin_queue ON seller_reports(status, created_at DESC)`,
  ] },
  { version: 62, name: "refund-progress-updated-at", statements: [
    `ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_updated_at TIMESTAMP`,
    `CREATE OR REPLACE FUNCTION set_refund_progress_updated_at() RETURNS TRIGGER AS $$
     BEGIN
       IF NEW.refund_status IS DISTINCT FROM OLD.refund_status OR NEW.payment_status IS DISTINCT FROM OLD.payment_status THEN
         NEW.refund_updated_at = NOW();
       END IF;
       RETURN NEW;
     END; $$ LANGUAGE plpgsql`,
    `DROP TRIGGER IF EXISTS trg_refund_progress_updated_at ON orders`,
    `CREATE TRIGGER trg_refund_progress_updated_at BEFORE UPDATE ON orders
       FOR EACH ROW EXECUTE FUNCTION set_refund_progress_updated_at()`,
  ] },
  { version: 63, name: "casual-seller-automatic-verification", statements: [
    `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS casual_seller_status TEXT NOT NULL DEFAULT 'none',
       ADD COLUMN IF NOT EXISTS casual_seller_limit NUMERIC(14,2) NOT NULL DEFAULT 500000,
       ADD COLUMN IF NOT EXISTS casual_seller_approved_at TIMESTAMP,
       ADD COLUMN IF NOT EXISTS casual_seller_suspended_at TIMESTAMP`,
    `CREATE TABLE IF NOT EXISTS casual_seller_applications (
       id BIGSERIAL PRIMARY KEY,
       reference TEXT NOT NULL UNIQUE,
       user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
       legal_name TEXT NOT NULL,
       date_of_birth DATE NOT NULL,
       id_type TEXT NOT NULL,
       id_number_hash TEXT NOT NULL,
       id_number_last4 TEXT NOT NULL,
       id_expiration DATE,
       evidence_paths JSONB NOT NULL DEFAULT '{}'::jsonb,
       evidence_hashes JSONB NOT NULL DEFAULT '{}'::jsonb,
       face_descriptor JSONB,
       liveness_challenges JSONB NOT NULL DEFAULT '[]'::jsonb,
       automatic_checks JSONB NOT NULL DEFAULT '{}'::jsonb,
       status TEXT NOT NULL,
       decision_reason TEXT,
       consent_version TEXT NOT NULL,
       consented_at TIMESTAMP NOT NULL,
       submitted_ip_hash TEXT,
       submitted_user_agent TEXT,
       approved_at TIMESTAMP,
       suspended_at TIMESTAMP,
       included_in_report_id BIGINT,
       created_at TIMESTAMP NOT NULL DEFAULT NOW(),
       updated_at TIMESTAMP NOT NULL DEFAULT NOW()
     )`,
    `ALTER TABLE casual_seller_applications ADD COLUMN IF NOT EXISTS face_descriptor JSONB`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_casual_seller_identity_once
       ON casual_seller_applications(id_number_hash)
       WHERE status IN ('approved', 'suspended')`,
    `CREATE INDEX IF NOT EXISTS idx_casual_seller_applications_user
       ON casual_seller_applications(user_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_casual_seller_daily_report_queue
       ON casual_seller_applications(status, approved_at)
       WHERE status = 'approved' AND included_in_report_id IS NULL`,
    `CREATE TABLE IF NOT EXISTS casual_seller_daily_reports (
       id BIGSERIAL PRIMARY KEY,
       report_date DATE NOT NULL UNIQUE,
       application_count INTEGER NOT NULL DEFAULT 0,
       pdf_storage_path TEXT,
       pdf_sha256 TEXT,
       email_recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
       email_status TEXT NOT NULL DEFAULT 'pending',
       email_error TEXT,
       emailed_at TIMESTAMP,
       created_at TIMESTAMP NOT NULL DEFAULT NOW()
     )`,
    `DO $$ BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'casual_seller_applications_report_fk') THEN
         ALTER TABLE casual_seller_applications ADD CONSTRAINT casual_seller_applications_report_fk
         FOREIGN KEY (included_in_report_id) REFERENCES casual_seller_daily_reports(id) ON DELETE SET NULL;
       END IF;
     END $$`,
    `CREATE TABLE IF NOT EXISTS casual_seller_access_log (
       id BIGSERIAL PRIMARY KEY,
       application_id BIGINT REFERENCES casual_seller_applications(id) ON DELETE RESTRICT,
       report_id BIGINT REFERENCES casual_seller_daily_reports(id) ON DELETE RESTRICT,
       admin_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
       action TEXT NOT NULL,
       created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )`,
  ] },
  { version: 64, name: "verified-seller-20m-tier", statements: [
    `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS seller_tier TEXT NOT NULL DEFAULT 'buyer',
       ADD COLUMN IF NOT EXISTS seller_listing_limit NUMERIC(14,2) NOT NULL DEFAULT 20000000`,
    `UPDATE users SET seller_tier = 'verified', seller_listing_limit = 20000000 WHERE is_approved = true AND is_admin = false`,
    `UPDATE users SET seller_tier = 'casual' WHERE is_approved = false AND casual_seller_status = 'approved'`,
    `CREATE TABLE IF NOT EXISTS verified_seller_applications (
       id BIGSERIAL PRIMARY KEY,
       reference TEXT NOT NULL UNIQUE,
       user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
       casual_application_id BIGINT NOT NULL REFERENCES casual_seller_applications(id) ON DELETE RESTRICT,
       bank_statement_path TEXT NOT NULL,
       address_id INTEGER NOT NULL REFERENCES user_addresses(id) ON DELETE RESTRICT,
       requested_limit NUMERIC(14,2) NOT NULL DEFAULT 20000000,
       requirements_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
       consented_at TIMESTAMP NOT NULL,
       status TEXT NOT NULL DEFAULT 'pending',
       decision_reason TEXT,
       reviewed_by INTEGER REFERENCES users(id) ON DELETE RESTRICT,
       reviewed_at TIMESTAMP,
       created_at TIMESTAMP NOT NULL DEFAULT NOW(),
       updated_at TIMESTAMP NOT NULL DEFAULT NOW()
     )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_one_pending_verified_seller_application
       ON verified_seller_applications(user_id) WHERE status = 'pending'`,
    `CREATE INDEX IF NOT EXISTS idx_verified_seller_admin_queue ON verified_seller_applications(status, created_at DESC)`,
  ] },
  { version: 65, name: "verified-bank-account-owner-name", statements: [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS bank_account_name TEXT`,
  ] },
  { version: 66, name: "verified-seller-10m-tier", statements: [
    `ALTER TABLE users ALTER COLUMN seller_listing_limit SET DEFAULT 10000000`,
    `UPDATE users SET seller_tier = 'verified', seller_listing_limit = 10000000
       WHERE is_admin = false AND is_approved = true AND COALESCE(seller_tier, 'verified') <> 'premium'`,
    `ALTER TABLE verified_seller_applications ALTER COLUMN requested_limit SET DEFAULT 10000000`,
    `UPDATE verified_seller_applications SET requested_limit = 10000000
       WHERE status = 'pending' AND requested_limit > 10000000`,
  ] },
  { version: 67, name: "split-casual-and-verified-identity-requirements", statements: [
    `ALTER TABLE casual_seller_applications
       ALTER COLUMN id_type DROP NOT NULL,
       ALTER COLUMN id_number_hash DROP NOT NULL,
       ALTER COLUMN id_number_last4 DROP NOT NULL`,
    `ALTER TABLE verified_seller_applications
       ADD COLUMN IF NOT EXISTS id_type TEXT,
       ADD COLUMN IF NOT EXISTS id_number_hash TEXT,
       ADD COLUMN IF NOT EXISTS id_number_last4 TEXT,
       ADD COLUMN IF NOT EXISTS id_expiration DATE,
       ADD COLUMN IF NOT EXISTS id_front_path TEXT,
       ADD COLUMN IF NOT EXISTS id_back_path TEXT`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_verified_seller_identity_once
       ON verified_seller_applications(id_number_hash)
       WHERE id_number_hash IS NOT NULL AND status IN ('pending', 'approved')`,
  ] },
  { version: 68, name: "member-other-name", statements: [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS other_name TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS date_of_birth DATE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS nationality TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS state_of_residence TEXT`,
  ] },
  { version: 69, name: "verified-seller-daily-reports", statements: [
    `CREATE TABLE IF NOT EXISTS verified_seller_daily_reports (
       id BIGSERIAL PRIMARY KEY,
       report_date DATE NOT NULL UNIQUE,
       application_count INTEGER NOT NULL DEFAULT 0,
       pdf_storage_path TEXT,
       pdf_sha256 TEXT,
       email_recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
       email_status TEXT NOT NULL DEFAULT 'pending',
       email_error TEXT,
       emailed_at TIMESTAMP,
       created_at TIMESTAMP NOT NULL DEFAULT NOW()
     )`,
    `ALTER TABLE verified_seller_applications ADD COLUMN IF NOT EXISTS included_in_report_id BIGINT`,
    `DO $$ BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'verified_seller_applications_report_fk') THEN
         ALTER TABLE verified_seller_applications ADD CONSTRAINT verified_seller_applications_report_fk
         FOREIGN KEY (included_in_report_id) REFERENCES verified_seller_daily_reports(id) ON DELETE SET NULL;
       END IF;
     END $$`,
    `CREATE INDEX IF NOT EXISTS idx_verified_seller_daily_report_queue
       ON verified_seller_applications(status, reviewed_at)
       WHERE status = 'approved' AND included_in_report_id IS NULL`,
    `CREATE TABLE IF NOT EXISTS verified_seller_report_access_log (
       id BIGSERIAL PRIMARY KEY,
       report_id BIGINT NOT NULL REFERENCES verified_seller_daily_reports(id) ON DELETE RESTRICT,
       admin_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
       action TEXT NOT NULL,
       created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )`,
  ] },
  { version: 70, name: "verified-seller-report-passwords", statements: [
    `ALTER TABLE verified_seller_daily_reports ADD COLUMN IF NOT EXISTS password_encrypted TEXT`,
  ] },
  { version: 71, name: "casual-seller-report-passwords", statements: [
    `ALTER TABLE casual_seller_daily_reports ADD COLUMN IF NOT EXISTS password_encrypted TEXT`,
  ] },
];

async function ensureMigrationTable(client = pool) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

async function applyPendingMigrations() {
  const client = await pool.connect();
  try {
    await ensureMigrationTable(client);
    const appliedResult = await client.query("SELECT version FROM schema_migrations ORDER BY version");
    const applied = new Set(appliedResult.rows.map((r) => Number(r.version)));
    const pending = SCHEMA_MIGRATIONS.filter((m) => !applied.has(m.version));

    if (pending.length === 0) {
      console.log("Database schema is current — no migrations pending.");
      return { applied: [], pending: 0 };
    }

    const completed = [];
    for (const migration of pending) {
      await client.query("BEGIN");
      try {
        for (const statement of migration.statements) {
          await client.query(statement);
        }
        await client.query(
          "INSERT INTO schema_migrations (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
          [migration.version, migration.name]
        );
        await client.query("COMMIT");
        completed.push(migration.name);
        console.log(`Applied database migration ${migration.version}: ${migration.name}`);
      } catch (err) {
        await client.query("ROLLBACK");
        throw new Error(`Migration ${migration.version} (${migration.name}) failed: ${err.message}`);
      }
    }
    return { applied: completed, pending: 0 };
  } finally {
    client.release();
  }
}

// Super Admin can inspect migration status from the secured admin API.
// There is deliberately no endpoint that accepts a migration key in a URL.
app.get("/admin/schema-status", authenticate, requirePermission("role_assignment"), async (req, res) => {
  try {
    await ensureMigrationTable();
    const appliedResult = await pool.query("SELECT version, name, applied_at FROM schema_migrations ORDER BY version");
    const appliedVersions = new Set(appliedResult.rows.map((r) => Number(r.version)));
    const pending = SCHEMA_MIGRATIONS
      .filter((m) => !appliedVersions.has(m.version))
      .map((m) => ({ version: m.version, name: m.name }));
    res.json({
      current: pending.length === 0,
      totalMigrations: SCHEMA_MIGRATIONS.length,
      applied: appliedResult.rows,
      pending,
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/signup", authRateLimit, async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    const verifiedEmail = await getSecurityState("email-verified", email.toLowerCase());
    if (!verifiedEmail) {
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
       RETURNING id, username, email, phone, display_name, first_name, last_name, other_name, date_of_birth, gender, nationality, state_of_residence, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type,
         id_country, license_number, license_photos, id_verification_exempt,
         is_email_verified, profile_complete, created_at, token_version`,
      [username, email, passwordHash, displayName || username, isFirstUser, isFirstUser]
    );

    await deleteSecurityState("email-verified", email.toLowerCase());
    if (!result.rows[0].is_admin) setAuthCookie(res, result.rows[0]);
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username or email already in use" });
    }
    sendInternalError(res, err);
  }
});

app.patch("/profile/complete", authenticate, async (req, res) => {
  try {
    const {
      firstName, lastName, otherName, dateOfBirth, gender, nationality, stateOfResidence, phone, officeLocation, country, accountType,
      idType, idCountry, licenseNumber, licensePhotos, idVerificationExempt,
    } = req.body;

    const normalizedCountry = (country || "").trim().toLowerCase();
    if (normalizedCountry && !isNigeriaCountry(normalizedCountry)) {
      return res.status(403).json({ error: "Stallyard is available in Nigeria only" });
    }

    if (phone) {
      const phoneCheck = await checkPhoneNumber(phone);
      if (phoneCheck?.blocked) {
        return res.status(400).json({ error: phoneCheck.reason });
      }
    }

    if (!dateOfBirth || ageOnDate(dateOfBirth) < 18) {
      return res.status(400).json({ error: "You must be at least 18 years old" });
    }
    const normalizedGender = String(gender || "").trim().toLowerCase();
    if (!["male", "female", "prefer_not_to_say"].includes(normalizedGender)) {
      return res.status(400).json({ error: "Select a valid gender" });
    }
    const normalizedNationality = String(nationality || "").trim();
    if (!normalizedNationality) return res.status(400).json({ error: "Enter your nationality" });
    const normalizedState = String(stateOfResidence || "").trim();
    if (!normalizedState) return res.status(400).json({ error: "Select your state of residence" });

    const hasCore = firstName && lastName && dateOfBirth && normalizedGender && normalizedNationality && normalizedState && country;
    const hasId = !!idVerificationExempt || (idType && licenseNumber);
    const nowComplete = !!(hasCore && (accountType === "personal" || hasId));

    const result = await pool.query(
      `UPDATE users SET
         first_name = COALESCE($1, first_name),
         last_name = COALESCE($2, last_name),
         other_name = COALESCE($3, other_name),
         date_of_birth = COALESCE($4, date_of_birth),
         gender = COALESCE($5, gender),
         nationality = COALESCE($6, nationality),
         state_of_residence = COALESCE($7, state_of_residence),
         phone = COALESCE($8, phone),
         office_location = COALESCE($9, office_location),
         country = COALESCE($10, country),
         account_type = COALESCE($11, account_type),
         id_type = COALESCE($12, id_type),
         id_country = COALESCE($13, id_country),
         license_number = COALESCE($14, license_number),
         license_photos = COALESCE($15, license_photos),
         id_verification_exempt = COALESCE($16, id_verification_exempt),
         profile_complete = $17
       WHERE id = $18
       RETURNING id, username, email, phone, display_name, first_name, last_name, other_name, date_of_birth, gender, nationality, state_of_residence, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type,
         id_country, license_number, license_photos, id_verification_exempt,
         is_email_verified, profile_complete, created_at`,
      [
        firstName || null, lastName || null, otherName?.trim() || null, dateOfBirth, normalizedGender, normalizedNationality, normalizedState, phone || null, officeLocation || null,
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
    sendInternalError(res, err);
  }
});

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
    sendInternalError(res, err);
  }
});

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
    const updated = await pool.query(
      `UPDATE users SET password_hash = $1, token_version = COALESCE(token_version, 0) + 1
       WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [newHash, req.user.id]
    );
    setAuthCookie(res, updated.rows[0], req.user.isAdmin ? { adminVerifiedAt: req.user.adminVerifiedAt } : {});
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/profile/sign-out-other-devices", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET token_version = COALESCE(token_version, 0) + 1
       WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    setAuthCookie(res, result.rows[0], req.user.isAdmin ? { adminVerifiedAt: req.user.adminVerifiedAt } : {});
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/addresses", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM user_addresses WHERE user_id = $1 ORDER BY is_default DESC, created_at DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/addresses", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const { label, fullName, phone, street, city, state, zip, country, deliveryInstructions, preferredDeliveryTime, locationPhotos, isDefault } = req.body;
    if (!fullName || !phone || !street || !city || !country) {
      return res.status(400).json({ error: "Recipient name, phone, street, city, and country are required" });
    }
    if (!isNigeriaCountry(country)) {
      return res.status(400).json({ error: "Stallyard shipping addresses must be in Nigeria" });
    }
    const existingCount = await pool.query("SELECT COUNT(*) FROM user_addresses WHERE user_id = $1", [req.user.id]);
    const shouldBeDefault = !!isDefault || Number(existingCount.rows[0].count) === 0;
    if (shouldBeDefault) {
      await pool.query("UPDATE user_addresses SET is_default = false WHERE user_id = $1", [req.user.id]);
    }
    const photos = Array.isArray(locationPhotos) ? locationPhotos.filter((p) => typeof p === "string" && p.startsWith("data:image/") && p.length <= 1500000).slice(0, 5) : [];
    const result = await pool.query(
      `INSERT INTO user_addresses (user_id, label, full_name, phone, street, city, state, zip, country,
         delivery_instructions, preferred_delivery_time, location_photos, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [req.user.id, label || "", fullName || "", phone || "", street, city, state || "", zip || "", country,
       String(deliveryInstructions || "").slice(0, 1000), String(preferredDeliveryTime || "").slice(0, 200), JSON.stringify(photos), shouldBeDefault]
    );
    res.json(result.rows[0]);
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/addresses/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM user_addresses WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Address not found" });
    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only edit your own addresses" });
    }
    const { label, fullName, phone, street, city, state, zip, country, deliveryInstructions, preferredDeliveryTime, locationPhotos } = req.body;
    const current = existing.rows[0];
    const nextCountry = country ?? current.country;
    if (!isNigeriaCountry(nextCountry)) {
      return res.status(400).json({ error: "Stallyard shipping addresses must be in Nigeria" });
    }
    const photos = locationPhotos === undefined
      ? current.location_photos
      : (Array.isArray(locationPhotos) ? locationPhotos.filter((p) => typeof p === "string" && p.startsWith("data:image/") && p.length <= 1500000).slice(0, 5) : []);
    const result = await pool.query(
      `UPDATE user_addresses SET label = $1, full_name = $2, phone = $3, street = $4, city = $5, state = $6,
         zip = $7, country = $8, delivery_instructions = $9, preferred_delivery_time = $10, location_photos = $11
       WHERE id = $12 RETURNING *`,
      [
        label ?? current.label,
        fullName ?? current.full_name,
        phone ?? current.phone,
        street ?? current.street,
        city ?? current.city,
        state ?? current.state,
        zip ?? current.zip,
        country ?? current.country,
        String(deliveryInstructions ?? current.delivery_instructions ?? "").slice(0, 1000),
        String(preferredDeliveryTime ?? current.preferred_delivery_time ?? "").slice(0, 200),
        JSON.stringify(photos || []),
        req.params.id,
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/addresses/:id/default", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM user_addresses WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Address not found" });
    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only edit your own addresses" });
    }
    await pool.query("UPDATE user_addresses SET is_default = false WHERE user_id = $1", [req.user.id]);
    const result = await pool.query(
      "UPDATE user_addresses SET is_default = true WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/addresses/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM user_addresses WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Address not found" });
    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only delete your own addresses" });
    }
    await pool.query("DELETE FROM user_addresses WHERE id = $1", [req.params.id]);
    if (existing.rows[0].is_default) {
      const remaining = await pool.query(
        "SELECT id FROM user_addresses WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        [req.user.id]
      );
      if (remaining.rows.length) {
        await pool.query("UPDATE user_addresses SET is_default = true WHERE id = $1", [remaining.rows[0].id]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/saved-cards", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, card_type, last4, bank, exp_month, exp_year, is_default, created_at FROM saved_cards WHERE user_id = $1 ORDER BY is_default DESC, created_at DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/saved-cards/:id/default", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM saved_cards WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Saved card not found" });
    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only edit your own saved cards" });
    }
    await pool.query("UPDATE saved_cards SET is_default = false WHERE user_id = $1", [req.user.id]);
    const result = await pool.query("UPDATE saved_cards SET is_default = true WHERE id = $1 RETURNING *", [req.params.id]);
    res.json(result.rows[0]);
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/saved-cards/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM saved_cards WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Saved card not found" });
    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only remove your own saved cards" });
    }
    await pool.query("DELETE FROM saved_cards WHERE id = $1", [req.params.id]);
    if (existing.rows[0].is_default) {
      const remaining = await pool.query(
        "SELECT id FROM saved_cards WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        [req.user.id]
      );
      if (remaining.rows.length) {
        await pool.query("UPDATE saved_cards SET is_default = true WHERE id = $1", [remaining.rows[0].id]);
      }
    }
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/profile/two-factor", authenticate, async (req, res) => {
  try {
    const { enabled } = req.body;
    if (enabled) {
      return res.status(400).json({ error: "Use /profile/two-factor/enable/send to turn this on" });
    }
    if (req.user.isAdmin) {
      return res.status(403).json({ error: "Admin accounts can't turn off two-factor authentication" });
    }
    const result = await pool.query(
      "UPDATE users SET two_factor_enabled = false WHERE id = $1 RETURNING two_factor_enabled",
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    res.json({ twoFactorEnabled: result.rows[0].two_factor_enabled });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/profile/two-factor/enable/send", authenticate, async (req, res) => {
  try {
    if (req.user.isAdmin) {
      return res.status(400).json({ error: "Admin accounts use an authenticator app — see /admin/totp/setup" });
    }
    const check = await pool.query("SELECT email FROM users WHERE id = $1", [req.user.id]);
    if (!check.rows.length || !check.rows[0].email) {
      return res.status(400).json({ error: "Add a verified email to your account before turning this on" });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Two-factor isn't configured — contact support" });
    }
    const code = generateSecurityCode();
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress,
        to: [check.rows[0].email],
        subject: `Your Stallyard two-factor code is ${code}`,
        html: `<p>Your code to turn on two-factor authentication is <strong>${code}</strong>.</p><p>Expires in 10 minutes. If this wasn't you, change your password immediately.</p>`,
      }),
    });
    if (!resendRes.ok) {
      return res.status(400).json({ error: "Couldn't send your code — try again" });
    }
    await setSecurityState("2fa-enable", req.user.id, { code }, TWO_FACTOR_CODE_TTL_MS);
    res.json({ sent: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/profile/two-factor/enable/verify", authenticate, async (req, res) => {
  try {
    if (req.user.isAdmin) {
      return res.status(400).json({ error: "Admin accounts use an authenticator app — see /admin/totp/setup" });
    }
    const { code } = req.body;
    const stored = await getSecurityState("2fa-enable", req.user.id);
    if (!stored) {
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }
    if (stored.code !== String(code || "").trim()) {
      return res.status(400).json({ error: "That code doesn't match" });
    }
    await deleteSecurityState("2fa-enable", req.user.id);
    const result = await pool.query(
      "UPDATE users SET two_factor_enabled = true WHERE id = $1 RETURNING two_factor_enabled",
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    res.json({ twoFactorEnabled: result.rows[0].two_factor_enabled });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/totp/setup", authenticate, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const secret = generateTotpSecret();
    await pool.query("UPDATE users SET totp_secret = $1 WHERE id = $2", [encryptField(secret), req.user.id]);
    const label = encodeURIComponent(`Stallyard:${req.user.username}`);
    const issuer = encodeURIComponent("Stallyard");
    const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const qrCodeUrl = makeLocalTotpQrDataUrl(otpauthUrl);
    res.json({ secret, otpauthUrl, qrCodeUrl });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/totp/confirm", authenticate, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const { code } = req.body;
    const result = await pool.query("SELECT totp_secret FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length || !result.rows[0].totp_secret) {
      return res.status(400).json({ error: "Start setup again — no pending authenticator secret found" });
    }
    if (!verifyTotpCode(decryptTotpSecret(result.rows[0].totp_secret), code)) {
      return res.status(400).json({ error: "That code doesn't match — check your authenticator app and try again" });
    }
    const updated = await pool.query(
      "UPDATE users SET two_factor_enabled = true WHERE id = $1 RETURNING two_factor_enabled",
      [req.user.id]
    );
    res.json({ twoFactorEnabled: updated.rows[0].two_factor_enabled });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/reauth", authenticate, authRateLimit, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "Enter your password" });
    const result = await pool.query("SELECT password_hash, two_factor_enabled, totp_secret FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    const matches = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!matches) return res.status(401).json({ error: "Password doesn't match" });

    if (!result.rows[0].two_factor_enabled || !result.rows[0].totp_secret) {
      return res.status(403).json({
        error: "Admin multi-factor authentication is not configured. Authenticator setup is required before admin access.",
        code: "ADMIN_MFA_REQUIRED",
      });
    }
    const reauthChallenge = crypto.randomBytes(32).toString("hex");
    await setSecurityState(
      "admin-reauth-challenge",
      Number(req.user.id),
      { challenge: reauthChallenge, passwordVerifiedAt: Date.now() },
      TOTP_VERIFIED_MARKER_TTL_MS
    );
    await deleteSecurityState("admin-reauth-totp", Number(req.user.id));
    await deleteSecurityState("admin-reauth-email", Number(req.user.id));
    res.json({ twoFactorRequired: true, method: "totp" });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/reauth/verify", authenticate, authRateLimit, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const { code } = req.body;
    const challengeState = await getSecurityState("admin-reauth-challenge", Number(req.user.id));
    if (!challengeState?.challenge) {
      return res.status(400).json({ error: "Your password step expired — start admin re-authentication again" });
    }
    const result = await pool.query("SELECT email, totp_secret FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });

    if (!result.rows[0].totp_secret || !verifyTotpCode(decryptTotpSecret(result.rows[0].totp_secret), code)) {
      return res.status(400).json({ error: "That code doesn't match — check your authenticator app and try again" });
    }
    if (!result.rows[0].email) {
      return res.status(400).json({ error: "This account has no email on file — contact support" });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Email step isn't configured — contact support" });
    }
    const emailCode = generateSecurityCode();
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress,
        to: [result.rows[0].email],
        subject: `Your Stallyard admin access code is ${emailCode}`,
        html: `<p>Your code to unlock the admin panel is <strong>${emailCode}</strong>.</p><p>Expires in 10 minutes. If this wasn't you, change your password immediately.</p>`,
      }),
    });
    if (!resendRes.ok) {
      return res.status(400).json({ error: "Couldn't send the email step's code — try again" });
    }
    await setSecurityState(
      "admin-reauth-email",
      Number(req.user.id),
      { code: emailCode, challenge: challengeState.challenge },
      TWO_FACTOR_CODE_TTL_MS
    );
    await setSecurityState(
      "admin-reauth-totp",
      Number(req.user.id),
      { verified: true, challenge: challengeState.challenge },
      TOTP_VERIFIED_MARKER_TTL_MS
    );
    res.json({ emailStepRequired: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/reauth/verify-email", authenticate, authRateLimit, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const { code } = req.body;
    const challengeState = await getSecurityState("admin-reauth-challenge", Number(req.user.id));
    const marker = await getSecurityState("admin-reauth-totp", Number(req.user.id));
    const stored = await getSecurityState("admin-reauth-email", Number(req.user.id));
    if (!challengeState?.challenge || !marker?.challenge || !stored?.challenge ||
        marker.challenge !== challengeState.challenge || stored.challenge !== challengeState.challenge) {
      await deleteSecurityState("admin-reauth-challenge", Number(req.user.id));
      await deleteSecurityState("admin-reauth-totp", Number(req.user.id));
      await deleteSecurityState("admin-reauth-email", Number(req.user.id));
      return res.status(400).json({ error: "Your admin authentication sequence expired — start over" });
    }
    if (stored.code !== String(code || "").trim()) {
      return res.status(400).json({ error: "That code doesn't match" });
    }
    await deleteSecurityState("admin-reauth-challenge", Number(req.user.id));
    await deleteSecurityState("admin-reauth-totp", Number(req.user.id));
    await deleteSecurityState("admin-reauth-email", Number(req.user.id));

    const refreshed = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS} FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (!refreshed.rows.length || !refreshed.rows[0].is_admin) {
      clearAuthCookie(res);
      return res.status(403).json({ error: "Admin access is no longer active" });
    }
    setAuthCookie(res, refreshed.rows[0], { adminVerifiedAt: Date.now() });
    logAdminAction(req.user.id, "admin_reauth_completed", "Completed password + authenticator + email re-authentication; refreshed the server-enforced 30-minute admin session");
    res.json({ success: true, adminSessionExpiresInMs: ADMIN_SERVER_SESSION_MS });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/profile/verify-email", authenticate, async (req, res) => {
  try {
    const check = await pool.query("SELECT email FROM users WHERE id = $1", [req.user.id]);
    if (!check.rows.length || !check.rows[0].email) {
      return res.status(400).json({ error: "Add an email to your account first" });
    }
    const email = check.rows[0].email.toLowerCase();
    const verifiedEmail = await getSecurityState("email-verified", email);
    if (!verifiedEmail) {
      return res.status(400).json({ error: "Verify the code we sent first" });
    }
    await deleteSecurityState("email-verified", email);
    await pool.query("UPDATE users SET is_email_verified = true WHERE id = $1", [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/profile/verify-phone", authenticate, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: "Missing phone number" });
    const verifiedPhone = await getSecurityState("phone-verified", phone);
    if (!verifiedPhone) {
      return res.status(400).json({ error: "Verify the code we sent first" });
    }
    await deleteSecurityState("phone-verified", phone);
    await pool.query("UPDATE users SET phone = $1, is_phone_verified = true WHERE id = $2", [phone, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/profile/apply-to-sell", authenticate, requireNigeriaMarketplaceUser, async (req, res) => {
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
    sendInternalError(res, err);
  }
});

const USER_PUBLIC_FIELDS = `id, username, display_name, country, account_type, created_at,
  avatar_url, store_bio, store_policies`;

const USER_FULL_FIELDS = `id, username, email, phone, display_name, first_name, last_name, other_name, date_of_birth, gender, nationality, state_of_residence, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, verification_status,
  bank_statement_url, rejection_reason, created_at, avatar_url, store_bio, store_policies, two_factor_enabled,
  is_email_verified, is_phone_verified, admin_role`;

// Safe staff directory fields for admin roles that do not need seller-verification
// documents. This intentionally excludes email/phone, ID/license data, document
// URLs, bank statements, and seller-verification rejection details.
const USER_ADMIN_SAFE_FIELDS = `id, username, display_name, first_name, last_name, other_name, date_of_birth, gender, nationality, state_of_residence, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, verification_status, created_at,
  avatar_url, store_bio, store_policies, two_factor_enabled, is_email_verified, is_phone_verified, admin_role`;

app.get("/users", async (req, res) => {
  try {
    let fields = USER_PUBLIC_FIELDS;
    const requester = getRequester(req);

    // /users remains usable for public storefront/profile discovery, but cookie-
    // authenticated admin access is revalidated against PostgreSQL before any
    // staff-only fields are exposed. A malformed/expired cookie never upgrades
    // the response; it receives the same minimal public directory as anonymous
    // callers.
    if (requester?.id) {
      const authCheck = await pool.query(
        `SELECT is_admin, is_suspended, token_version, admin_role, two_factor_enabled
         FROM users WHERE id = $1`,
        [requester.id]
      );

      if (authCheck.rows.length) {
        const current = authCheck.rows[0];
        const versionMatches = (requester.tokenVersion || 0) === (current.token_version || 0);

        if (!current.is_suspended && versionMatches && current.is_admin) {
          if (!current.two_factor_enabled) {
            return res.status(403).json({
              error: "Two-factor authentication is required for admin accounts",
              code: "2FA_REQUIRED",
            });
          }

          // The public directory must not become a way around the backend's
          // 30-minute privileged-admin window.
          const verifiedAt = Number(requester.adminVerifiedAt || 0);
          const age = Date.now() - verifiedAt;
          const invalidFutureTimestamp = verifiedAt > Date.now() + ADMIN_SESSION_CLOCK_SKEW_MS;
          if (!verifiedAt || invalidFutureTimestamp || age > ADMIN_SERVER_SESSION_MS) {
            return res.status(401).json({
              error: "Admin session expired — complete admin re-authentication",
              code: "ADMIN_SESSION_EXPIRED",
            });
          }

          const role = current.admin_role || "super_admin";
          const canReviewSellerPrivateData = role === "super_admin" || role === "seller_verification";
          fields = canReviewSellerPrivateData ? USER_FULL_FIELDS : USER_ADMIN_SAFE_FIELDS;
        }
      }
    }

    const result = await pool.query(`SELECT ${fields} FROM users ORDER BY display_name ASC`);
    res.json({ users: result.rows });
  } catch (err) {
    console.error("Users directory error:", err);
    res.status(500).json({ error: "Unable to load users" });
  }
});

const USER_RETURNING_FIELDS = `id, username, email, phone, display_name, first_name, last_name, other_name, date_of_birth, gender, nationality, state_of_residence, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, verification_status,
  bank_statement_url, rejection_reason, created_at, avatar_url, store_bio, store_policies, two_factor_enabled,
  is_email_verified, is_phone_verified, token_version, admin_role, casual_seller_status,
  casual_seller_limit, casual_seller_approved_at, seller_tier, seller_listing_limit`;

app.patch("/users/:id/verify", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const { isVerified } = req.body;
    const result = await pool.query(
      `UPDATE users SET is_verified = $1 WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [!!isVerified, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.user.id, "user_verified", `${isVerified ? "Verified" : "Unverified"} ${result.rows[0].username}`);
    res.json({ user: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/users/:id/suspend", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const { isSuspended } = req.body;
    const result = await pool.query(
      `UPDATE users SET is_suspended = $1 WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [!!isSuspended, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.user.id, "user_suspended", `${isSuspended ? "Suspended" : "Unsuspended"} ${result.rows[0].username}`);
    res.json({ user: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/users/:id/admin-role", authenticate, requirePermission("role_assignment"), async (req, res) => {
  const client = await pool.connect();
  try {
    const { role, reason } = req.body;
    if (role !== null && !ADMIN_ROLES.has(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    const targetId = Number(req.params.id);
    if (targetId === Number(req.user.id)) {
      return res.status(400).json({ error: "You can't change or revoke your own admin role. Another Super Admin must do that." });
    }
    await client.query("BEGIN");
    const existing = await client.query("SELECT id, username, is_admin, admin_role FROM users WHERE id = $1 FOR UPDATE", [targetId]);
    if (!existing.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }
    const target = existing.rows[0];
    const oldRole = target.is_admin ? (target.admin_role || "super_admin") : null;
    if (oldRole === "super_admin" && role !== "super_admin") {
      const superCount = await client.query(
        "SELECT COUNT(*) FROM users WHERE is_admin = true AND COALESCE(admin_role, 'super_admin') = 'super_admin'"
      );
      if (Number(superCount.rows[0].count) <= 1) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "Stallyard must always have at least one active Super Admin." });
      }
    }
    const result = await client.query(
      `UPDATE users
       SET is_admin = $1, admin_role = $2, token_version = COALESCE(token_version, 0) + 1
       WHERE id = $3 RETURNING ${USER_RETURNING_FIELDS}`,
      [role !== null, role, targetId]
    );
    await client.query(
      `INSERT INTO admin_role_history (user_id, changed_by, old_role, new_role, reason)
       VALUES ($1, $2, $3, $4, $5)`,
      [targetId, req.user.id, oldRole, role, String(reason || "").trim()]
    );
    await client.query("COMMIT");
    logAdminAction(req.user.id, "admin_role_changed", `Set ${result.rows[0].username}'s admin role from ${oldRole || "none"} to ${role || "none (revoked)"}`);
    res.json({ user: result.rows[0] });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.get("/admin/staff", authenticate, requirePermission("role_assignment"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id, u.username, u.email, u.display_name, u.is_admin, u.admin_role,
        u.two_factor_enabled, u.is_suspended, u.created_at,
        (SELECT MAX(lh.created_at) FROM login_history lh WHERE lh.user_id = u.id) AS last_login_at,
        (SELECT MAX(aal.created_at) FROM admin_audit_log aal WHERE aal.admin_id = u.id) AS last_action_at,
        (SELECT COUNT(*) FROM admin_audit_log aal WHERE aal.admin_id = u.id) AS action_count
      FROM users u
      WHERE u.is_admin = true
         OR EXISTS (SELECT 1 FROM admin_role_history arh WHERE arh.user_id = u.id)
      ORDER BY u.is_admin DESC, u.display_name ASC, u.username ASC
    `);
    const staff = [];
    for (const row of result.rows) {
      const history = await pool.query(
        `SELECT arh.*, actor.username AS changed_by_username, actor.display_name AS changed_by_name
         FROM admin_role_history arh
         LEFT JOIN users actor ON actor.id = arh.changed_by
         WHERE arh.user_id = $1 ORDER BY arh.created_at DESC LIMIT 20`,
        [row.id]
      );
      staff.push({ ...row, role_history: history.rows });
    }
    res.json({ staff });
  } catch (err) {
    if (err.code === "42P01") {
      return res.status(409).json({ error: "Run the admin staff management migration first", code: "MIGRATION_REQUIRED" });
    }
    sendInternalError(res, err);
  }
});

app.post("/admin/staff/:id/revoke-sessions", authenticate, requirePermission("role_assignment"), async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (targetId === Number(req.user.id)) {
      return res.status(400).json({ error: "Use your own account security controls to sign out your other sessions." });
    }
    const result = await pool.query(
      `UPDATE users SET token_version = COALESCE(token_version, 0) + 1
       WHERE id = $1 AND is_admin = true
       RETURNING id, username, display_name, token_version`,
      [targetId]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Active admin account not found" });
    logAdminAction(req.user.id, "admin_sessions_revoked", `Revoked all active sessions for admin ${result.rows[0].username}`);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/staff/:id/temporary-password", authenticate, requirePermission("role_assignment"), authRateLimit, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (!Number.isFinite(targetId)) return res.status(400).json({ error: "Invalid staff account" });
    if (targetId === Number(req.user.id)) {
      return res.status(400).json({ error: "Use your own account security controls to change your password." });
    }

    const found = await pool.query(
      `SELECT id, username, email, display_name, is_admin, is_suspended
       FROM users WHERE id = $1`,
      [targetId]
    );
    if (!found.rows.length || !found.rows[0].is_admin) {
      return res.status(404).json({ error: "Active admin account not found" });
    }
    const target = found.rows[0];
    if (target.is_suspended) {
      return res.status(400).json({ error: "Unsuspend this admin before issuing a temporary password." });
    }

    // Easy enough to type but still high entropy. Plaintext is returned once
    // to the Super Admin; only the bcrypt hash is persisted.
    const temporaryPassword = `STL-${crypto.randomBytes(6).toString("base64url")}`;
    const passwordHash = await bcrypt.hash(temporaryPassword, 10);
    const expiresAt = new Date(Date.now() + ADMIN_TEMP_PASSWORD_TTL_MS);

    await pool.query(
      `UPDATE users SET
         admin_temp_password_hash = $1,
         admin_temp_password_expires_at = $2,
         admin_temp_password_created_at = NOW(),
         admin_temp_password_created_by = $3,
         token_version = COALESCE(token_version, 0) + 1
       WHERE id = $4`,
      [passwordHash, expiresAt, req.user.id, targetId]
    );

    // Notify the sub-admin that recovery was initiated, but never email the
    // temporary password itself. The Super Admin should deliver it separately.
    if (process.env.RESEND_API_KEY && target.email) {
      const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
      fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
        body: JSON.stringify({
          from: fromAddress,
          to: [target.email],
          subject: "A temporary Stallyard admin password was issued",
          html: `<p>A Stallyard Super Admin issued a temporary password for your admin account.</p><p>It expires in 10 minutes and can only be used on the Stallyard Admin sign-in page. You will still need your authenticator code and emailed security code, then you will be required to choose a new permanent password.</p><p>If you did not request help signing in, contact the Stallyard Super Admin immediately.</p>`,
        }),
      }).catch((err) => console.error("Failed to send temporary-password notice:", err.message));
    }

    logAdminAction(req.user.id, "admin_temporary_password_issued", `Issued a 10-minute temporary password for admin ${target.username}; existing sessions were revoked`);
    res.json({
      success: true,
      username: target.username,
      displayName: target.display_name || target.username,
      temporaryPassword,
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    if (err.code === "42703") {
      return res.status(409).json({ error: "Run the temporary admin password migration first", code: "MIGRATION_REQUIRED" });
    }
    sendInternalError(res, err);
  }
});

app.post("/admin/staff/:id/reset-password", authenticate, requirePermission("role_assignment"), authRateLimit, async (req, res) => {
  const client = await pool.connect();
  try {
    const targetId = Number(req.params.id);
    if (!Number.isFinite(targetId)) return res.status(400).json({ error: "Invalid staff account" });
    if (targetId === Number(req.user.id)) {
      return res.status(400).json({ error: "Use your own account security controls to change your password." });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Password reset email isn't configured" });
    }

    await client.query("BEGIN");
    const found = await client.query(
      `SELECT id, username, email, display_name, is_admin
       FROM users WHERE id = $1 FOR UPDATE`,
      [targetId]
    );
    if (!found.rows.length || !found.rows[0].is_admin) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Active admin account not found" });
    }
    const target = found.rows[0];
    if (!target.email) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This admin account has no email on file" });
    }

    const code = generateSecurityCode();
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress,
        to: [target.email],
        subject: `Stallyard admin password reset code: ${code}`,
        html: `<p>A Stallyard Super Admin started a password reset for your admin account.</p><p>Your password reset code is <strong>${code}</strong>.</p><p>This code expires in 15 minutes. Go to Stallyard sign in, choose <strong>Forgot password</strong>, enter your admin username <strong>${target.username}</strong>, and use this code to set a new password.</p><p>Your existing sessions have been signed out for security. If you did not expect this reset, contact the Stallyard Super Admin immediately.</p>`,
      }),
    });
    const resendData = await resendRes.json().catch(() => ({}));
    if (!resendRes.ok) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: resendData.message || "Couldn't send the password reset email" });
    }

    await setSecurityState("password-reset", target.username.trim().toLowerCase(), { code, userId: targetId, adminIssued: true }, PASSWORD_RESET_CODE_TTL_MS, client);
    await client.query(
      "UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = $1",
      [targetId]
    );
    await client.query("COMMIT");

    const maskedEmail = target.email.replace(/^(.{1,2}).*(@.*)$/, (m, a, b) => `${a}***${b}`);
    logAdminAction(req.user.id, "admin_password_reset_started", `Started a secure password reset for admin ${target.username} and revoked existing sessions`);
    res.json({ success: true, maskedEmail });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

const ADMIN_NOTE_ENTITY_TYPES = new Set(["member", "listing", "order", "dispute", "support_ticket"]);

function canAccessAdminNotes(user, entityType) {
  if (!user?.isAdmin || !user.twoFactorEnabled) return false;
  if (!user.adminRole || user.adminRole === "super_admin") return true;
  if (entityType === "member") return hasPermission(user, "seller_verification") || hasPermission(user, "user_management");
  if (entityType === "listing") return hasPermission(user, "listing_moderation");
  if (entityType === "order") return hasPermission(user, "finance") || hasPermission(user, "dispute_resolution");
  if (entityType === "dispute") return hasPermission(user, "dispute_resolution");
  if (entityType === "support_ticket") return hasPermission(user, "support_tickets");
  return false;
}

function requireAdminNotesAccess(req, res, next) {
  const entityType = String(req.params.entityType || "");
  if (!ADMIN_NOTE_ENTITY_TYPES.has(entityType)) return res.status(400).json({ error: "Invalid note type" });
  if (!canAccessAdminNotes(req.user, entityType)) return res.status(403).json({ error: "You don't have permission to view notes for this record" });
  next();
}

app.get("/admin-notes/:entityType/:entityId", authenticate, requireAdminNotesAccess, async (req, res) => {
  try {
    const entityId = Number(req.params.entityId);
    if (!Number.isInteger(entityId) || entityId <= 0) return res.status(400).json({ error: "Invalid record ID" });
    const result = await pool.query(
      `SELECT n.id, n.entity_type, n.entity_id, n.body, n.created_at, n.admin_id,
              u.username AS admin_username, u.display_name AS admin_display_name
       FROM admin_notes n
       LEFT JOIN users u ON n.admin_id = u.id
       WHERE n.entity_type = $1 AND n.entity_id = $2
       ORDER BY n.created_at DESC, n.id DESC`,
      [req.params.entityType, entityId]
    );
    res.json({ notes: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin-notes/:entityType/:entityId", authenticate, requireAdminNotesAccess, async (req, res) => {
  try {
    const entityId = Number(req.params.entityId);
    const body = String(req.body?.body || "").trim();
    if (!Number.isInteger(entityId) || entityId <= 0) return res.status(400).json({ error: "Invalid record ID" });
    if (!body) return res.status(400).json({ error: "Write a note first" });
    if (body.length > 4000) return res.status(400).json({ error: "Internal notes are limited to 4,000 characters" });
    const result = await pool.query(
      `INSERT INTO admin_notes (entity_type, entity_id, admin_id, body)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [req.params.entityType, entityId, req.user.id, body]
    );
    const admin = await pool.query("SELECT username, display_name FROM users WHERE id = $1", [req.user.id]);
    const note = {
      ...result.rows[0],
      admin_username: admin.rows[0]?.username || req.user.username,
      admin_display_name: admin.rows[0]?.display_name || req.user.username,
    };
    logAdminAction(req.user.id, "admin_note_added", `Added private note to ${req.params.entityType} #${entityId}`);
    res.status(201).json({ note });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/admin-audit-log", authenticate, requirePermission("role_assignment"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT aal.*, u.username, u.display_name
       FROM admin_audit_log aal
       LEFT JOIN users u ON aal.admin_id = u.id
       ORDER BY aal.created_at DESC LIMIT 500`
    );
    res.json({ log: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/users/:id/approve", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const pendingApplication = await pool.query(
      "SELECT id FROM verified_seller_applications WHERE user_id=$1 AND status='pending' ORDER BY created_at DESC LIMIT 1", [req.params.id]
    );
    if (!pendingApplication.rows.length) {
      return res.status(409).json({ error: "A complete pending verified-seller application is required before approval" });
    }
    const result = await pool.query(
      `UPDATE users SET is_approved = true, verification_status = 'approved', rejection_reason = NULL,
         seller_tier = 'verified', seller_listing_limit = 10000000
       WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    await pool.query(
      `UPDATE verified_seller_applications SET status='approved', reviewed_by=$1, reviewed_at=NOW(), updated_at=NOW()
        WHERE id=(SELECT id FROM verified_seller_applications WHERE user_id=$2 AND status='pending' ORDER BY created_at DESC LIMIT 1)`,
      [req.user.id, req.params.id]
    );
    logAdminAction(req.user.id, "seller_approved", `Approved ${result.rows[0].username}'s seller application`);
    createNotification(
      req.params.id,
      "seller_application",
      "Your Verified Seller application was approved. You may now maintain up to ₦10,000,000 in combined active listings."
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/users/:id/reject", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const { reason } = req.body;
    const pendingApplication = await pool.query(
      "SELECT id FROM verified_seller_applications WHERE user_id=$1 AND status='pending' ORDER BY created_at DESC LIMIT 1", [req.params.id]
    );
    if (!pendingApplication.rows.length) {
      return res.status(409).json({ error: "A pending Verified Seller application is required before rejection" });
    }
    const result = await pool.query(
      `UPDATE users SET is_approved = false, verification_status = 'rejected', rejection_reason = $1
       WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [reason || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    await pool.query(
      `UPDATE verified_seller_applications SET status='rejected', decision_reason=$1, reviewed_by=$2, reviewed_at=NOW(), updated_at=NOW()
        WHERE id=(SELECT id FROM verified_seller_applications WHERE user_id=$3 AND status='pending' ORDER BY created_at DESC LIMIT 1)`,
      [reason || "Application rejected", req.user.id, req.params.id]
    );
    logAdminAction(req.user.id, "seller_rejected", `Rejected ${result.rows[0].username}'s seller application${reason ? ": " + reason : ""}`);
    createNotification(
      req.params.id,
      "verification_problem",
      `Your seller verification needs attention${reason ? ": " + reason : ""}`
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/users/:id", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const target = await pool.query("SELECT username FROM users WHERE id = $1", [req.params.id]);
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.user.id, "user_deleted", `Deleted member ${target.rows[0]?.username || req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    if (err.code === "23503") {
      return res.status(409).json({
        error: "This member has order or payout history and can't be permanently deleted. Suspend them instead to block access while keeping records intact.",
        code: "HAS_HISTORY",
      });
    }
    sendInternalError(res, err);
  }
});

app.post("/admin/create-member", authenticate, requirePermission("user_management"), async (req, res) => {
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

    logAdminAction(req.user.id, "member_created", `Created member ${result.rows[0].username}${result.rows[0].is_admin ? " as an admin" : ""}`);
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username, email, or phone already in use" });
    }
    sendInternalError(res, err);
  }
});

app.get("/follows", async (req, res) => {
  try {
    const result = await pool.query("SELECT follower_username, followed_username FROM follows");
    res.json({ follows: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/follows", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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
    sendInternalError(res, err);
  }
});

app.delete("/follows", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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
    sendInternalError(res, err);
  }
});

app.get("/cart", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT listing_id, qty, offer_price FROM cart_items WHERE user_id = $1",
      [req.user.id]
    );
    res.json({ items: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.put("/cart", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.get("/watchlist", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT listing_id FROM watchlist_items WHERE user_id = $1",
      [req.user.id]
    );
    res.json({ listingIds: result.rows.map((r) => r.listing_id) });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.put("/watchlist", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

// Dedicated admin entrance. Admin accounts must complete all three steps:
// password -> authenticator TOTP -> emailed code. There is no password-only
// fallback, and non-admin credentials receive the same generic error as bad
// credentials so this endpoint does not disclose account roles.
app.post("/admin/login", authRateLimit, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(401).json({ error: "Username or password doesn't match" });
    }

    const result = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS}, password_hash, totp_secret,
              admin_temp_password_hash, admin_temp_password_expires_at
       FROM users WHERE username = $1`,
      [String(username).trim().toLowerCase()]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Username or password doesn't match" });
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    let temporaryPasswordMatches = false;
    const tempExpiry = user.admin_temp_password_expires_at ? new Date(user.admin_temp_password_expires_at).getTime() : 0;
    if (!passwordMatches && user.admin_temp_password_hash && tempExpiry > Date.now()) {
      temporaryPasswordMatches = await bcrypt.compare(password, user.admin_temp_password_hash);
    }
    if ((!passwordMatches && !temporaryPasswordMatches) || !user.is_admin) {
      return res.status(401).json({ error: "Username or password doesn't match" });
    }
    if (!temporaryPasswordMatches) {
      await deleteSecurityState("admin-temp-login", Number(user.id));
      if (user.admin_temp_password_hash && tempExpiry && tempExpiry <= Date.now()) {
        pool.query(
          `UPDATE users SET admin_temp_password_hash = NULL, admin_temp_password_expires_at = NULL,
             admin_temp_password_created_at = NULL, admin_temp_password_created_by = NULL WHERE id = $1`,
          [user.id]
        ).catch(() => {});
      }
    }
    if (user.is_suspended) {
      return res.status(403).json({ error: "This account has been suspended" });
    }

    const vpnDetected = await isVpnOrProxy(getClientIp(req));
    if (vpnDetected) {
      return res.status(403).json({ error: "Admin login isn't allowed over a VPN, proxy, or Tor connection. Please disable it and try again." });
    }

    if (!user.two_factor_enabled || !user.totp_secret) {
      return res.status(403).json({
        error: "Admin multi-factor authentication is not configured. Authenticator setup is required before admin access.",
        code: "ADMIN_MFA_REQUIRED",
      });
    }
    if (!user.email) {
      return res.status(403).json({
        error: "Admin email verification is required before admin access.",
        code: "ADMIN_EMAIL_REQUIRED",
      });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Admin email verification isn't configured — contact support" });
    }

    // Password is step 1. Bind the remaining MFA steps to a short-lived,
    // cryptographically random server-side challenge. A new successful
    // password step invalidates any older in-progress admin login sequence.
    const adminLoginChallenge = crypto.randomBytes(32).toString("hex");
    await deleteSecurityState("admin-login-totp", Number(user.id));
    await deleteSecurityState("admin-login-email", Number(user.id));
    await setSecurityState(
      "admin-login-challenge",
      Number(user.id),
      { challenge: adminLoginChallenge, passwordVerifiedAt: Date.now(), temporaryPassword: temporaryPasswordMatches === true },
      TOTP_VERIFIED_MARKER_TTL_MS
    );
    if (temporaryPasswordMatches) {
      await setSecurityState(
        "admin-temp-login",
        Number(user.id),
        { expiresAt: tempExpiry, challenge: adminLoginChallenge },
        Math.max(1000, Math.min(TOTP_VERIFIED_MARKER_TTL_MS, tempExpiry - Date.now()))
      );
    }
    res.json({ twoFactorRequired: true, userId: user.id, method: "totp" });
  } catch (err) {
    sendInternalError(res, err);
  }
});

// Keep session restoration deliberately small. This endpoint is called on page
// load, so it must never return seller verification documents, bank data,
// government-ID details, or other private profile records.
const SESSION_USER_FIELDS = `id, username, email, phone, display_name, first_name, last_name, other_name, date_of_birth, gender, nationality, state_of_residence,
  country, is_admin, is_approved, is_verified, is_suspended, account_type,
  has_applied_to_sell, verification_status, avatar_url, store_bio, store_policies,
  two_factor_enabled, is_email_verified, is_phone_verified, token_version, admin_role,
  casual_seller_status, casual_seller_limit, casual_seller_approved_at, seller_tier, seller_listing_limit`;

app.get("/session/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT ${SESSION_USER_FIELDS} FROM users WHERE id = $1`, [req.user.id]);
    if (!result.rows.length) {
      clearAuthCookie(res);
      return res.status(401).json({ error: "Session account no longer exists" });
    }
    res.json({ user: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/logout", (req, res) => {
  clearAuthCookie(res);
  res.json({ success: true });
});

app.post("/login", authRateLimit, async (req, res) => {
  try {
    const { username, password } = req.body;
    const loginIdentifier = String(username || "").trim().toLowerCase();

    if (!loginIdentifier || !password) {
      return res.status(400).json({ error: "Missing username/email or password" });
    }

    const result = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS}, password_hash, totp_secret
       FROM users
       WHERE LOWER(username) = $1 OR LOWER(email) = $1
       ORDER BY CASE WHEN LOWER(username) = $1 THEN 0 ELSE 1 END
       LIMIT 1`,
      [loginIdentifier]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Username/email or password doesn't match" });
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({ error: "Username/email or password doesn't match" });
    }

    if (user.is_suspended) {
      return res.status(403).json({ error: "This account has been suspended" });
    }

    if (user.is_admin) {
      return res.status(403).json({ error: "Admin accounts must sign in through the Stallyard admin portal." });
    }

    const vpnDetected = await isVpnOrProxy(getClientIp(req));
    if (vpnDetected) {
      return res.status(403).json({ error: "Login isn't allowed over a VPN, proxy, or Tor connection. Please disable it and try again." });
    }

    if (user.two_factor_enabled) {
      if (user.is_admin) {
        if (!user.totp_secret) {
          return res.status(500).json({ error: "Two-factor is on but no authenticator is set up — contact support" });
        }
        return res.json({ twoFactorRequired: true, userId: user.id, method: "totp" });
      }
      if (!user.email) {
        return res.status(400).json({ error: "Two-factor is on but this account has no email on file — contact support." });
      }
      if (!process.env.RESEND_API_KEY) {
        return res.status(500).json({ error: "Two-factor login isn't configured yet" });
      }
      const code = generateSecurityCode();
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
      await setSecurityState("2fa-email", user.id, { code }, TWO_FACTOR_CODE_TTL_MS);
      return res.json({ twoFactorRequired: true, userId: user.id, method: "email" });
    }

    delete user.password_hash;
    delete user.totp_secret;
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    pool
      .query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [user.id, ip, userAgent])
      .catch((err) => console.error("Failed to record login history:", err.message));
    setAuthCookie(res, user);
    res.json({ user });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/login/verify-2fa", authRateLimit, async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: "Missing userId or code" });

    const result = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS}, totp_secret
       FROM users WHERE id = $1`,
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const user = result.rows[0];

    if (user.is_admin) {
      if (user.is_suspended) {
        await deleteSecurityState("admin-login-challenge", Number(user.id));
        await deleteSecurityState("admin-login-totp", Number(user.id));
        await deleteSecurityState("admin-login-email", Number(user.id));
        await deleteSecurityState("admin-temp-login", Number(user.id));
        return res.status(403).json({ error: "This account has been suspended" });
      }
      const loginChallenge = await getSecurityState("admin-login-challenge", Number(user.id));
      if (!loginChallenge?.challenge) {
        return res.status(400).json({ error: "Your password step expired — start admin sign-in again" });
      }
      if (!user.totp_secret || !verifyTotpCode(decryptTotpSecret(user.totp_secret), code)) {
        return res.status(400).json({ error: "That code doesn't match — check your authenticator app and try again" });
      }
      if (!user.email) {
        return res.status(400).json({ error: "Two-factor is on but this account has no email on file — contact support." });
      }
      if (!process.env.RESEND_API_KEY) {
        return res.status(500).json({ error: "Email step isn't configured — contact support" });
      }
      const emailCode = generateSecurityCode();
      const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
      const resendRes = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
        body: JSON.stringify({
          from: fromAddress,
          to: [user.email],
          subject: `Your Stallyard login code is ${emailCode}`,
          html: `<p>Your Stallyard login code is <strong>${emailCode}</strong>.</p><p>This code expires in 10 minutes. If this wasn't you, change your password right away.</p>`,
        }),
      });
      if (!resendRes.ok) {
        return res.status(400).json({ error: "Couldn't send the email step's code — try again" });
      }
      await setSecurityState(
        "admin-login-email",
        Number(userId),
        { code: emailCode, challenge: loginChallenge.challenge },
        TWO_FACTOR_CODE_TTL_MS
      );
      await setSecurityState(
        "admin-login-totp",
        Number(userId),
        { verified: true, challenge: loginChallenge.challenge },
        TOTP_VERIFIED_MARKER_TTL_MS
      );
      return res.json({ emailStepRequired: true, userId: user.id });
    }

    const stored = await getSecurityState("2fa-email", Number(userId));
    if (!stored) {
      return res.status(400).json({ error: "That code has expired — log in again to get a new one" });
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    await deleteSecurityState("2fa-email", Number(userId));

    delete user.totp_secret;
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    pool
      .query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [user.id, ip, userAgent])
      .catch((err) => console.error("Failed to record login history:", err.message));
    setAuthCookie(res, user);
    res.json({ user });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/login/verify-2fa-email", authRateLimit, async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: "Missing userId or code" });

    const preflight = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS}
       FROM users WHERE id = $1`,
      [userId]
    );
    if (preflight.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const preflightUser = preflight.rows[0];

    let marker;
    let stored;
    let activeAdminChallenge = null;
    if (preflightUser.is_admin) {
      if (preflightUser.is_suspended) {
        await deleteSecurityState("admin-login-challenge", Number(userId));
        await deleteSecurityState("admin-login-totp", Number(userId));
        await deleteSecurityState("admin-login-email", Number(userId));
        await deleteSecurityState("admin-temp-login", Number(userId));
        return res.status(403).json({ error: "This account has been suspended" });
      }
      activeAdminChallenge = await getSecurityState("admin-login-challenge", Number(userId));
      marker = await getSecurityState("admin-login-totp", Number(userId));
      stored = await getSecurityState("admin-login-email", Number(userId));
      if (!activeAdminChallenge?.challenge || !marker?.challenge || !stored?.challenge ||
          marker.challenge !== activeAdminChallenge.challenge || stored.challenge !== activeAdminChallenge.challenge) {
        await deleteSecurityState("admin-login-challenge", Number(userId));
        await deleteSecurityState("admin-login-totp", Number(userId));
        await deleteSecurityState("admin-login-email", Number(userId));
        await deleteSecurityState("admin-temp-login", Number(userId));
        return res.status(400).json({ error: "Your admin authentication sequence expired — start sign-in again" });
      }
    } else {
      marker = await getSecurityState("totp-verified", Number(userId));
      stored = await getSecurityState("2fa-email", Number(userId));
      if (!marker) {
        return res.status(400).json({ error: "Your authenticator step expired — log in again from the start" });
      }
      if (!stored) {
        return res.status(400).json({ error: "That email code has expired — log in again to get a new one" });
      }
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    if (preflightUser.is_admin) {
      await deleteSecurityState("admin-login-challenge", Number(userId));
      await deleteSecurityState("admin-login-totp", Number(userId));
      await deleteSecurityState("admin-login-email", Number(userId));
    } else {
      await deleteSecurityState("2fa-email", Number(userId));
      await deleteSecurityState("totp-verified", Number(userId));
    }

    const result = preflight;
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const user = result.rows[0];
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";

    const tempMarker = user.is_admin ? await getSecurityState("admin-temp-login", Number(user.id)) : null;
    if (tempMarker && tempMarker.expiresAt > Date.now() &&
        activeAdminChallenge?.challenge && tempMarker.challenge === activeAdminChallenge.challenge) {
      await deleteSecurityState("admin-temp-login", Number(user.id));
      const passwordChangeToken = jwt.sign(
        { type: "admin_temp_password_change", userId: user.id },
        JWT_SECRET,
        { expiresIn: "10m" }
      );
      logAdminAction(user.id, "admin_temporary_password_mfa_completed", `Completed MFA using a Super-Admin-issued temporary password from ${ip || "unknown IP"}`);
      return res.json({
        temporaryPasswordChangeRequired: true,
        passwordChangeToken,
        username: user.username,
      });
    }
    await deleteSecurityState("admin-temp-login", Number(user.id));

    // Admin accounts are deliberately single-session. Only after all three
    // admin authentication steps succeed do we advance token_version. This
    // invalidates every older admin JWT while avoiding a password-only login
    // attempt from kicking the currently signed-in admin out.
    let sessionUser = user;
    if (user.is_admin) {
      const rotated = await pool.query(
        `UPDATE users
         SET token_version = COALESCE(token_version, 0) + 1
         WHERE id = $1
         RETURNING ${USER_RETURNING_FIELDS}`,
        [user.id]
      );
      if (!rotated.rows.length) return res.status(404).json({ error: "Account not found" });
      sessionUser = rotated.rows[0];
    }

    pool
      .query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [sessionUser.id, ip, userAgent])
      .catch((err) => console.error("Failed to record login history:", err.message));
    if (sessionUser.is_admin) {
      logAdminAction(
        sessionUser.id,
        "admin_login_completed",
        `Completed three-step admin login from ${ip || "unknown IP"}; previous admin sessions were revoked`
      );
    }
    setAuthCookie(res, sessionUser, { adminVerifiedAt: Date.now() });
    res.json({ user: sessionUser, adminSessionExpiresInMs: ADMIN_SERVER_SESSION_MS });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/admin/temporary-password/complete", authRateLimit, async (req, res) => {
  try {
    const { passwordChangeToken, newPassword } = req.body;
    if (!passwordChangeToken || !newPassword) {
      return res.status(400).json({ error: "Enter a new password" });
    }
    if (String(newPassword).length < 8) {
      return res.status(400).json({ error: "New password must be at least 8 characters" });
    }

    let decoded;
    try {
      decoded = jwt.verify(passwordChangeToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "That temporary-password recovery session expired — ask the Super Admin for a new temporary password" });
    }
    if (decoded.type !== "admin_temp_password_change") {
      return res.status(401).json({ error: "Invalid password recovery session" });
    }

    const current = await pool.query(
      `SELECT id, is_admin, is_suspended, admin_temp_password_expires_at
       FROM users WHERE id = $1`,
      [decoded.userId]
    );
    if (!current.rows.length || !current.rows[0].is_admin) {
      return res.status(403).json({ error: "Admin access is no longer active" });
    }
    if (current.rows[0].is_suspended) {
      return res.status(403).json({ error: "This admin account has been suspended" });
    }
    const expiry = current.rows[0].admin_temp_password_expires_at ? new Date(current.rows[0].admin_temp_password_expires_at).getTime() : 0;
    if (!expiry || expiry <= Date.now()) {
      return res.status(401).json({ error: "The temporary password expired — ask the Super Admin for a new one" });
    }

    const passwordHash = await bcrypt.hash(String(newPassword), 10);
    const updated = await pool.query(
      `UPDATE users SET
         password_hash = $1,
         admin_temp_password_hash = NULL,
         admin_temp_password_expires_at = NULL,
         admin_temp_password_created_at = NULL,
         admin_temp_password_created_by = NULL,
         token_version = COALESCE(token_version, 0) + 1
       WHERE id = $2
       RETURNING ${USER_RETURNING_FIELDS}`,
      [passwordHash, decoded.userId]
    );
    if (!updated.rows.length) return res.status(404).json({ error: "Admin account not found" });
    const user = updated.rows[0];
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    await pool.query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [user.id, ip, userAgent]);
    logAdminAction(user.id, "admin_temporary_password_completed", `Set a new permanent password after temporary-password recovery from ${ip || "unknown IP"}`);
    setAuthCookie(res, user, { adminVerifiedAt: Date.now() });
    res.json({ user, adminSessionExpiresInMs: ADMIN_SERVER_SESSION_MS });
  } catch (err) {
    if (err.code === "42703") {
      return res.status(409).json({ error: "Run the temporary admin password migration first", code: "MIGRATION_REQUIRED" });
    }
    sendInternalError(res, err);
  }
});

async function moderateImageUrl(url) {
  const { SIGHTENGINE_API_USER, SIGHTENGINE_API_SECRET } = process.env;
  if (!SIGHTENGINE_API_USER || !SIGHTENGINE_API_SECRET) return [];
  try {
    const params = new URLSearchParams({
      url,
      models: "nudity-2.1,offensive,scam,text-content,type",
      api_user: SIGHTENGINE_API_USER,
      api_secret: SIGHTENGINE_API_SECRET,
    });
    const res = await fetch(`https://api.sightengine.com/1.0/check.json?${params}`);
    const data = await res.json();
    if (data.status !== "success") return [];
    const reasons = [];
    if (data.nudity && (data.nudity.raw > 0.5 || data.nudity.partial > 0.5)) {
      reasons.push("Possible nudity detected");
    }
    if (data.offensive?.prob > 0.5) reasons.push("Possibly offensive content");
    if (data.scam?.prob > 0.5) reasons.push("Looks like it may be scam-related imagery");
    if (data.type?.illustration > 0.7) reasons.push("Looks like a graphic/illustration, not a real photo");
    if (data.text?.personal?.length) reasons.push("May contain a phone number or personal contact info");
    if (data.text?.link?.length) reasons.push("May contain a link or promotional text");
    if (data.text?.profanity?.length) reasons.push("May contain inappropriate text");
    return reasons;
  } catch (err) {
    console.error("Sightengine moderation check failed:", err.message);
    return [];
  }
}

async function moderateListingImagesAsync(listingId, imageUrls) {
  if (!Array.isArray(imageUrls) || !imageUrls.length) return;
  const flagged = [];
  for (const url of imageUrls) {
    const reasons = await moderateImageUrl(url);
    if (reasons.length) flagged.push({ url, reasons });
  }
  if (flagged.length) {
    pool
      .query("UPDATE listings SET flagged_images = $1 WHERE id = $2", [JSON.stringify(flagged), listingId])
      .catch((err) => console.error("Couldn't save flagged images:", err.message));
  }
}

app.post("/uploads/image", authenticate, imageUploadIpBurstRateLimit, imageUploadUserBurstRateLimit, imageUploadUserDailyRateLimit, async (req, res) => {
  try {
    const { dataUrl, folder } = req.body;
    if (!dataUrl) return res.status(400).json({ error: "Missing image data" });

    const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
    // Supports the variable name already added in Railway as well as Supabase's newer naming.
    const SUPABASE_SECRET_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
    const SUPABASE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || "stallyard-media";
    if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
      return res.status(500).json({ error: "Image uploads aren't configured — contact support" });
    }

    const match = String(dataUrl).match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/s);
    if (!match) {
      return res.status(400).json({ error: "Invalid image data" });
    }

    const mimeType = match[1].toLowerCase();
    const allowedTypes = new Set(["image/jpeg", "image/jpg", "image/png", "image/webp", "image/avif"]);
    if (!allowedTypes.has(mimeType)) {
      return res.status(400).json({ error: "Unsupported image type" });
    }

    let imageBuffer;
    try {
      imageBuffer = Buffer.from(match[2], "base64");
    } catch {
      return res.status(400).json({ error: "Couldn't decode image" });
    }
    if (!imageBuffer.length) {
      return res.status(400).json({ error: "Image is empty" });
    }
    if (imageBuffer.length > MAX_IMAGE_UPLOAD_BYTES) {
      return res.status(413).json({ error: "Image is too large — maximum upload size is 8 MB" });
    }

    const extension = mimeType === "image/png" ? "png" : mimeType === "image/webp" ? "webp" : mimeType === "image/avif" ? "avif" : "jpg";
    const safeFolder = String(folder || "listings")
      .replace(/^\/+|\/+$/g, "")
      .replace(/[^a-zA-Z0-9/_-]/g, "-") || "listings";
    const objectPath = `${safeFolder}/${req.user.id}/${Date.now()}-${crypto.randomBytes(8).toString("hex")}.${extension}`;

    const uploadUrl = `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(SUPABASE_BUCKET)}/${objectPath.split("/").map(encodeURIComponent).join("/")}`;
    const storageRes = await fetch(uploadUrl, {
      method: "POST",
      headers: {
        apikey: SUPABASE_SECRET_KEY,
        "Content-Type": mimeType,
        "x-upsert": "false",
        "Cache-Control": "public, max-age=31536000, immutable",
      },
      body: imageBuffer,
    });

    let storageData = {};
    try {
      storageData = await storageRes.json();
    } catch {
      // Supabase may return a non-JSON error body; the generic message below is enough for the client.
    }
    if (!storageRes.ok) {
      console.error("Supabase Storage upload failed:", storageRes.status, storageData);
      return res.status(400).json({ error: storageData.message || storageData.error || "Upload to Supabase Storage failed" });
    }

    const encodedPath = objectPath.split("/").map(encodeURIComponent).join("/");
    const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/${encodeURIComponent(SUPABASE_BUCKET)}/${encodedPath}`;
    res.json({
      url: publicUrl,
      path: objectPath,
      publicId: objectPath, // compatibility with the existing frontend response shape
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

// Super Admin-only upload for the large homepage promotional slot. The browser
// streams the MP4/WebM bytes directly instead of base64-encoding them, avoiding
// the ~33% base64 size penalty and keeping the normal JSON limit small.
app.post(
  "/admin/homepage-ads/upload-video",
  authenticate,
  requireAdmin,
  homepageVideoIpRateLimit,
  homepageVideoUserRateLimit,
  express.raw({ type: ["video/mp4", "video/webm"], limit: "40mb" }),
  async (req, res) => {
    try {
      if (req.user.adminRole && req.user.adminRole !== "super_admin") {
        return res.status(403).json({ error: "Only the Super Admin can manage homepage ads" });
      }

      const mimeType = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
      if (!["video/mp4", "video/webm"].includes(mimeType)) {
        return res.status(400).json({ error: "Use an MP4 or WebM promotional video" });
      }
      if (!Buffer.isBuffer(req.body) || !req.body.length) {
        return res.status(400).json({ error: "Video file is empty" });
      }
      if (req.body.length > MAX_HOMEPAGE_VIDEO_BYTES) {
        return res.status(413).json({ error: "Video is too large — maximum upload size is 40 MB" });
      }

      const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
      const SUPABASE_SECRET_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
      const SUPABASE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || "stallyard-media";
      if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
        return res.status(500).json({ error: "Media uploads aren't configured — contact support" });
      }

      const extension = mimeType === "video/webm" ? "webm" : "mp4";
      const objectPath = `homepage-ads/${req.user.id}/${Date.now()}-${crypto.randomBytes(8).toString("hex")}.${extension}`;
      const uploadUrl = `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(SUPABASE_BUCKET)}/${objectPath.split("/").map(encodeURIComponent).join("/")}`;
      const storageRes = await fetch(uploadUrl, {
        method: "POST",
        headers: {
          apikey: SUPABASE_SECRET_KEY,
          "Content-Type": mimeType,
          "x-upsert": "false",
          "Cache-Control": "public, max-age=31536000, immutable",
        },
        body: req.body,
      });

      let storageData = {};
      try { storageData = await storageRes.json(); } catch {}
      if (!storageRes.ok) {
        console.error("Supabase promotional video upload failed:", storageRes.status, storageData);
        return res.status(400).json({ error: storageData.message || storageData.error || "Video upload failed" });
      }

      const encodedPath = objectPath.split("/").map(encodeURIComponent).join("/");
      const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/${encodeURIComponent(SUPABASE_BUCKET)}/${encodedPath}`;
      logAdminAction(req.user.id, "homepage_ad_video_uploaded", "Uploaded a promotional video for homepage Ad 1");
      res.json({ url: publicUrl, path: objectPath });
    } catch (err) {
      sendInternalError(res, err);
    }
  }
);

// Publishes a new listing. RETURNING * only pulls columns from the
// listings table itself, so seller_name/owner_username (which the
// frontend needs to attribute the listing to the right seller, e.g. for
// "My Stall" filtering) aren't in that row — they only come from the JOIN
// in GET /listings. Fetching them here and merging them into the response
// keeps a freshly published listing consistent with what a page refresh
// would show, instead of silently missing its owner until then.
const LISTING_SUBCATEGORIES = {
  "Accessories": [
    "Belts",
    "Hats & Caps",
    "Scarves & Wraps",
    "Sunglasses",
    "Eyewear",
    "Hair Accessories",
    "Gloves",
    "Wallets",
    "Keychains",
    "Umbrellas",
    "Watches",
    "Fashion Accessories",
    "Other Accessories"
  ],
  "Art": [
    "Paintings",
    "Drawings & Illustrations",
    "Prints",
    "Photography",
    "Sculpture",
    "Digital Art",
    "Wall Art",
    "African Art",
    "Mixed Media",
    "Art Supplies",
    "Posters",
    "Other Art"
  ],
  "Auto Parts": [
    "Engine Parts",
    "Transmission Parts",
    "Brakes",
    "Suspension & Steering",
    "Tires",
    "Wheels & Rims",
    "Batteries",
    "Alternators & Starters",
    "Filters",
    "Exhaust Parts",
    "Cooling System",
    "Fuel System",
    "Electrical Parts",
    "Headlights & Lighting",
    "Mirrors",
    "Body Parts",
    "Bumpers",
    "Doors & Windows",
    "Interior Parts",
    "Car Audio",
    "GPS & Electronics",
    "Tools & Equipment",
    "Motorcycle Parts",
    "Truck Parts",
    "Car Care Products",
    "Other Auto Parts"
  ],
  "Bags & Purses": [
    "Handbags",
    "Shoulder Bags",
    "Crossbody Bags",
    "Tote Bags",
    "Backpacks",
    "Clutches",
    "Wallets",
    "Travel Bags",
    "Laptop Bags",
    "School Bags",
    "Briefcases",
    "Luggage",
    "Cosmetic Bags",
    "Other Bags"
  ],
  "Bath & Beauty": [
    "Skin Care",
    "Hair Care",
    "Makeup",
    "Fragrances",
    "Bath Products",
    "Body Care",
    "Nail Care",
    "Shaving & Grooming",
    "Beauty Tools",
    "Hair Extensions & Wigs",
    "Natural Beauty Products",
    "Men's Grooming",
    "Other Beauty Products"
  ],
  "Books": [
    "Fiction",
    "Nonfiction",
    "Children's Books",
    "Textbooks",
    "Academic Books",
    "Religious Books",
    "Business Books",
    "Self-Help",
    "Cookbooks",
    "Comics & Graphic Novels",
    "Magazines",
    "Dictionaries",
    "Exam Preparation",
    "Used Books",
    "Rare Books",
    "Other Books"
  ],
  "Clothing": [
    "Men's Clothing",
    "Women's Clothing",
    "Boys' Clothing",
    "Girls' Clothing",
    "Dresses",
    "Shirts",
    "T-Shirts",
    "Trousers",
    "Jeans",
    "Shorts",
    "Skirts",
    "Suits",
    "Jackets & Coats",
    "Sweaters",
    "Sportswear",
    "Underwear",
    "Sleepwear",
    "Swimwear",
    "Traditional Nigerian Clothing",
    "Maternity Clothing",
    "Uniforms",
    "Other Clothing"
  ],
  "Collectibles": [
    "Coins",
    "Stamps",
    "Trading Cards",
    "Sports Memorabilia",
    "Music Memorabilia",
    "Movie Memorabilia",
    "Historical Memorabilia",
    "Figurines",
    "Dolls",
    "Antiques",
    "Vintage Collectibles",
    "Autographs",
    "Advertising Collectibles",
    "African Collectibles",
    "Other Collectibles"
  ],
  "Craft Supplies & Tools": [
    "Beads",
    "Fabric",
    "Yarn",
    "Sewing Supplies",
    "Knitting Supplies",
    "Crochet Supplies",
    "Jewelry Making",
    "Leatherworking",
    "Woodworking",
    "Painting Supplies",
    "Drawing Supplies",
    "Sculpting Supplies",
    "Candle Making",
    "Soap Making",
    "Floral Supplies",
    "Craft Tools",
    "Other Craft Supplies"
  ],
  "Electronics": [
    "Mobile Phones",
    "Smartphones",
    "Tablets",
    "Laptops",
    "Desktop Computers",
    "Computer Components",
    "Computer Accessories",
    "Monitors",
    "Televisions",
    "Projectors",
    "Cameras",
    "Camera Accessories",
    "Video Cameras",
    "Headphones",
    "Earbuds",
    "Speakers",
    "Home Audio",
    "Gaming Consoles",
    "Video Games",
    "Smart Watches",
    "Wearable Technology",
    "Chargers & Cables",
    "Power Banks",
    "Routers & Networking",
    "Printers & Scanners",
    "Storage Devices",
    "Security Cameras",
    "Smart Home Devices",
    "Electronic Accessories",
    "Other Electronics"
  ],
  "Gifts": [
    "Birthday Gifts",
    "Wedding Gifts",
    "Anniversary Gifts",
    "Graduation Gifts",
    "Baby Gifts",
    "Gifts for Him",
    "Gifts for Her",
    "Gifts for Kids",
    "Corporate Gifts",
    "Personalized Gifts",
    "Gift Sets",
    "Gift Cards",
    "Holiday Gifts",
    "Other Gifts"
  ],
  "Groceries": [
    "Rice & Grains",
    "Pasta & Noodles",
    "Flour & Baking",
    "Cooking Oil",
    "Spices & Seasonings",
    "Canned Foods",
    "Snacks",
    "Biscuits & Cookies",
    "Sweets & Chocolate",
    "Beverages",
    "Tea & Coffee",
    "Breakfast Foods",
    "Dairy Products",
    "Frozen Foods",
    "Fresh Produce",
    "Meat & Seafood",
    "Nigerian Food Products",
    "Health Foods",
    "Baby Food",
    "Other Groceries"
  ],
  "Handmade": [
    "Handmade Jewelry",
    "Handmade Clothing",
    "Handmade Bags",
    "Handmade Shoes",
    "Handmade Furniture",
    "Handmade Home Decor",
    "Handmade Art",
    "Handmade Toys",
    "Handmade Beauty Products",
    "Handmade Gifts",
    "Handmade Accessories",
    "Traditional Crafts",
    "Other Handmade Items"
  ],
  "Home": [
    "Furniture",
    "Living Room Furniture",
    "Bedroom Furniture",
    "Dining Furniture",
    "Office Furniture",
    "Home Decor",
    "Rugs & Carpets",
    "Curtains & Blinds",
    "Lighting",
    "Bedding",
    "Mattresses",
    "Kitchenware",
    "Cookware",
    "Dinnerware",
    "Small Appliances",
    "Major Appliances",
    "Storage & Organization",
    "Bathroom Accessories",
    "Cleaning Supplies",
    "Garden & Outdoor",
    "Home Improvement",
    "Tools",
    "Other Home Items"
  ],
  "Jewelry": [
    "Rings",
    "Necklaces",
    "Earrings",
    "Bracelets",
    "Anklets",
    "Chains",
    "Pendants",
    "Brooches",
    "Engagement Rings",
    "Wedding Rings",
    "Men's Jewelry",
    "Women's Jewelry",
    "Gold Jewelry",
    "Silver Jewelry",
    "Beaded Jewelry",
    "Costume Jewelry",
    "Traditional Jewelry",
    "Other Jewelry"
  ],
  "Kids & Baby": [
    "Baby Clothing",
    "Kids' Clothing",
    "Baby Shoes",
    "Kids' Shoes",
    "Diapers",
    "Baby Feeding",
    "Bottles",
    "Strollers",
    "Car Seats",
    "Cribs",
    "Baby Bedding",
    "Baby Furniture",
    "Baby Bath",
    "Maternity Products",
    "School Supplies",
    "Kids' Accessories",
    "Other Baby & Kids Items"
  ],
  "Movies & Music": [
    "DVDs",
    "Blu-rays",
    "CDs",
    "Vinyl Records",
    "Music Downloads/Media",
    "Movie Collectibles",
    "Music Collectibles",
    "Musical Instruments",
    "Guitars",
    "Keyboards & Pianos",
    "Drums",
    "DJ Equipment",
    "Studio Equipment",
    "Microphones",
    "Other Movies & Music"
  ],
  "Outdoors": [
    "Camping",
    "Hiking",
    "Fishing",
    "Cycling",
    "Sports Equipment",
    "Football",
    "Basketball",
    "Fitness Equipment",
    "Gym Equipment",
    "Running",
    "Swimming",
    "Hunting Accessories",
    "Outdoor Furniture",
    "Garden Equipment",
    "Travel Gear",
    "Other Outdoor Items"
  ],
  "Paper & Party Supplies": [
    "Invitations",
    "Greeting Cards",
    "Gift Wrap",
    "Gift Bags",
    "Stickers",
    "Stationery",
    "Notebooks",
    "Journals",
    "Party Decorations",
    "Balloons",
    "Cake Decorations",
    "Party Favors",
    "Event Supplies",
    "Other Party Supplies"
  ],
  "Pet Supplies": [
    "Dog Supplies",
    "Cat Supplies",
    "Bird Supplies",
    "Fish & Aquarium Supplies",
    "Pet Food",
    "Pet Beds",
    "Collars & Leashes",
    "Pet Clothing",
    "Pet Toys",
    "Grooming Supplies",
    "Pet Carriers",
    "Other Pet Supplies"
  ],
  "Shoes": [
    "Men's Shoes",
    "Women's Shoes",
    "Boys' Shoes",
    "Girls' Shoes",
    "Sneakers",
    "Sandals",
    "Slippers",
    "Boots",
    "Heels",
    "Flats",
    "Formal Shoes",
    "Work Shoes",
    "Sports Shoes",
    "Traditional Footwear",
    "Other Shoes"
  ],
  "Toys & Games": [
    "Action Figures",
    "Dolls",
    "Educational Toys",
    "Building Toys",
    "Baby Toys",
    "Outdoor Toys",
    "Remote-Control Toys",
    "Board Games",
    "Card Games",
    "Puzzles",
    "Video Games",
    "Gaming Accessories",
    "Stuffed Animals",
    "Other Toys & Games"
  ],
  "Vintage": [
    "Vintage Clothing",
    "Vintage Jewelry",
    "Vintage Furniture",
    "Vintage Home Decor",
    "Vintage Electronics",
    "Vintage Books",
    "Vintage Toys",
    "Vintage Bags",
    "Vintage Shoes",
    "Vintage Collectibles",
    "Other Vintage Items"
  ],
  "Weddings": [
    "Wedding Dresses",
    "Bridesmaid Dresses",
    "Groom & Groomsmen",
    "Wedding Shoes",
    "Wedding Jewelry",
    "Wedding Accessories",
    "Invitations",
    "Decorations",
    "Cake Accessories",
    "Wedding Favors",
    "Bridal Shower",
    "Traditional Wedding Items",
    "Wedding Gifts",
    "Other Wedding Supplies"
  ],
  "Other": [
    "Business & Industrial",
    "Office Supplies",
    "Medical Supplies",
    "Agricultural Equipment",
    "Construction Equipment",
    "Tools & Machinery",
    "Renewable Energy",
    "Solar Equipment",
    "Safety Equipment",
    "Miscellaneous"
  ]
};

const CASUAL_SELLER_LIMIT_NGN = 500000;
const VERIFIED_SELLER_LIMIT_NGN = 10000000;
const CASUAL_SELLER_ID_TYPES = new Set(["nin", "passport", "drivers_license", "voters_card", "cerpac"]);
const CASUAL_SELLER_CONSENT_VERSION = "2026-09-12";
const VERIFICATION_BUCKET = process.env.SUPABASE_VERIFICATION_BUCKET || "seller-verification-private";

function verificationStorageConfig() {
  return {
    url: (process.env.SUPABASE_URL || "").replace(/\/$/, ""),
    key: process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || "",
  };
}

async function ensurePrivateVerificationBucket() {
  const { url, key } = verificationStorageConfig();
  if (!url || !key) throw new Error("Private seller-verification storage is not configured");
  const inspect = await fetch(`${url}/storage/v1/bucket/${encodeURIComponent(VERIFICATION_BUCKET)}`, {
    headers: { apikey: key, Authorization: `Bearer ${key}` },
  });
  if (inspect.ok) {
    const bucket = await inspect.json();
    if (bucket.public) throw new Error(`${VERIFICATION_BUCKET} exists but is public; identity evidence requires a private bucket`);
    return;
  }
  if (![400, 404].includes(inspect.status)) throw new Error(`Could not inspect private verification bucket (${inspect.status})`);
  const created = await fetch(`${url}/storage/v1/bucket`, {
    method: "POST",
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ id: VERIFICATION_BUCKET, name: VERIFICATION_BUCKET, public: false, file_size_limit: 25 * 1024 * 1024,
      allowed_mime_types: ["image/jpeg", "application/pdf"] }),
  });
  if (!created.ok) throw new Error(`Could not create private verification bucket (${created.status})`);
}

function parseVerificationJpeg(dataUrl, label) {
  const match = String(dataUrl || "").match(/^data:image\/jpeg;base64,([a-zA-Z0-9+/=]+)$/);
  if (!match) throw Object.assign(new Error(`${label} must be a camera-captured JPEG image`), { statusCode: 400 });
  const buffer = Buffer.from(match[1], "base64");
  if (buffer.length < 20 * 1024) throw Object.assign(new Error(`${label} is too small or unclear — capture it again`), { statusCode: 400 });
  if (buffer.length > 3 * 1024 * 1024) throw Object.assign(new Error(`${label} is too large — maximum 3 MB`), { statusCode: 413 });
  if (buffer[0] !== 0xff || buffer[1] !== 0xd8 || buffer[buffer.length - 2] !== 0xff || buffer[buffer.length - 1] !== 0xd9) {
    throw Object.assign(new Error(`${label} is not a valid JPEG image`), { statusCode: 400 });
  }
  return { buffer, sha256: crypto.createHash("sha256").update(buffer).digest("hex") };
}

async function uploadPrivateVerificationObject(path, buffer, contentType = "image/jpeg") {
  const { url, key } = verificationStorageConfig();
  if (!url || !key) throw Object.assign(new Error("Private identity storage isn't configured"), { statusCode: 500 });
  const endpoint = `${url}/storage/v1/object/${encodeURIComponent(VERIFICATION_BUCKET)}/${path.split("/").map(encodeURIComponent).join("/")}`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": contentType, "x-upsert": "false" },
    body: buffer,
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    console.error("Private verification upload failed:", response.status, body.slice(0, 300));
    throw Object.assign(new Error("Couldn't securely store verification evidence"), { statusCode: 502 });
  }
  return path;
}

async function fetchPrivateVerificationObject(path) {
  const { url, key } = verificationStorageConfig();
  if (!url || !key) throw new Error("Private identity storage isn't configured");
  const endpoint = `${url}/storage/v1/object/authenticated/${encodeURIComponent(VERIFICATION_BUCKET)}/${String(path).split("/").map(encodeURIComponent).join("/")}`;
  const response = await fetch(endpoint, { headers: { apikey: key, Authorization: `Bearer ${key}` } });
  if (!response.ok) throw new Error(`Private verification object could not be read (${response.status})`);
  return Buffer.from(await response.arrayBuffer());
}

function identityDigest(value) {
  const secret = process.env.FIELD_ENCRYPTION_KEY || JWT_SECRET || "development-only";
  return crypto.createHmac("sha256", secret).update(String(value || "").replace(/\s+/g, "").toUpperCase()).digest("hex");
}

function normalizedPersonName(value) {
  return String(value || "").toLowerCase().replace(/[^a-z]/g, "");
}

function ageOnDate(dateOfBirth, now = new Date()) {
  const birth = new Date(`${dateOfBirth}T00:00:00Z`);
  if (Number.isNaN(birth.getTime()) || birth > now) return -1;
  let age = now.getUTCFullYear() - birth.getUTCFullYear();
  const beforeBirthday = now.getUTCMonth() < birth.getUTCMonth() ||
    (now.getUTCMonth() === birth.getUTCMonth() && now.getUTCDate() < birth.getUTCDate());
  if (beforeBirthday) age--;
  return age;
}

async function activeListingValue(client, ownerId, excludeListingId = null) {
  const result = await client.query(
    `SELECT COALESCE(SUM(price * GREATEST(COALESCE(quantity, 1), 1)), 0)::numeric AS total
       FROM listings WHERE owner_id = $1 AND status = 'active' AND ($2::integer IS NULL OR id <> $2)`,
    [ownerId, excludeListingId]
  );
  return Number(result.rows[0]?.total || 0);
}

async function assertSellerMayPublish(client, ownerId, proposedPrice, proposedQuantity, excludeListingId = null) {
  const userResult = await client.query(
    `SELECT is_approved, casual_seller_status, casual_seller_limit, seller_tier, seller_listing_limit, username, display_name
       FROM users WHERE id = $1 FOR UPDATE`,
    [ownerId]
  );
  if (!userResult.rows.length) throw Object.assign(new Error("Seller account not found"), { statusCode: 404 });
  const seller = userResult.rows[0];
  const price = Number(proposedPrice || 0);
  const quantity = Math.max(1, Number(proposedQuantity || 1));
  const current = await activeListingValue(client, ownerId, excludeListingId);
  if (seller.is_approved) {
    const verifiedLimit = Number(seller.seller_listing_limit || VERIFIED_SELLER_LIMIT_NGN);
    if (!Number.isFinite(price) || price <= 0 || current + price * quantity > verifiedLimit) {
      throw Object.assign(new Error(`Verified sellers may have no more than ₦${verifiedLimit.toLocaleString("en-NG")} in combined active listings.`), {
        statusCode: 409, code: "VERIFIED_LISTING_LIMIT", currentActiveValue: current, limit: verifiedLimit,
      });
    }
    return seller;
  }
  if (seller.casual_seller_status !== "approved") {
    throw Object.assign(new Error("Complete automatic casual-seller identity verification before publishing."), { statusCode: 403, code: "CASUAL_VERIFICATION_REQUIRED" });
  }
  const limit = Number(seller.casual_seller_limit || CASUAL_SELLER_LIMIT_NGN);
  if (!Number.isFinite(price) || price <= 0 || current + price * quantity > limit) {
    throw Object.assign(new Error(`Casual sellers may have no more than ₦${limit.toLocaleString("en-NG")} in combined active listings.`), {
      statusCode: 409, code: "CASUAL_LISTING_LIMIT", currentActiveValue: current, limit,
    });
  }
  return seller;
}

app.get("/casual-seller/status", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const user = await pool.query(
      `SELECT casual_seller_status, casual_seller_limit, casual_seller_approved_at,
              is_approved, is_email_verified, is_phone_verified
         FROM users WHERE id = $1`, [req.user.id]
    );
    const latest = await pool.query(
      `SELECT reference, status, decision_reason, automatic_checks, created_at, approved_at
         FROM casual_seller_applications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, [req.user.id]
    );
    const currentValue = await activeListingValue(pool, req.user.id);
    res.json({
      status: user.rows[0]?.casual_seller_status || "none",
      limit: Number(user.rows[0]?.casual_seller_limit || CASUAL_SELLER_LIMIT_NGN),
      currentActiveValue: currentValue,
      remainingValue: Math.max(0, Number(user.rows[0]?.casual_seller_limit || CASUAL_SELLER_LIMIT_NGN) - currentValue),
      fullyApprovedSeller: !!user.rows[0]?.is_approved,
      emailVerified: !!user.rows[0]?.is_email_verified,
      phoneVerified: !!user.rows[0]?.is_phone_verified,
      application: latest.rows[0] || null,
    });
  } catch (err) { sendInternalError(res, err); }
});

app.post("/casual-seller/apply", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, async (req, res) => {
  const client = await pool.connect();
  const uploadedPaths = [];
  try {
    const {
      legalName, dateOfBirth, consent,
      liveSelfie, holdingIdSelfie, challengeFrames, challenges,
      faceDetectionSupported, faceChecks, faceMatch,
    } = req.body || {};
    if (consent !== true) return res.status(400).json({ error: "Consent is required before identity verification" });
    if (!legalName || !dateOfBirth) {
      return res.status(400).json({ error: "Complete your legal name and birth date" });
    }
    if (ageOnDate(dateOfBirth) < 18) return res.status(400).json({ error: "Casual sellers must be at least 18 years old" });
    if (!Array.isArray(challengeFrames) || challengeFrames.length !== 3 || !Array.isArray(challenges) || challenges.length !== 3) {
      return res.status(400).json({ error: "Complete all three live camera challenges" });
    }
    const acceptedChallenges = new Set(["blink", "turn_left", "turn_right", "smile", "move_closer"]);
    if (new Set(challenges).size !== 3 || challenges.some((item) => !acceptedChallenges.has(item))) {
      return res.status(400).json({ error: "The live camera challenge is invalid — restart verification" });
    }

    const images = {
      live_selfie: parseVerificationJpeg(liveSelfie, "Live selfie"),
      holding_id_selfie: parseVerificationJpeg(holdingIdSelfie, "Selfie holding ID"),
    };
    challengeFrames.forEach((frame, index) => { images[`challenge_${index + 1}`] = parseVerificationJpeg(frame, `Challenge photo ${index + 1}`); });
    const hashes = Object.values(images).map((image) => image.sha256);
    const distinctEvidence = new Set(hashes).size === hashes.length;

    await client.query("BEGIN");
    const accountResult = await client.query(
      `SELECT id, username, email, phone, first_name, last_name, other_name, display_name, country,
              is_email_verified, is_phone_verified, is_suspended, is_approved, casual_seller_status
         FROM users WHERE id = $1 FOR UPDATE`, [req.user.id]
    );
    const account = accountResult.rows[0];
    if (!account || account.is_suspended) throw Object.assign(new Error("This account cannot apply"), { statusCode: 403 });
    if (account.is_approved) throw Object.assign(new Error("Your account already has full seller approval"), { statusCode: 409 });
    if (!account.is_email_verified || !account.is_phone_verified) {
      throw Object.assign(new Error("Verify both your email and phone number before applying"), { statusCode: 400, code: "CONTACT_VERIFICATION_REQUIRED" });
    }
    const accountName = normalizedPersonName(`${account.last_name || ""} ${account.first_name || ""} ${account.other_name || ""}`) || normalizedPersonName(account.display_name);
    const submittedName = normalizedPersonName(legalName);
    const nameMatches = !!accountName && (submittedName.includes(accountName) || accountName.includes(submittedName));
    const clientFaceChecks = faceDetectionSupported === true && Array.isArray(faceChecks) && faceChecks.length >= 5 && faceChecks.every(Boolean);
    const faceDescriptor = Array.isArray(faceMatch?.selfieDescriptor) && faceMatch.selfieDescriptor.length === 128 &&
      faceMatch.selfieDescriptor.every((value) => Number.isFinite(Number(value)) && Math.abs(Number(value)) < 10)
      ? faceMatch.selfieDescriptor.map(Number) : null;
    const checks = {
      age18OrOlder: true,
      nigeriaAccount: isNigeriaCountry(account.country),
      emailVerified: true,
      phoneVerified: true,
      nameMatchesProfile: nameMatches,
      evidenceFilesPresent: Object.keys(images).length >= 5,
      evidenceFilesDistinct: distinctEvidence,
      randomizedChallengesComplete: true,
      cameraFacePresenceChecks: clientFaceChecks,
      liveSelfieMatchesHoldingPhoto: faceMatch?.passed === true && Number(faceMatch?.distance) >= 0 && Number(faceMatch.distance) <= 0.5,
      validFaceDescriptor: !!faceDescriptor,
      duplicateFaceNotFound: true,
    };
    if (faceDescriptor) {
      const previousFaces = await client.query(
        `SELECT user_id, face_descriptor FROM casual_seller_applications
          WHERE user_id <> $1 AND status IN ('approved','suspended') AND face_descriptor IS NOT NULL`, [req.user.id]
      );
      checks.duplicateFaceNotFound = !previousFaces.rows.some((row) => {
        const stored = row.face_descriptor;
        if (!Array.isArray(stored) || stored.length !== 128) return false;
        const distance = Math.sqrt(faceDescriptor.reduce((sum, value, index) => sum + (value - Number(stored[index] || 0)) ** 2, 0));
        return distance < 0.45;
      });
    }
    const approved = Object.values(checks).every(Boolean);
    const status = approved ? "approved" : "review_required";
    const failedLabels = Object.entries(checks).filter(([, passed]) => !passed).map(([name]) => name);
    const reference = `CSV-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
    const applicationInsert = await client.query(
      `INSERT INTO casual_seller_applications
        (reference, user_id, legal_name, date_of_birth, id_type, id_number_hash, id_number_last4,
         id_expiration, evidence_paths, evidence_hashes, liveness_challenges, automatic_checks,
         status, decision_reason, consent_version, consented_at, submitted_ip_hash, submitted_user_agent, approved_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'{}'::jsonb,$9,$10,$11,$12,$13,$14,NOW(),$15,$16,
         CASE WHEN $12 = 'approved' THEN NOW() ELSE NULL END) RETURNING id`,
      [reference, req.user.id, String(legalName).trim(), dateOfBirth, null, null, null,
       null, JSON.stringify(Object.fromEntries(Object.entries(images).map(([k, v]) => [k, v.sha256]))),
       JSON.stringify(challenges), JSON.stringify(checks), status,
       approved ? "All automatic checks passed" : `Automatic verification needs attention: ${failedLabels.join(", ")}`,
       CASUAL_SELLER_CONSENT_VERSION, identityDigest(getClientIp(req) || "unknown"), String(req.headers["user-agent"] || "").slice(0, 500)]
    );
    const applicationId = applicationInsert.rows[0].id;
    const evidencePaths = {};
    for (const [name, image] of Object.entries(images)) {
      const path = `user-${req.user.id}/application-${applicationId}/${name}-${image.sha256.slice(0, 12)}.jpg`;
      evidencePaths[name] = await uploadPrivateVerificationObject(path, image.buffer);
      uploadedPaths.push(path);
    }
    await client.query("UPDATE casual_seller_applications SET evidence_paths = $1, face_descriptor = $2 WHERE id = $3", [JSON.stringify(evidencePaths), JSON.stringify(faceDescriptor), applicationId]);
    await client.query(
      `UPDATE users SET casual_seller_status = $1, casual_seller_approved_at = CASE WHEN $1 = 'approved' THEN NOW() ELSE NULL END,
         has_applied_to_sell = true, verification_status = CASE WHEN $1 = 'approved' THEN 'casual_approved' ELSE 'review_required' END
       WHERE id = $2`, [status, req.user.id]
    );
    await client.query("COMMIT");
    createNotification(req.user.id, approved ? "seller_verified" : "verification_problem",
      approved ? "Your casual-seller identity verification passed. You may publish up to ₦500,000 in combined active listings."
        : "Your automatic identity verification needs attention. Please review the results and try again.");
    res.status(201).json({ reference, status, checks, limit: CASUAL_SELLER_LIMIT_NGN });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.code === "23505") return res.status(409).json({ error: "This identity is already connected to another seller account", code: "DUPLICATE_IDENTITY" });
    if (err.statusCode) return res.status(err.statusCode).json({ error: err.message, code: err.code, currentActiveValue: err.currentActiveValue, limit: err.limit });
    sendInternalError(res, err, "casual seller application");
  } finally { client.release(); }
});

function parsePrivateApplicationDocument(dataUrl, label) {
  const match = String(dataUrl || "").match(/^data:(image\/jpeg|application\/pdf);base64,([a-zA-Z0-9+/=]+)$/);
  if (!match) throw Object.assign(new Error(`${label} must be a JPEG image or PDF`), { statusCode: 400 });
  const buffer = Buffer.from(match[2], "base64");
  if (buffer.length < 1024 || buffer.length > 6 * 1024 * 1024) throw Object.assign(new Error(`${label} must be between 1 KB and 6 MB`), { statusCode: 413 });
  if (match[1] === "application/pdf" && buffer.subarray(0, 5).toString() !== "%PDF-") throw Object.assign(new Error(`${label} is not a valid PDF`), { statusCode: 400 });
  if (match[1] === "image/jpeg" && (buffer[0] !== 0xff || buffer[1] !== 0xd8)) throw Object.assign(new Error(`${label} is not a valid JPEG`), { statusCode: 400 });
  return { buffer, contentType: match[1], extension: match[1] === "application/pdf" ? "pdf" : "jpg", sha256: crypto.createHash("sha256").update(buffer).digest("hex") };
}

app.post("/verified-seller/apply", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, async (req, res) => {
  const client = await pool.connect();
  try {
    if (req.body?.consent !== true) return res.status(400).json({ error: "Accept the verified-seller declaration before applying" });
    const document = parsePrivateApplicationDocument(req.body?.bankStatement, "Bank statement");
    const idType = String(req.body?.idType || "").trim();
    if (!CASUAL_SELLER_ID_TYPES.has(idType)) return res.status(400).json({ error: "Choose an accepted identification" });
    const idFront = parseVerificationJpeg(req.body?.idFront, "ID front");
    const idBack = req.body?.idBack ? parseVerificationJpeg(req.body.idBack, "ID back") : null;
    await client.query("BEGIN");
    const userResult = await client.query(
      `SELECT id, username, is_approved, is_suspended, casual_seller_status, is_email_verified,
              is_phone_verified, paystack_recipient_code FROM users WHERE id=$1 FOR UPDATE`, [req.user.id]
    );
    const user = userResult.rows[0];
    if (!user || user.is_suspended) throw Object.assign(new Error("This account cannot apply"), { statusCode: 403 });
    if (user.is_approved) throw Object.assign(new Error("Your account is already a verified seller"), { statusCode: 409 });
    if (user.casual_seller_status !== "approved") throw Object.assign(new Error("Complete automatic casual-seller identity verification first"), { statusCode: 400 });
    if (!user.is_email_verified || !user.is_phone_verified) throw Object.assign(new Error("Verify your email and phone number first"), { statusCode: 400 });
    if (!user.paystack_recipient_code) throw Object.assign(new Error("Add and verify your seller payout bank account first"), { statusCode: 400 });
    const identityResult = await client.query(
      "SELECT id, reference FROM casual_seller_applications WHERE user_id=$1 AND status='approved' ORDER BY approved_at DESC LIMIT 1", [req.user.id]
    );
    if (!identityResult.rows.length) throw Object.assign(new Error("Approved identity evidence was not found — complete casual verification again"), { statusCode: 400 });
    const addressResult = await client.query(
      `SELECT id, full_name, phone, street, city, state, zip, country FROM user_addresses
        WHERE user_id=$1 AND is_default=true AND street<>'' AND city<>'' AND state<>'' AND LOWER(country)='nigeria' LIMIT 1`, [req.user.id]
    );
    if (!addressResult.rows.length) throw Object.assign(new Error("Add a complete default Nigerian address before applying"), { statusCode: 400 });
    const existing = await client.query("SELECT reference FROM verified_seller_applications WHERE user_id=$1 AND status='pending'", [req.user.id]);
    if (existing.rows.length) throw Object.assign(new Error(`Your verified-seller application ${existing.rows[0].reference} is already awaiting review`), { statusCode: 409 });
    const reference = `VSA-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
    const path = `user-${req.user.id}/verified-seller/${reference}/bank-statement-${document.sha256.slice(0, 12)}.${document.extension}`;
    const idFrontPath = `user-${req.user.id}/verified-seller/${reference}/id-front-${idFront.sha256.slice(0, 12)}.jpg`;
    const idBackPath = idBack ? `user-${req.user.id}/verified-seller/${reference}/id-back-${idBack.sha256.slice(0, 12)}.jpg` : null;
    await uploadPrivateVerificationObject(path, document.buffer, document.contentType);
    await uploadPrivateVerificationObject(idFrontPath, idFront.buffer);
    if (idBack && idBackPath) await uploadPrivateVerificationObject(idBackPath, idBack.buffer);
    const snapshot = { identityReference: identityResult.rows[0].reference, emailVerified: true, phoneVerified: true,
      payoutBankVerified: true, address: addressResult.rows[0], requestedLimit: VERIFIED_SELLER_LIMIT_NGN,
      idType };
    await client.query(
      `INSERT INTO verified_seller_applications(reference,user_id,casual_application_id,bank_statement_path,address_id,
         requested_limit,requirements_snapshot,consented_at,status,id_type,id_number_hash,id_number_last4,id_expiration,id_front_path,id_back_path)
       VALUES($1,$2,$3,$4,$5,$6,$7,NOW(),'pending',$8,$9,$10,$11,$12,$13)`,
      [reference, req.user.id, identityResult.rows[0].id, path, addressResult.rows[0].id, VERIFIED_SELLER_LIMIT_NGN, JSON.stringify(snapshot),
       idType, null, null, null, idFrontPath, idBackPath]
    );
    await client.query("UPDATE users SET has_applied_to_sell=true, verification_status='pending', rejection_reason=NULL WHERE id=$1", [req.user.id]);
    await client.query("COMMIT");
    createNotification(req.user.id, "seller_application", `Your verified-seller application ${reference} was submitted for review.`);
    res.status(201).json({ reference, status: "pending", requestedLimit: VERIFIED_SELLER_LIMIT_NGN });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.statusCode) return res.status(err.statusCode).json({ error: err.message });
    if (err.code === "23505") return res.status(409).json({ error: "A verified-seller application is already pending" });
    sendInternalError(res, err, "verified seller application");
  } finally { client.release(); }
});

app.get("/admin/verified-seller-applications", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.id,a.reference,a.user_id,a.requested_limit,a.requirements_snapshot,a.status,a.decision_reason,
              a.id_type,(a.id_back_path IS NOT NULL) AS has_id_back,
              a.created_at,a.reviewed_at,u.username,u.display_name,u.email,u.phone
         FROM verified_seller_applications a JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 500`
    );
    res.json({ applications: result.rows });
  } catch (err) { sendInternalError(res, err); }
});

app.patch("/admin/verified-seller-applications/:id/auto-verify", authenticate, requireSuperAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const applicationResult = await client.query(
      `SELECT a.*, u.username, u.is_suspended, u.casual_seller_status,
              u.is_email_verified, u.is_phone_verified, u.paystack_recipient_code
         FROM verified_seller_applications a
         JOIN users u ON u.id = a.user_id
        WHERE a.id = $1 FOR UPDATE`,
      [req.params.id]
    );
    if (!applicationResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Verified Seller application not found" });
    }
    const application = applicationResult.rows[0];
    if (application.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Only a pending Verified Seller application can be auto-verified" });
    }

    const addressResult = await client.query(
      `SELECT id FROM user_addresses
        WHERE id = $1 AND user_id = $2 AND is_default = true
          AND street <> '' AND city <> '' AND state <> '' AND LOWER(country) = 'nigeria'`,
      [application.address_id, application.user_id]
    );
    const failedChecks = [];
    if (application.is_suspended) failedChecks.push("account is suspended");
    if (application.casual_seller_status !== "approved") failedChecks.push("Casual Seller verification is not approved");
    if (!application.is_email_verified) failedChecks.push("email is not verified");
    if (!application.is_phone_verified) failedChecks.push("phone is not verified");
    if (!application.paystack_recipient_code) failedChecks.push("payout bank account is not verified");
    if (!addressResult.rows.length) failedChecks.push("complete default Nigerian address is missing");
    if (!CASUAL_SELLER_ID_TYPES.has(application.id_type)) failedChecks.push("accepted identification type is missing");
    if (!application.id_front_path) failedChecks.push("front identification image is missing");
    if (!application.bank_statement_path) failedChecks.push("bank statement is missing");
    if (!application.consented_at) failedChecks.push("seller declaration was not accepted");
    if (Number(application.requested_limit) !== VERIFIED_SELLER_LIMIT_NGN) failedChecks.push("requested limit is invalid");
    if (failedChecks.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: `Automatic verification could not approve this application: ${failedChecks.join("; ")}`,
        failedChecks,
      });
    }

    const userResult = await client.query(
      `UPDATE users SET is_approved = true, verification_status = 'approved', rejection_reason = NULL,
         seller_tier = 'verified', seller_listing_limit = $1
       WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [VERIFIED_SELLER_LIMIT_NGN, application.user_id]
    );
    await client.query(
      `UPDATE verified_seller_applications
          SET status = 'approved', decision_reason = 'Approved by Super Admin automatic record checks',
              reviewed_by = $1, reviewed_at = NOW(), updated_at = NOW()
        WHERE id = $2`,
      [req.user.id, application.id]
    );
    await client.query("COMMIT");
    logAdminAction(req.user.id, "verified_seller_auto_verified", `Auto-verified ${application.username}'s Verified Seller application ${application.reference}`);
    createNotification(
      application.user_id,
      "seller_application",
      "Your Verified Seller application was approved. You may now maintain up to ₦10,000,000 in combined active listings."
    );
    res.json({
      user: userResult.rows[0],
      applicationId: application.id,
      checksPassed: ["casual seller", "email", "phone", "payout bank", "address", "ID image", "bank statement", "consent"],
      notice: "Automatic record checks do not authenticate the identification with its issuing government agency.",
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    sendInternalError(res, err, "verified seller automatic verification");
  } finally {
    client.release();
  }
});

app.get("/admin/verified-seller-applications/:id/bank-statement", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const result = await pool.query("SELECT reference,bank_statement_path FROM verified_seller_applications WHERE id=$1", [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: "Application not found" });
    const bytes = await fetchPrivateVerificationObject(result.rows[0].bank_statement_path);
    const isPdf = result.rows[0].bank_statement_path.endsWith(".pdf");
    logAdminAction(req.user.id, "verified_seller_bank_statement_viewed", `Viewed bank statement for ${result.rows[0].reference}`);
    res.setHeader("Content-Type", isPdf ? "application/pdf" : "image/jpeg");
    res.setHeader("Content-Disposition", `inline; filename="${result.rows[0].reference}-bank-statement.${isPdf ? "pdf" : "jpg"}"`);
    res.setHeader("Cache-Control", "private, no-store");
    res.send(bytes);
  } catch (err) { sendInternalError(res, err); }
});

app.get("/admin/verified-seller-applications/:id/identification/:side", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const column = req.params.side === "front" ? "id_front_path" : req.params.side === "back" ? "id_back_path" : null;
    if (!column) return res.status(400).json({ error: "Invalid identification side" });
    const result = await pool.query(`SELECT reference,${column} AS document_path FROM verified_seller_applications WHERE id=$1`, [req.params.id]);
    if (!result.rows.length || !result.rows[0].document_path) return res.status(404).json({ error: "Identification image not found" });
    const bytes = await fetchPrivateVerificationObject(result.rows[0].document_path);
    logAdminAction(req.user.id, "verified_seller_identification_viewed", `Viewed ${req.params.side} identification for ${result.rows[0].reference}`);
    res.setHeader("Content-Type", "image/jpeg");
    res.setHeader("Content-Disposition", `inline; filename="${result.rows[0].reference}-id-${req.params.side}.jpg"`);
    res.setHeader("Cache-Control", "private, no-store");
    res.send(bytes);
  } catch (err) { sendInternalError(res, err); }
});

function jpegDimensions(buffer) {
  let offset = 2;
  while (offset + 9 < buffer.length) {
    if (buffer[offset] !== 0xff) { offset++; continue; }
    const marker = buffer[offset + 1];
    const length = buffer.readUInt16BE(offset + 2);
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      return { height: buffer.readUInt16BE(offset + 5), width: buffer.readUInt16BE(offset + 7) };
    }
    if (!length || length < 2) break;
    offset += 2 + length;
  }
  throw new Error("Invalid JPEG dimensions");
}

function pdfText(value) {
  return String(value ?? "").replace(/[^\x20-\x7E]/g, "?").replace(/([\\()])/g, "\\$1");
}

const PDF_PASSWORD_PADDING = Buffer.from([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
]);

function rc4(key, input) {
  const state = Array.from({ length: 256 }, (_, index) => index);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + state[i] + key[i % key.length]) & 255;
    [state[i], state[j]] = [state[j], state[i]];
  }
  const output = Buffer.alloc(input.length);
  let i = 0;
  j = 0;
  for (let offset = 0; offset < input.length; offset++) {
    i = (i + 1) & 255;
    j = (j + state[i]) & 255;
    [state[i], state[j]] = [state[j], state[i]];
    output[offset] = input[offset] ^ state[(state[i] + state[j]) & 255];
  }
  return output;
}

function padPdfPassword(password) {
  const bytes = Buffer.from(String(password || ""), "latin1").subarray(0, 32);
  return Buffer.concat([bytes, PDF_PASSWORD_PADDING]).subarray(0, 32);
}

function encryptPdfStreamObject(object, objectId, fileKey) {
  const streamMarker = Buffer.from("stream\n");
  const streamAt = object.indexOf(streamMarker);
  if (streamAt < 0) return object;
  const prefixEnd = streamAt + streamMarker.length;
  const lengthMatch = object.subarray(0, streamAt).toString().match(/\/Length\s+(\d+)/);
  if (!lengthMatch) return object;
  const streamLength = Number(lengthMatch[1]);
  const streamEnd = prefixEnd + streamLength;
  if (!Number.isSafeInteger(streamLength) || streamEnd > object.length) throw new Error("Invalid PDF stream length");
  const suffix = Buffer.alloc(5);
  suffix[0] = objectId & 255;
  suffix[1] = (objectId >> 8) & 255;
  suffix[2] = (objectId >> 16) & 255;
  const objectKey = crypto.createHash("md5").update(Buffer.concat([fileKey, suffix])).digest().subarray(0, Math.min(fileKey.length + 5, 16));
  return Buffer.concat([object.subarray(0, prefixEnd), rc4(objectKey, object.subarray(prefixEnd, streamEnd)), object.subarray(streamEnd)]);
}

function assemblePdf(objects, rootId, userPassword = "") {
  let encryptId = null;
  let fileId = null;
  if (userPassword) {
    fileId = crypto.randomBytes(16);
    const userPad = padPdfPassword(userPassword);
    const ownerKey = crypto.createHash("md5").update(padPdfPassword(crypto.randomBytes(24).toString("base64url"))).digest().subarray(0, 5);
    const ownerEntry = rc4(ownerKey, userPad);
    const permissions = Buffer.alloc(4);
    permissions.writeInt32LE(-64, 0);
    const fileKey = crypto.createHash("md5").update(Buffer.concat([userPad, ownerEntry, permissions, fileId])).digest().subarray(0, 5);
    const userEntry = rc4(fileKey, PDF_PASSWORD_PADDING);
    objects.push(Buffer.from(`<< /Filter /Standard /V 1 /R 2 /Length 40 /O <${ownerEntry.toString("hex")}> /U <${userEntry.toString("hex")}> /P -64 >>`));
    encryptId = objects.length - 1;
    for (let id = 1; id < objects.length; id++) {
      if (id !== encryptId) objects[id] = encryptPdfStreamObject(objects[id], id, fileKey);
    }
  }
  const chunks = [Buffer.from("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n", "binary")];
  const offsets = [0];
  let position = chunks[0].length;
  for (let id = 1; id < objects.length; id++) {
    offsets[id] = position;
    const prefix = Buffer.from(`${id} 0 obj\n`);
    const suffix = Buffer.from("\nendobj\n");
    chunks.push(prefix, objects[id], suffix);
    position += prefix.length + objects[id].length + suffix.length;
  }
  const xrefOffset = position;
  let xref = `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id++) xref += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
  const securityTrailer = encryptId ? ` /Encrypt ${encryptId} 0 R /ID [<${fileId.toString("hex")}><${fileId.toString("hex")}>]` : "";
  xref += `trailer\n<< /Size ${objects.length} /Root ${rootId} 0 R${securityTrailer} >>\nstartxref\n${xrefOffset}\n%%EOF`;
  chunks.push(Buffer.from(xref));
  return Buffer.concat(chunks);
}

async function buildCasualSellerReportPdf(applications, reportDate, reportPassword) {
  const objects = [null];
  const addObject = (value) => { objects.push(Buffer.isBuffer(value) ? value : Buffer.from(value)); return objects.length - 1; };
  const fontId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const pagesId = addObject("");
  const catalogId = addObject(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);
  const pageIds = [];
  for (const application of applications) {
    const paths = application.evidence_paths || {};
    const slots = [
      ["live_selfie", "Live selfie"], ["holding_id_selfie", "Selfie holding ID"],
      ["id_front", "ID front"], ["id_back", "ID back"],
    ].filter(([key]) => paths[key]);
    const imageObjects = [];
    for (const [key, label] of slots) {
      const bytes = await fetchPrivateVerificationObject(paths[key]);
      const dimensions = jpegDimensions(bytes);
      const header = Buffer.from(`<< /Type /XObject /Subtype /Image /Width ${dimensions.width} /Height ${dimensions.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${bytes.length} >>\nstream\n`);
      const imageId = addObject(Buffer.concat([header, bytes, Buffer.from("\nendstream")]));
      imageObjects.push({ imageId, label, ...dimensions });
    }
    let content = "BT /F1 15 Tf 40 808 Td (Stallyard Casual Seller Verification) Tj ET\n";
    const lines = [
      `Daily report: ${reportDate}`,
      `Application: ${application.reference}`,
      `Applicant: ${application.legal_name} (@${application.username})`,
      `Email: ${application.email || "not provided"}   Phone: ${application.phone || "not provided"}`,
      `Identity document: shown in holding-ID selfie; full document details required for Verified Seller upgrade`,
      `Date of birth: ${String(application.date_of_birth).slice(0, 10)}   Approved: ${new Date(application.approved_at).toISOString()}`,
      `Checks: ${Object.entries(application.automatic_checks || {}).map(([key, value]) => `${key}=${value ? "pass" : "fail"}`).join(", ")}`,
    ];
    lines.forEach((line, index) => { content += `BT /F1 ${index === 6 ? 7 : 9} Tf 40 ${786 - index * 14} Td (${pdfText(line).slice(0, 145)}) Tj ET\n`; });
    const placements = [[40, 410], [308, 410], [40, 105], [308, 105]];
    imageObjects.forEach((image, index) => {
      const [x, y] = placements[index];
      const maxW = 247, maxH = 270;
      const scale = Math.min(maxW / image.width, maxH / image.height);
      const width = Math.max(1, image.width * scale), height = Math.max(1, image.height * scale);
      content += `BT /F1 9 Tf ${x} ${y + 278} Td (${pdfText(image.label)}) Tj ET\nq ${width.toFixed(2)} 0 0 ${height.toFixed(2)} ${x} ${y} cm /Im${index + 1} Do Q\n`;
    });
    const contentBuffer = Buffer.from(content);
    const contentId = addObject(Buffer.concat([Buffer.from(`<< /Length ${contentBuffer.length} >>\nstream\n`), contentBuffer, Buffer.from("endstream")]));
    const xObjects = imageObjects.map((image, index) => `/Im${index + 1} ${image.imageId} 0 R`).join(" ");
    const pageId = addObject(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 ${fontId} 0 R >> /XObject << ${xObjects} >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  }
  objects[pagesId] = Buffer.from(`<< /Type /Pages /Count ${pageIds.length} /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] >>`);
  return assemblePdf(objects, catalogId, reportPassword);
}

async function buildVerifiedSellerReportPdf(applications, reportDate, reportPassword) {
  const objects = [null];
  const addObject = (value) => { objects.push(Buffer.isBuffer(value) ? value : Buffer.from(value)); return objects.length - 1; };
  const fontId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const pagesId = addObject("");
  const catalogId = addObject(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);
  const pageIds = [];
  for (const application of applications) {
    const documentSlots = [
      [application.id_front_path, "Identification front"],
      [application.id_back_path, "Identification back"],
      [application.bank_statement_path?.toLowerCase().endsWith(".jpg") ? application.bank_statement_path : null, "Bank statement"],
    ].filter(([path]) => path);
    const imageObjects = [];
    for (const [path, label] of documentSlots) {
      const bytes = await fetchPrivateVerificationObject(path);
      const dimensions = jpegDimensions(bytes);
      const header = Buffer.from(`<< /Type /XObject /Subtype /Image /Width ${dimensions.width} /Height ${dimensions.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${bytes.length} >>\nstream\n`);
      const imageId = addObject(Buffer.concat([header, bytes, Buffer.from("\nendstream")]));
      imageObjects.push({ imageId, label, ...dimensions });
    }
    const fullName = [application.last_name, application.first_name, application.other_name].filter(Boolean).join(" ") || application.display_name || application.username;
    const approvalMethod = String(application.decision_reason || "Manual administrative approval");
    const lines = [
      `Daily report: ${reportDate}`,
      `Application: ${application.reference}`,
      `Seller: ${fullName} (@${application.username})`,
      `Email: ${application.email || "not provided"}   Phone: ${application.phone || "not provided"}`,
      `Nationality: ${application.nationality || "not provided"}   State: ${application.state_of_residence || application.address_state || "not provided"}`,
      `Identification: ${application.id_type || "not provided"}`,
      `Payout account: ${application.bank_account_name || "verified account on file"}`,
      `Address: ${[application.address_street, application.address_city, application.address_state].filter(Boolean).join(", ")}`,
      `Seller level: Verified Seller   Combined active-listing limit: NGN 10,000,000`,
      `Approved: ${application.reviewed_at ? new Date(application.reviewed_at).toISOString() : "not recorded"}`,
      `Approval method: ${approvalMethod}`,
      `Reviewed by: ${application.reviewer_name || application.reviewer_username || "authorized administrator"}`,
      application.bank_statement_path?.toLowerCase().endsWith(".pdf")
        ? "Bank statement: original PDF retained securely in the Verified Seller application record"
        : "Bank statement: image reproduced below and original retained securely",
    ];
    let content = "BT /F1 15 Tf 40 812 Td (Stallyard Verified Seller Approval) Tj ET\n";
    lines.forEach((line, index) => { content += `BT /F1 ${index >= 7 ? 7 : 8} Tf 40 ${791 - index * 13} Td (${pdfText(line).slice(0, 150)}) Tj ET\n`; });
    const placements = [[40, 385], [308, 385], [40, 85]];
    imageObjects.forEach((image, index) => {
      const [x, y] = placements[index];
      const maxW = 247, maxH = index === 2 ? 250 : 270;
      const scale = Math.min(maxW / image.width, maxH / image.height);
      const width = Math.max(1, image.width * scale), height = Math.max(1, image.height * scale);
      content += `BT /F1 9 Tf ${x} ${y + maxH + 8} Td (${pdfText(image.label)}) Tj ET\nq ${width.toFixed(2)} 0 0 ${height.toFixed(2)} ${x} ${y} cm /Im${index + 1} Do Q\n`;
    });
    const contentBuffer = Buffer.from(content);
    const contentId = addObject(Buffer.concat([Buffer.from(`<< /Length ${contentBuffer.length} >>\nstream\n`), contentBuffer, Buffer.from("endstream")]));
    const xObjects = imageObjects.map((image, index) => `/Im${index + 1} ${image.imageId} 0 R`).join(" ");
    const pageId = addObject(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 ${fontId} 0 R >> /XObject << ${xObjects} >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  }
  objects[pagesId] = Buffer.from(`<< /Type /Pages /Count ${pageIds.length} /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] >>`);
  return assemblePdf(objects, catalogId, reportPassword);
}

function lagosDateParts(now = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Lagos", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23" })
    .formatToParts(now).reduce((out, part) => ({ ...out, [part.type]: part.value }), {});
  return { date: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour) };
}

async function sendDailyCasualSellerReport(force = false) {
  const { date, hour } = lagosDateParts();
  if (!force && hour < 8) return { skipped: true, reason: "before_schedule" };
  const lockClient = await pool.connect();
  try {
    const locked = await lockClient.query("SELECT pg_try_advisory_lock($1) AS locked", [830500001]);
    if (!locked.rows[0]?.locked) return { skipped: true, reason: "already_running" };
    const existing = await lockClient.query("SELECT id, email_status FROM casual_seller_daily_reports WHERE report_date = $1", [date]);
    if (existing.rows[0]?.email_status === "sent") return { skipped: true, reason: "already_sent" };
    const applicationsResult = await lockClient.query(
      `SELECT a.*, u.username, u.email, u.phone
         FROM casual_seller_applications a JOIN users u ON u.id = a.user_id
        WHERE a.status = 'approved' AND a.included_in_report_id IS NULL
        ORDER BY a.approved_at, a.id`
    );
    if (!applicationsResult.rows.length) return { skipped: true, reason: "no_applications" };
    const recipientsResult = await lockClient.query(
      `SELECT email FROM users WHERE is_admin = true AND COALESCE(admin_role, 'super_admin') = 'super_admin'
         AND is_suspended = false AND email IS NOT NULL AND email <> ''`
    );
    const recipients = [...new Set(recipientsResult.rows.map((row) => row.email.toLowerCase()))];
    if (!recipients.length) throw new Error("No active super-admin email address is configured");
    const reportRow = await lockClient.query(
      `INSERT INTO casual_seller_daily_reports(report_date, application_count, email_recipients)
       VALUES ($1,$2,$3) ON CONFLICT(report_date) DO UPDATE SET application_count = EXCLUDED.application_count,
       email_recipients = EXCLUDED.email_recipients, email_status = 'pending', email_error = NULL RETURNING id`,
      [date, applicationsResult.rows.length, JSON.stringify(recipients)]
    );
    const reportId = reportRow.rows[0].id;
    const reportPassword = `STY-${crypto.randomBytes(9).toString("base64url")}`;
    const pdf = await buildCasualSellerReportPdf(applicationsResult.rows, date, reportPassword);
    const pdfHash = crypto.createHash("sha256").update(pdf).digest("hex");
    const pdfPath = `daily-reports/${date}/casual-seller-approved-${reportId}-${pdfHash.slice(0, 12)}-${crypto.randomBytes(4).toString("hex")}.pdf`;
    await uploadPrivateVerificationObject(pdfPath, pdf, "application/pdf");
    await lockClient.query("UPDATE casual_seller_daily_reports SET pdf_storage_path=$1, pdf_sha256=$2, password_encrypted=$3 WHERE id=$4", [pdfPath, pdfHash, encryptField(reportPassword), reportId]);
    if (!process.env.RESEND_API_KEY) throw new Error("RESEND_API_KEY is not configured");
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const emailResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress, to: recipients,
        subject: `Stallyard approved casual sellers — ${date}`,
        html: `<p>Attached is the password-protected daily record of ${applicationsResult.rows.length} automatically approved casual-seller application(s).</p><p>The password is not included in this email. An authorized Super Admin must retrieve it from the Stallyard admin dashboard.</p><p>This document contains sensitive identity information. Do not forward it.</p>`,
        attachments: [{ filename: `stallyard-casual-sellers-${date}.pdf`, content: pdf.toString("base64") }],
      }),
    });
    if (!emailResponse.ok) throw new Error(`Daily report email failed (${emailResponse.status})`);
    await lockClient.query("BEGIN");
    await lockClient.query("UPDATE casual_seller_daily_reports SET email_status='sent', emailed_at=NOW(), email_error=NULL WHERE id=$1", [reportId]);
    await lockClient.query("UPDATE casual_seller_applications SET included_in_report_id=$1 WHERE id = ANY($2::bigint[])", [reportId, applicationsResult.rows.map((row) => row.id)]);
    await lockClient.query("COMMIT");
    return { sent: true, reportId, applicationCount: applicationsResult.rows.length };
  } catch (err) {
    await lockClient.query("ROLLBACK").catch(() => {});
    console.error("Daily casual-seller report failed:", err.message);
    await lockClient.query(
      `UPDATE casual_seller_daily_reports SET email_status='failed', email_error=$1
        WHERE report_date=$2`, [String(err.message).slice(0, 500), date]
    ).catch(() => {});
    return { sent: false, error: err.message };
  } finally {
    await lockClient.query("SELECT pg_advisory_unlock($1)", [830500001]).catch(() => {});
    lockClient.release();
  }
}

async function sendDailyVerifiedSellerReport(force = false) {
  const { date, hour } = lagosDateParts();
  if (!force && hour < 8) return { skipped: true, reason: "before_schedule" };
  const lockClient = await pool.connect();
  try {
    const locked = await lockClient.query("SELECT pg_try_advisory_lock($1) AS locked", [830500002]);
    if (!locked.rows[0]?.locked) return { skipped: true, reason: "already_running" };
    const existing = await lockClient.query("SELECT id, email_status FROM verified_seller_daily_reports WHERE report_date = $1", [date]);
    if (existing.rows[0]?.email_status === "sent") return { skipped: true, reason: "already_sent" };
    const applicationsResult = await lockClient.query(
      `SELECT a.*, u.username, u.display_name, u.email, u.phone, u.first_name, u.last_name, u.other_name,
              u.nationality, u.state_of_residence, u.bank_account_name,
              addr.street AS address_street, addr.city AS address_city, addr.state AS address_state,
              reviewer.username AS reviewer_username, reviewer.display_name AS reviewer_name
         FROM verified_seller_applications a
         JOIN users u ON u.id = a.user_id
         LEFT JOIN user_addresses addr ON addr.id = a.address_id
         LEFT JOIN users reviewer ON reviewer.id = a.reviewed_by
        WHERE a.status = 'approved' AND a.included_in_report_id IS NULL
        ORDER BY a.reviewed_at, a.id`
    );
    if (!applicationsResult.rows.length) return { skipped: true, reason: "no_applications" };
    const recipientsResult = await lockClient.query(
      `SELECT email FROM users WHERE is_admin = true AND COALESCE(admin_role, 'super_admin') = 'super_admin'
         AND is_suspended = false AND email IS NOT NULL AND email <> ''`
    );
    const recipients = [...new Set(recipientsResult.rows.map((row) => row.email.toLowerCase()))];
    if (!recipients.length) throw new Error("No active super-admin email address is configured");
    const reportRow = await lockClient.query(
      `INSERT INTO verified_seller_daily_reports(report_date, application_count, email_recipients)
       VALUES ($1,$2,$3) ON CONFLICT(report_date) DO UPDATE SET application_count = EXCLUDED.application_count,
       email_recipients = EXCLUDED.email_recipients, email_status = 'pending', email_error = NULL RETURNING id`,
      [date, applicationsResult.rows.length, JSON.stringify(recipients)]
    );
    const reportId = reportRow.rows[0].id;
    const reportPassword = `STY-${crypto.randomBytes(9).toString("base64url")}`;
    const pdf = await buildVerifiedSellerReportPdf(applicationsResult.rows, date, reportPassword);
    const pdfHash = crypto.createHash("sha256").update(pdf).digest("hex");
    const pdfPath = `daily-reports/${date}/verified-seller-approved-${reportId}-${pdfHash.slice(0, 12)}-${crypto.randomBytes(4).toString("hex")}.pdf`;
    await uploadPrivateVerificationObject(pdfPath, pdf, "application/pdf");
    await lockClient.query("UPDATE verified_seller_daily_reports SET pdf_storage_path=$1, pdf_sha256=$2, password_encrypted=$3 WHERE id=$4", [pdfPath, pdfHash, encryptField(reportPassword), reportId]);
    if (!process.env.RESEND_API_KEY) throw new Error("RESEND_API_KEY is not configured");
    const fromAddress = process.env.RESEND_FROM_EMAIL || "Stallyard <onboarding@resend.dev>";
    const emailResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: fromAddress,
        to: recipients,
        subject: `Stallyard approved Verified Sellers — ${date}`,
        html: `<p>Attached is the password-protected daily approval record for ${applicationsResult.rows.length} Verified Seller application(s).</p><p>The password is not included in this email. An authorized Super Admin must retrieve it from the Stallyard admin dashboard.</p><p>This document contains sensitive identity and financial information. It is for Super Admin access only and must not be forwarded.</p>`,
        attachments: [{ filename: `stallyard-verified-sellers-${date}.pdf`, content: pdf.toString("base64") }],
      }),
    });
    if (!emailResponse.ok) throw new Error(`Verified Seller report email failed (${emailResponse.status})`);
    await lockClient.query("BEGIN");
    await lockClient.query("UPDATE verified_seller_daily_reports SET email_status='sent', emailed_at=NOW(), email_error=NULL WHERE id=$1", [reportId]);
    await lockClient.query("UPDATE verified_seller_applications SET included_in_report_id=$1 WHERE id = ANY($2::bigint[])", [reportId, applicationsResult.rows.map((row) => row.id)]);
    await lockClient.query("COMMIT");
    return { sent: true, reportId, applicationCount: applicationsResult.rows.length };
  } catch (err) {
    await lockClient.query("ROLLBACK").catch(() => {});
    console.error("Daily Verified Seller report failed:", err.message);
    await lockClient.query(
      `UPDATE verified_seller_daily_reports SET email_status='failed', email_error=$1 WHERE report_date=$2`,
      [String(err.message).slice(0, 500), date]
    ).catch(() => {});
    return { sent: false, error: err.message };
  } finally {
    await lockClient.query("SELECT pg_advisory_unlock($1)", [830500002]).catch(() => {});
    lockClient.release();
  }
}

app.get("/admin/casual-seller-applications", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.reference, a.user_id, a.legal_name, a.date_of_birth, a.id_type, a.id_number_last4,
              a.id_expiration, a.status, a.decision_reason, a.automatic_checks, a.liveness_challenges,
              a.approved_at, a.suspended_at, a.created_at, u.username, u.email, u.phone,
              ARRAY(SELECT jsonb_object_keys(a.evidence_paths)) AS evidence_keys
         FROM casual_seller_applications a JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 500`
    );
    res.json({ applications: result.rows });
  } catch (err) { sendInternalError(res, err); }
});

app.get("/admin/casual-seller-applications/:id/evidence/:key", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const allowed = new Set(["live_selfie", "holding_id_selfie", "id_front", "id_back", "challenge_1", "challenge_2", "challenge_3"]);
    if (!allowed.has(req.params.key)) return res.status(400).json({ error: "Invalid evidence type" });
    const result = await pool.query("SELECT evidence_paths ->> $1 AS path FROM casual_seller_applications WHERE id=$2", [req.params.key, req.params.id]);
    if (!result.rows[0]?.path) return res.status(404).json({ error: "Evidence not found" });
    const bytes = await fetchPrivateVerificationObject(result.rows[0].path);
    await pool.query("INSERT INTO casual_seller_access_log(application_id,admin_id,action) VALUES($1,$2,$3)", [req.params.id, req.user.id, `viewed_${req.params.key}`]);
    res.setHeader("Content-Type", "image/jpeg");
    res.setHeader("Cache-Control", "private, no-store");
    res.send(bytes);
  } catch (err) { sendInternalError(res, err); }
});

app.patch("/admin/casual-seller-applications/:id/suspend", authenticate, requireSuperAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const application = await client.query("SELECT user_id, reference FROM casual_seller_applications WHERE id=$1 FOR UPDATE", [req.params.id]);
    if (!application.rows.length) throw Object.assign(new Error("Application not found"), { statusCode: 404 });
    await client.query("UPDATE casual_seller_applications SET status='suspended', suspended_at=NOW(), decision_reason=$1, updated_at=NOW() WHERE id=$2", [String(req.body?.reason || "Suspended after verification review").slice(0, 500), req.params.id]);
    await client.query("UPDATE users SET casual_seller_status='suspended', casual_seller_suspended_at=NOW() WHERE id=$1", [application.rows[0].user_id]);
    await client.query("UPDATE listings SET status='paused' WHERE owner_id=$1 AND status='active'", [application.rows[0].user_id]);
    await client.query("COMMIT");
    logAdminAction(req.user.id, "casual_seller_suspended", `Suspended casual seller application ${application.rows[0].reference}`);
    createNotification(application.rows[0].user_id, "verification_problem", "Your casual-seller verification was suspended. Your active listings have been paused.");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.statusCode) return res.status(err.statusCode).json({ error: err.message });
    sendInternalError(res, err);
  } finally { client.release(); }
});

app.get("/admin/casual-seller-reports", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, report_date, application_count, email_status, emailed_at, created_at FROM casual_seller_daily_reports ORDER BY report_date DESC LIMIT 365");
    res.json({ reports: result.rows });
  } catch (err) { sendInternalError(res, err); }
});

app.get("/admin/casual-seller-reports/:id/download", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT report_date,pdf_storage_path FROM casual_seller_daily_reports WHERE id=$1", [req.params.id]);
    if (!result.rows[0]?.pdf_storage_path) return res.status(404).json({ error: "Report file not found" });
    const pdf = await fetchPrivateVerificationObject(result.rows[0].pdf_storage_path);
    await pool.query("INSERT INTO casual_seller_access_log(report_id,admin_id,action) VALUES($1,$2,'downloaded_pdf')", [req.params.id, req.user.id]);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="stallyard-casual-sellers-${result.rows[0].report_date}.pdf"`);
    res.setHeader("Cache-Control", "private, no-store");
    res.send(pdf);
  } catch (err) { sendInternalError(res, err); }
});

app.get("/admin/casual-seller-reports/:id/password", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT password_encrypted FROM casual_seller_daily_reports WHERE id=$1", [req.params.id]);
    if (!result.rows[0]?.password_encrypted) return res.status(404).json({ error: "Report password not found" });
    const password = decryptFieldSafe(result.rows[0].password_encrypted);
    await pool.query("INSERT INTO casual_seller_access_log(report_id,admin_id,action) VALUES($1,$2,'revealed_password')", [req.params.id, req.user.id]);
    res.setHeader("Cache-Control", "private, no-store");
    res.json({ password });
  } catch (err) { sendInternalError(res, err); }
});

app.post("/admin/casual-seller-reports/run", authenticate, requireSuperAdmin, async (req, res) => {
  const result = await sendDailyCasualSellerReport(true);
  if (result.error) return res.status(502).json({ error: "The report could not be completed", details: result.error });
  res.json(result);
});

app.get("/admin/verified-seller-reports", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, report_date, application_count, email_status, emailed_at, created_at FROM verified_seller_daily_reports ORDER BY report_date DESC LIMIT 365"
    );
    res.json({ reports: result.rows });
  } catch (err) { sendInternalError(res, err); }
});

app.get("/admin/verified-seller-reports/:id/download", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT report_date,pdf_storage_path FROM verified_seller_daily_reports WHERE id=$1", [req.params.id]);
    if (!result.rows[0]?.pdf_storage_path) return res.status(404).json({ error: "Report file not found" });
    const pdf = await fetchPrivateVerificationObject(result.rows[0].pdf_storage_path);
    await pool.query("INSERT INTO verified_seller_report_access_log(report_id,admin_id,action) VALUES($1,$2,'downloaded_pdf')", [req.params.id, req.user.id]);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="stallyard-verified-sellers-${result.rows[0].report_date}.pdf"`);
    res.setHeader("Cache-Control", "private, no-store");
    res.send(pdf);
  } catch (err) { sendInternalError(res, err); }
});

app.get("/admin/verified-seller-reports/:id/password", authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT password_encrypted FROM verified_seller_daily_reports WHERE id=$1", [req.params.id]);
    if (!result.rows[0]?.password_encrypted) return res.status(404).json({ error: "Report password not found" });
    const password = decryptFieldSafe(result.rows[0].password_encrypted);
    await pool.query("INSERT INTO verified_seller_report_access_log(report_id,admin_id,action) VALUES($1,$2,'revealed_password')", [req.params.id, req.user.id]);
    res.setHeader("Cache-Control", "private, no-store");
    res.json({ password });
  } catch (err) { sendInternalError(res, err); }
});

app.post("/admin/verified-seller-reports/run", authenticate, requireSuperAdmin, async (req, res) => {
  const result = await sendDailyVerifiedSellerReport(true);
  if (result.error) return res.status(502).json({ error: "The Verified Seller report could not be completed", details: result.error });
  res.json(result);
});

app.post("/listings", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      title, description, price, category, subcategory, condition, shippingFee,
      emoji, fitMake, fitModel, fitYear, images, listingType, currency,
      status, auctionEndTime, quantity, sku, brand, state, shippingMethods,
      returnPolicy, vin,
    } = req.body;
    const ownerId = req.user.id; // always the signed-in user — never trust a client-supplied owner

    if (!title) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (status !== "draft" && !price) {
      return res.status(400).json({ error: "Give it a price before publishing" });
    }

    // "active" is the one canonical live listing status across browse, checkout, and moderation.
    // Approved sellers may create a draft or publish live; legacy client value "approved" is treated as live.
    const listingStatus = status === "draft" ? "draft" : "active";
    const allowedSubcategories = LISTING_SUBCATEGORIES[category || "Other"] || [];
    if (listingStatus !== "draft" && (!subcategory || !allowedSubcategories.includes(subcategory))) {
      return res.status(400).json({ error: "Choose a valid subcategory for this category." });
    }

    await client.query("BEGIN");
    const seller = listingStatus === "active"
      ? await assertSellerMayPublish(client, ownerId, price, quantity)
      : (await client.query("SELECT username, display_name FROM users WHERE id = $1", [ownerId])).rows[0];
    const result = await client.query(
      `INSERT INTO listings (
         owner_id, title, description, price, category, subcategory, condition, shipping_fee,
         emoji, fit_make, fit_model, fit_year, images, listing_type, currency,
         status, auction_end_time, quantity, sku, brand, state, shipping_methods,
         return_policy, vin
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
       RETURNING *`,
      [
        ownerId, title, description || "", price, category || "Other", subcategory || "", condition || "New", shippingFee || 0,
        emoji || "📦", fitMake || "", fitModel || "", fitYear || "", JSON.stringify(images || []),
        listingType || "fixed", "NGN", listingStatus,
        auctionEndTime ? new Date(auctionEndTime) : null,
        quantity === "" || quantity === undefined || quantity === null ? null : Number(quantity),
        sku || "", brand || "", state || "", JSON.stringify(shippingMethods || []),
        returnPolicy || "", vin || "",
      ]
    );

    const listingWithOwner = {
      ...result.rows[0],
      owner_username: seller.username,
      seller_name: seller.display_name,
    };

    await client.query("COMMIT");
    res.status(201).json({ listing: listingWithOwner });
    moderateListingImagesAsync(result.rows[0].id, images);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.statusCode) return res.status(err.statusCode).json({ error: err.message, code: err.code, currentActiveValue: err.currentActiveValue, limit: err.limit });
    sendInternalError(res, err);
  } finally { client.release(); }
});

function publicListingRow(row) {
  const hidden = Array.isArray(row.hidden_image_urls) ? row.hidden_image_urls : [];
  const images = (Array.isArray(row.images) ? row.images : []).filter((url) => !hidden.includes(url));
  return {
    id: row.id,
    owner_id: row.owner_id,
    title: row.title,
    description: row.description,
    price: row.price,
    category: row.category,
    subcategory: row.subcategory || "",
    condition: row.condition,
    shipping_fee: row.shipping_fee,
    emoji: row.emoji,
    fit_make: row.fit_make,
    fit_model: row.fit_model,
    fit_year: row.fit_year,
    images,
    listing_type: row.listing_type,
    currency: row.currency,
    status: row.status,
    is_featured: row.is_featured,
    auction_end_time: row.auction_end_time,
    highest_bidder_username: null,
    quantity: row.quantity,
    sku: row.sku,
    brand: row.brand,
    state: row.state,
    shipping_methods: row.shipping_methods,
    return_policy: row.return_policy,
    vin: row.vin,
    seller_name: row.seller_name,
    owner_username: row.owner_username,
    created_at: row.created_at,
  };
}

// Public listing discovery is enforced here on the server. Anonymous callers
// only receive active listings belonging to approved, unsuspended sellers.
// A signed-in marketplace user additionally receives their own listings in all
// statuses so drafts/pending items still appear in My Stall. Moderation-only
// fields are never exposed for somebody else's listing.
app.get("/listings", async (req, res) => {
  try {
    let validUserId = null;
    const requester = getRequester(req);
    if (requester) {
      const session = await pool.query(
        `SELECT id, is_suspended, token_version
         FROM users WHERE id = $1`,
        [requester.id]
      );
      if (session.rows.length && !session.rows[0].is_suspended) {
        const currentVersion = session.rows[0].token_version || 0;
        if ((requester.tokenVersion || 0) === currentVersion) validUserId = session.rows[0].id;
      }
    }

    const result = await pool.query(
      `SELECT listings.*, users.display_name AS seller_name, users.username AS owner_username,
              users.is_approved AS seller_is_approved, users.is_suspended AS seller_is_suspended
       FROM listings
       JOIN users ON listings.owner_id = users.id
       WHERE (
         listings.status = 'active'
         AND users.is_approved = true
         AND users.is_suspended = false
       )
       OR ($1::integer IS NOT NULL AND listings.owner_id = $1)
       ORDER BY listings.created_at DESC`,
      [validUserId]
    );

    const rows = result.rows.map((row) => {
      if (validUserId && row.owner_id === validUserId) {
        const { seller_is_approved, seller_is_suspended, ...ownRow } = row;
        return ownRow;
      }
      return publicListingRow(row);
    });
    res.json({ listings: rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

// Staff moderation gets a separate protected endpoint. This keeps drafts,
// rejected/removed listings and moderation metadata out of the public API.
app.get("/admin/listings", authenticate, requirePermission("listing_moderation"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT listings.*, users.display_name AS seller_name, users.username AS owner_username
       FROM listings
       JOIN users ON listings.owner_id = users.id
       ORDER BY listings.created_at DESC`
    );
    res.json({ listings: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

const LISTING_FIELD_MAP = {
  title: "title",
  description: "description",
  price: "price",
  category: "category",
  subcategory: "subcategory",
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query("SELECT * FROM listings WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (existing.rows.length === 0) throw Object.assign(new Error("Listing not found"), { statusCode: 404 });
    if (existing.rows[0].owner_id !== req.user.id && !hasPermission(req.user, "listing_moderation")) {
      throw Object.assign(new Error("You can only edit your own listings"), { statusCode: 403 });
    }
    const sets = [];
    const values = [];
    const nextCategory = req.body.category ?? existing.rows[0].category;
    const nextSubcategory = req.body.subcategory ?? existing.rows[0].subcategory;
    if (Object.prototype.hasOwnProperty.call(req.body, "subcategory") || Object.prototype.hasOwnProperty.call(req.body, "category")) {
      const allowed = LISTING_SUBCATEGORIES[nextCategory] || [];
      if (nextSubcategory && !allowed.includes(nextSubcategory)) {
        throw Object.assign(new Error("Choose a valid subcategory for this category."), { statusCode: 400 });
      }
    }
    let i = 1;
    for (const [key, column] of Object.entries(LISTING_FIELD_MAP)) {
      if (!Object.prototype.hasOwnProperty.call(req.body, key)) continue;
      sets.push(`${column} = $${i}`);
      const raw = req.body[key];
      if (key === "quantity") {
        values.push(raw === "" || raw === undefined || raw === null ? null : Number(raw));
      } else if (key === "status") {
        const normalizedStatus = raw === "approved" ? "active" : raw;
        const allowedStatuses = new Set(["draft", "pending", "active", "paused", "sold", "rejected", "removed"]);
        if (!allowedStatuses.has(normalizedStatus)) throw Object.assign(new Error("Invalid listing status"), { statusCode: 400 });
        values.push(normalizedStatus);
      } else {
        values.push(LISTING_JSON_FIELDS.has(key) ? JSON.stringify(raw) : raw);
      }
      i++;
    }
    if (sets.length === 0) throw Object.assign(new Error("No valid fields to update"), { statusCode: 400 });
    const nextStatusRaw = Object.prototype.hasOwnProperty.call(req.body, "status") ? req.body.status : existing.rows[0].status;
    const nextStatus = nextStatusRaw === "approved" ? "active" : nextStatusRaw;
    if (existing.rows[0].owner_id === req.user.id && nextStatus === "active") {
      await assertSellerMayPublish(
        client, req.user.id,
        Object.prototype.hasOwnProperty.call(req.body, "price") ? req.body.price : existing.rows[0].price,
        Object.prototype.hasOwnProperty.call(req.body, "quantity") ? req.body.quantity : existing.rows[0].quantity,
        Number(req.params.id)
      );
    }
    values.push(req.params.id);
    const result = await client.query(`UPDATE listings SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`, values);
    await client.query("COMMIT");
    if (existing.rows[0].owner_id !== req.user.id) {
      logAdminAction(req.user.id, "listing_moderated", `Updated listing "${result.rows[0].title}" (${Object.keys(req.body).join(", ")})`);
    }
    if (req.body.status === "rejected") createNotification(existing.rows[0].owner_id, "listing_rejected", `Your listing "${result.rows[0].title}" was rejected`);
    res.json({ listing: result.rows[0] });
    if (Object.prototype.hasOwnProperty.call(req.body, "images")) moderateListingImagesAsync(result.rows[0].id, req.body.images);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.statusCode) return res.status(err.statusCode).json({ error: err.message, code: err.code, currentActiveValue: err.currentActiveValue, limit: err.limit });
    sendInternalError(res, err);
  } finally { client.release(); }
});

app.patch("/listings/:id/dismiss-flag", authenticate, async (req, res) => {
  try {
    if (!hasPermission(req.user, "listing_moderation")) {
      return res.status(403).json({ error: "You don't have permission to moderate listing images" });
    }
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "Missing image url" });
    const existing = await pool.query("SELECT flagged_images FROM listings WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Listing not found" });
    const remaining = (existing.rows[0].flagged_images || []).filter((f) => f.url !== url);
    const result = await pool.query(
      "UPDATE listings SET flagged_images = $1 WHERE id = $2 RETURNING *",
      [JSON.stringify(remaining), req.params.id]
    );
    logAdminAction(req.user.id, "listing_image_flag_dismissed", `Dismissed an image moderation flag on listing #${req.params.id}`);
    res.json({ listing: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/listings/:id/image-visibility", authenticate, async (req, res) => {
  try {
    if (!hasPermission(req.user, "listing_moderation")) {
      return res.status(403).json({ error: "You don't have permission to moderate listing images" });
    }
    const { url, hidden, reason } = req.body;
    if (!url) return res.status(400).json({ error: "Missing image url" });

    const existing = await pool.query("SELECT owner_id, title, images, hidden_image_urls FROM listings WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Listing not found" });
    const listing = existing.rows[0];
    if (!(listing.images || []).includes(url)) {
      return res.status(400).json({ error: "That photo doesn't belong to this listing" });
    }

    const currentHidden = listing.hidden_image_urls || [];
    const nextHidden = hidden
      ? [...new Set([...currentHidden, url])]
      : currentHidden.filter((u) => u !== url);

    const result = await pool.query(
      "UPDATE listings SET hidden_image_urls = $1 WHERE id = $2 RETURNING *",
      [JSON.stringify(nextHidden), req.params.id]
    );
    logAdminAction(
      req.user.id,
      "listing_image_visibility_changed",
      `${hidden ? "Hid" : "Unhid"} a photo on listing "${listing.title}"${reason ? ` — reason: ${reason}` : ""}`
    );
    if (hidden) {
      createNotification(
        listing.owner_id,
        "listing_image_hidden",
        `An admin hid a photo on your listing "${listing.title}"${reason ? `: ${reason}` : "."} Upload a replacement when you can.`
      );
    }
    res.json({ listing: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/listings/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT owner_id, title FROM listings WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Listing not found" });
    if (existing.rows[0].owner_id !== req.user.id && !hasPermission(req.user, "listing_moderation")) {
      return res.status(403).json({ error: "You can only remove your own listings" });
    }
    const result = await pool.query("DELETE FROM listings WHERE id = $1 RETURNING id", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Listing not found" });
    if (existing.rows[0].owner_id !== req.user.id) {
      logAdminAction(req.user.id, "listing_removed", `Removed listing "${existing.rows[0].title}"`);
    }
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/listings/by-owner/:ownerId", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const removed = await pool.query("DELETE FROM listings WHERE owner_id = $1 RETURNING id", [req.params.ownerId]);
    logAdminAction(req.user.id, "seller_listings_removed", `Removed ${removed.rowCount} listing${removed.rowCount === 1 ? "" : "s"} belonging to user #${req.params.ownerId}`);
    res.json({ success: true, removedCount: removed.rowCount });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/settings", async (req, res) => {
  try {
    const result = await pool.query("SELECT commission_rate, tax_rate, auth_image FROM site_settings WHERE id = 1");
    const row = result.rows[0] || { commission_rate: 0.05, tax_rate: 0, auth_image: "" };
    res.json({
      commissionRate: Number(row.commission_rate),
      taxRate: Number(row.tax_rate || 0),
      authImage: row.auth_image || "",
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/settings", authenticate, async (req, res) => {
  try {
    const { commissionRate, taxRate, authImage } = req.body;
    if (commissionRate !== undefined) {
      if (!hasPermission(req.user, "finance")) {
        return res.status(403).json({ error: "You don't have permission to change the commission rate" });
      }
      const rate = Number(commissionRate);
      if (!(rate >= 0 && rate <= 1)) {
        return res.status(400).json({ error: "Commission rate must be between 0 and 1 (e.g. 0.05 for 5%)" });
      }
      await pool.query(
        "INSERT INTO site_settings (id, commission_rate) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET commission_rate = $1",
        [rate]
      );
      logAdminAction(req.user.id, "commission_rate_changed", `Set commission rate to ${(rate * 100).toFixed(1)}%`);
    }
    if (taxRate !== undefined) {
      if (!hasPermission(req.user, "finance")) {
        return res.status(403).json({ error: "You don't have permission to change the tax rate" });
      }
      const rate = Number(taxRate);
      if (!(rate >= 0 && rate <= 1)) {
        return res.status(400).json({ error: "Tax rate must be between 0 and 1 (e.g. 0.075 for 7.5%)" });
      }
      await pool.query(
        "INSERT INTO site_settings (id, tax_rate) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET tax_rate = $1",
        [rate]
      );
      logAdminAction(req.user.id, "tax_rate_changed", `Set tax rate to ${(rate * 100).toFixed(2)}%`);
    }
    if (authImage !== undefined) {
      if (!hasPermission(req.user, "content_management")) {
        return res.status(403).json({ error: "You don't have permission to change site branding" });
      }
      await pool.query(
        "INSERT INTO site_settings (id, auth_image) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET auth_image = $1",
        [authImage]
      );
      logAdminAction(req.user.id, "site_branding_changed", "Updated the sign-in/site branding image");
    }
    const result = await pool.query("SELECT commission_rate, tax_rate, auth_image FROM site_settings WHERE id = 1");
    res.json({
      commissionRate: Number(result.rows[0].commission_rate),
      taxRate: Number(result.rows[0].tax_rate || 0),
      authImage: result.rows[0].auth_image || "",
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

async function getCommissionRate() {
  try {
    const result = await pool.query("SELECT commission_rate FROM site_settings WHERE id = 1");
    return result.rows.length ? Number(result.rows[0].commission_rate) : 0.05;
  } catch {
    return 0.05;
  }
}

async function getTaxRate() {
  try {
    const result = await pool.query("SELECT tax_rate FROM site_settings WHERE id = 1");
    return result.rows.length ? Number(result.rows[0].tax_rate || 0) : 0;
  } catch {
    return 0;
  }
}

function normalizePrivateShippingAddress(input) {
  const address = input && typeof input === "object" ? input : {};
  const locationPhotos = Array.isArray(address.locationPhotos)
    ? address.locationPhotos.filter((p) => typeof p === "string" && p.startsWith("data:image/") && p.length <= 1500000).slice(0, 5)
    : [];
  return {
    fullName: String(address.fullName || "").trim().slice(0, 160),
    phone: String(address.phone || "").trim().slice(0, 40),
    street: String(address.street || "").trim().slice(0, 300),
    city: String(address.city || "").trim().slice(0, 120),
    state: String(address.state || "").trim().slice(0, 120),
    zip: String(address.zip || "").trim().slice(0, 30),
    country: "Nigeria",
    deliveryInstructions: String(address.deliveryInstructions || "").trim().slice(0, 1000),
    preferredDeliveryTime: String(address.preferredDeliveryTime || "").trim().slice(0, 200),
    locationPhotos,
  };
}

function privateShippingAddressIsComplete(address) {
  return !!(address.fullName && address.phone && address.street && address.city && address.zip);
}

app.post("/checkout", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, (req, res) => {
  return res.status(410).json({
    error: "Legacy checkout is disabled. Use the protected Paystack checkout flow.",
    code: "LEGACY_CHECKOUT_DISABLED",
  });
});

app.post("/checkout/initialize", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, async (req, res) => {
  try {
    const { items, shippingAddress, currency, saveCard } = req.body;
    if (!isNigeriaCountry(shippingAddress?.country)) {
      return res.status(400).json({ error: "Delivery is available to Nigerian addresses only" });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Cart is empty" });
    }
    const normalizedShippingAddress = normalizePrivateShippingAddress(shippingAddress);
    if (!privateShippingAddressIsComplete(normalizedShippingAddress)) {
      return res.status(400).json({ error: "Recipient name, phone, street, city, and postal code are required" });
    }
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: "Payments aren't configured — contact support" });
    }

    let subtotal = 0;
    let shippingTotal = 0;
    const itemSnapshots = [];
    for (const cartItem of items) {
      const qty = Number(cartItem.qty);
      if (!cartItem.listingId || !Number.isInteger(qty) || qty <= 0) {
        return res.status(400).json({ error: "Each cart item needs a valid listingId and a positive quantity" });
      }
      const listingResult = await pool.query(
        "SELECT * FROM listings WHERE id = $1 AND status = 'active'",
        [cartItem.listingId]
      );
      if (listingResult.rows.length === 0) {
        return res.status(404).json({ error: `Listing ${cartItem.listingId} isn't available` });
      }
      const listing = listingResult.rows[0];
      const price = Number(listing.price);
      if (!(price > 0)) return res.status(400).json({ error: "Listing has an invalid price" });
      const shippingFee = Number(listing.shipping_fee) || 0;
      subtotal += price * qty;
      shippingTotal += shippingFee * qty;
      itemSnapshots.push({ listingId: listing.id, qty, unitPrice: price, shippingFee });
    }

    const commissionRate = await getCommissionRate();
    const taxRate = await getTaxRate();
    const taxAmount = Math.round(subtotal * taxRate * 100) / 100;
    const total = Math.round((subtotal + shippingTotal + taxAmount) * 100) / 100;

    const userResult = await pool.query("SELECT email FROM users WHERE id = $1", [req.user.id]);
    const email = userResult.rows[0]?.email;
    if (!email) return res.status(400).json({ error: "Add an email to your account before checking out" });

    const reference = generateCheckoutReference();
    const amountKobo = Math.round(total * 100);
    const reservationClient = await pool.connect();
    try {
      await reservationClient.query("BEGIN");
      await createCheckoutIntent({
        reference, buyerId: req.user.id, buyerUsername: req.user.username, buyerEmail: email,
        amountKobo, items: itemSnapshots, shippingAddress: normalizedShippingAddress, saveCard: !!saveCard,
      }, reservationClient);
      await reserveCheckoutListings(reservationClient, { buyerId: req.user.id, reference, items: itemSnapshots });
      await reservationClient.query("COMMIT");
    } catch (reservationErr) {
      await reservationClient.query("ROLLBACK");
      if (reservationErr.code === "LISTING_RESERVED") {
        return res.status(409).json({ error: reservationErr.message, code: "LISTING_RESERVED" });
      }
      if (reservationErr.code === "LISTING_UNAVAILABLE") {
        return res.status(409).json({ error: reservationErr.message, code: "LISTING_UNAVAILABLE" });
      }
      throw reservationErr;
    } finally {
      reservationClient.release();
    }

    const paystackRes = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        amount: amountKobo,
        currency: "NGN",
        reference,
        callback_url: "https://stallyard.com/order-confirmation",
        metadata: {
          buyerId: req.user.id,
          buyerUsername: req.user.username,
          items: items.map((i) => ({ listingId: i.listingId, qty: Number(i.qty) })),
          currency: "NGN",
          saveCard: !!saveCard,
        },
      }),
    });
    const paystackData = await paystackRes.json();
    if (!paystackData.status) {
      await markCheckoutIntent(reference, "failed", paystackData.message || "Paystack initialization failed");
      await releaseCheckoutReservations(reference);
      await recordPaymentAttempt(req.user.id, { reference, method: "checkout_initialize", status: "failed", amount: total, currency: "NGN", message: paystackData.message || "Paystack error" });
      return res.status(500).json({ error: paystackData.message || "Paystack error" });
    }
    if (String(paystackData.data?.reference || "") !== reference) {
      await markCheckoutIntent(reference, "failed", "Paystack returned a different reference");
      await releaseCheckoutReservations(reference);
      return res.status(502).json({ error: "Payment initialization integrity check failed — please try again" });
    }
    await recordPaymentAttempt(req.user.id, { reference, method: "checkout_initialize", status: "initialized", amount: total, currency: "NGN" });
    res.json({ authorizationUrl: paystackData.data.authorization_url, reference });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/checkout/verify/:reference", authenticate, async (req, res) => {
  try {
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: "Payments aren't configured — contact support" });
    }
    const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${req.params.reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.status || verifyData.data.status !== "success") {
      await recordPaymentAttempt(req.user.id, { reference: req.params.reference, method: "checkout_verify", status: "failed", amount: Number(verifyData.data?.amount || 0) / 100, currency: verifyData.data?.currency || "NGN", message: verifyData.data?.gateway_response || verifyData.message || "Payment hasn't succeeded yet" });
      return res.status(400).json({ error: "Payment hasn't succeeded yet" });
    }
    const intent = await loadCheckoutIntent(req.params.reference);
    if (!intent || Number(intent.buyer_id) !== Number(req.user.id)) {
      return res.status(403).json({ error: "This payment does not belong to your account" });
    }
    try {
      assertPaystackMatchesCheckoutIntent(intent, verifyData.data);
    } catch (integrityErr) {
      await markCheckoutIntent(req.params.reference, "integrity_failed", integrityErr.message);
      await recordPaymentAttempt(req.user.id, { reference: req.params.reference, method: "checkout_verify", status: "integrity_failed", amount: Number(verifyData.data?.amount || 0) / 100, currency: verifyData.data?.currency || "NGN", message: integrityErr.message });
      return res.status(409).json({ error: "Payment received but checkout verification did not match. Your order was not created; contact support with the payment reference." });
    }
    await recordPaymentAttempt(req.user.id, { reference: req.params.reference, method: "checkout_verify", status: "success", amount: Number(verifyData.data?.amount || 0) / 100, currency: verifyData.data?.currency || "NGN" });
    const { order } = await finalizeOrderFromPaystackCharge(req.params.reference, verifyData.data);
    res.json({ order });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/checkout/pay-with-saved-card", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, async (req, res) => {
  try {
    const { items, shippingAddress, currency, cardId } = req.body;
    if (!isNigeriaCountry(shippingAddress?.country)) {
      return res.status(400).json({ error: "Delivery is available to Nigerian addresses only" });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Cart is empty" });
    }
    const normalizedShippingAddress = normalizePrivateShippingAddress(shippingAddress);
    if (!privateShippingAddressIsComplete(normalizedShippingAddress)) {
      return res.status(400).json({ error: "Recipient name, phone, street, city, and postal code are required" });
    }
    if (!cardId) return res.status(400).json({ error: "Pick a saved card" });
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: "Payments aren't configured — contact support" });
    }

    const cardResult = await pool.query("SELECT * FROM saved_cards WHERE id = $1", [cardId]);
    if (!cardResult.rows.length || cardResult.rows[0].user_id !== req.user.id) {
      return res.status(404).json({ error: "Saved card not found" });
    }
    const authorizationCode = decryptFieldSafe(cardResult.rows[0].authorization_code);

    let subtotal = 0;
    let shippingTotal = 0;
    const itemSnapshots = [];
    for (const cartItem of items) {
      const qty = Number(cartItem.qty);
      if (!cartItem.listingId || !Number.isInteger(qty) || qty <= 0) {
        return res.status(400).json({ error: "Each cart item needs a valid listingId and a positive quantity" });
      }
      const listingResult = await pool.query(
        "SELECT * FROM listings WHERE id = $1 AND status = 'active'",
        [cartItem.listingId]
      );
      if (listingResult.rows.length === 0) {
        return res.status(404).json({ error: `Listing ${cartItem.listingId} isn't available` });
      }
      const listing = listingResult.rows[0];
      const price = Number(listing.price);
      if (!(price > 0)) return res.status(400).json({ error: "Listing has an invalid price" });
      const shippingFee = Number(listing.shipping_fee) || 0;
      subtotal += price * qty;
      shippingTotal += shippingFee * qty;
      itemSnapshots.push({ listingId: listing.id, qty, unitPrice: price, shippingFee });
    }
    const taxRate = await getTaxRate();
    const taxAmount = Math.round(subtotal * taxRate * 100) / 100;
    const total = Math.round((subtotal + shippingTotal + taxAmount) * 100) / 100;

    const userResult = await pool.query("SELECT email FROM users WHERE id = $1", [req.user.id]);
    const email = userResult.rows[0]?.email;
    if (!email) return res.status(400).json({ error: "Add an email to your account before checking out" });

    const reference = generateCheckoutReference();
    const amountKobo = Math.round(total * 100);
    const reservationClient = await pool.connect();
    try {
      await reservationClient.query("BEGIN");
      await createCheckoutIntent({
        reference, buyerId: req.user.id, buyerUsername: req.user.username, buyerEmail: email,
        amountKobo, items: itemSnapshots, shippingAddress: normalizedShippingAddress, saveCard: false,
      }, reservationClient);
      await reserveCheckoutListings(reservationClient, { buyerId: req.user.id, reference, items: itemSnapshots });
      await reservationClient.query("COMMIT");
    } catch (reservationErr) {
      await reservationClient.query("ROLLBACK");
      if (reservationErr.code === "LISTING_RESERVED") {
        return res.status(409).json({ error: reservationErr.message, code: "LISTING_RESERVED" });
      }
      if (reservationErr.code === "LISTING_UNAVAILABLE") {
        return res.status(409).json({ error: reservationErr.message, code: "LISTING_UNAVAILABLE" });
      }
      throw reservationErr;
    } finally {
      reservationClient.release();
    }

    const chargeRes = await fetch("https://api.paystack.co/transaction/charge_authorization", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        amount: amountKobo,
        currency: "NGN",
        reference,
        authorization_code: authorizationCode,
        metadata: {
          buyerId: req.user.id,
          buyerUsername: req.user.username,
          items: items.map((i) => ({ listingId: i.listingId, qty: Number(i.qty) })),
          currency: "NGN",
        },
      }),
    });
    const chargeData = await chargeRes.json();
    if (!chargeData.status || chargeData.data.status !== "success") {
      await markCheckoutIntent(reference, "failed", chargeData.data?.gateway_response || chargeData.message || "Payment failed");
      await releaseCheckoutReservations(reference);
      await recordPaymentAttempt(req.user.id, { reference, method: "saved_card", status: "failed", amount: total, currency: "NGN", message: chargeData.data?.gateway_response || chargeData.message || "Payment failed" });
      return res.status(400).json({ error: chargeData.data?.gateway_response || chargeData.message || "Payment failed" });
    }
    try {
      assertPaystackMatchesCheckoutIntent(await loadCheckoutIntent(reference), chargeData.data);
    } catch (integrityErr) {
      await markCheckoutIntent(reference, "integrity_failed", integrityErr.message);
      await recordPaymentAttempt(req.user.id, { reference, method: "saved_card", status: "integrity_failed", amount: Number(chargeData.data?.amount || 0) / 100, currency: chargeData.data?.currency || "NGN", message: integrityErr.message });
      return res.status(409).json({ error: "Payment received but checkout verification did not match. Your order was not created; contact support with the payment reference." });
    }
    await recordPaymentAttempt(req.user.id, { reference, method: "saved_card", status: "success", amount: total, currency: "NGN" });
    const { order } = await finalizeOrderFromPaystackCharge(reference, chargeData.data);
    res.json({ order });
  } catch (err) {
    sendInternalError(res, err);
  }
});

async function fetchOrdersWithItems(whereClause, params, { includeDeliveryTokens = false, includeSentDeliveryTokens = false, payoutSellerId = null, includeAdminPayouts = false } = {}) {
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
  const historiesResult = await pool.query(
    `SELECT order_item_id, event_type, label, details, created_at
     FROM order_item_status_events
     WHERE order_item_id = ANY($1)
     ORDER BY created_at ASC, id ASC`,
    [itemsResult.rows.map((item) => item.id)]
  );
  const safeItems = itemsResult.rows.map((item) => {
    const withHistory = {
      ...item,
      status_history: historiesResult.rows.filter((event) => event.order_item_id === item.id),
    };
    // The paid buyer can see the token immediately. A seller receives it only
    // after that buyer explicitly sends it; admin order responses never do.
    if (includeDeliveryTokens) return withHistory;
    if (includeSentDeliveryTokens && payoutSellerId && Number(item.seller_id) === Number(payoutSellerId) && item.delivery_token_sent_at) return withHistory;
    const { delivery_token, ...safe } = withHistory;
    return safe;
  });
  let payouts = [];
  if (payoutSellerId || includeAdminPayouts) {
    const payoutParams = [orderIds];
    let payoutWhere = "order_id = ANY($1)";
    if (payoutSellerId) {
      payoutParams.push(payoutSellerId);
      payoutWhere += " AND seller_id = $2";
    }
    const payoutResult = await pool.query(
      `SELECT * FROM seller_payouts WHERE ${payoutWhere} ORDER BY created_at DESC`,
      payoutParams
    );
    payouts = payoutResult.rows;
  }
  return orders.map((o) => ({
    ...o,
    items: safeItems.filter((i) => i.order_id === o.id),
    payouts: payouts.filter((p) => p.order_id === o.id),
  }));
}

app.get("/orders/mine", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    // Only the buyer may receive the secret delivery token.
    const orders = await fetchOrdersWithItems("buyer_id = $1", [req.user.id], { includeDeliveryTokens: true });
    res.json({ orders });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/orders/selling", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const orders = await fetchOrdersWithItems(
      "id IN (SELECT order_id FROM order_items WHERE seller_id = $1)",
      [req.user.id],
      { payoutSellerId: req.user.id, includeSentDeliveryTokens: true }
    );
    res.json({
      orders: orders.map((order) => order.payment_status === "refunded"
        ? { ...order, shipping_address: { accessRemoved: true } }
        : order),
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/orders", authenticate, requirePermission("order_access"), async (req, res) => {
  try {
    const orders = await fetchOrdersWithItems("TRUE", [], { includeAdminPayouts: true });
    res.json({ orders });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/orders/:id/release", authenticate, requirePermission("finance"), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const orderResult = await client.query("SELECT * FROM orders WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (!orderResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Order not found" });
    }
    const order = orderResult.rows[0];
    if (order.payment_status !== "held") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: `Only held payments can be released. This order is currently ${order.payment_status}.` });
    }

    // Returns remain a hard financial lock. A manual delivery override may
    // bypass only the normal token/photo delivery safeguards — it may NEVER
    // bypass an active return. This keeps "emergency release" from becoming a
    // shortcut around buyer protection.
    const itemResult = await client.query(
      `SELECT id, title, seller_id, fulfillment_status, buyer_confirmed_at, proof_of_delivery_url,
         delivery_token_redeemed_at, return_status, cancellation_status
       FROM order_items WHERE order_id = $1 FOR UPDATE`,
      [req.params.id]
    );
    const allItems = itemResult.rows;
    const activeReturn = allItems.find((i) => ["requested", "approved"].includes(i.return_status));
    if (activeReturn) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Payment cannot be released while a return is in progress.",
        code: "RETURN_LOCKED",
      });
    }
    if (allItems.some((i) => i.fulfillment_status === "returned")) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Payment cannot be released because this order contains a returned item.",
        code: "RETURNED_ITEM_LOCKED",
      });
    }

    const relevantItems = allItems.filter((i) => i.fulfillment_status !== "cancelled");
    if (!relevantItems.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "There are no releasable items on this order." });
    }

    const safeguardProblems = [];
    for (const item of relevantItems) {
      if (!item.proof_of_delivery_url) {
        safeguardProblems.push(`Item #${item.id} (${item.title}): delivery picture is missing`);
      }
      if (!item.delivery_token_redeemed_at) {
        safeguardProblems.push(`Item #${item.id} (${item.title}): buyer delivery token has not been redeemed`);
      }
      if (["requested", "approved"].includes(item.cancellation_status)) {
        safeguardProblems.push(`Item #${item.id} (${item.title}): cancellation is ${item.cancellation_status}`);
      }
    }

    const overrideDeliverySafeguards = req.body?.overrideDeliverySafeguards === true;
    const overrideReason = String(req.body?.overrideReason || "").trim();
    if (safeguardProblems.length && !overrideDeliverySafeguards) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Normal delivery safeguards are incomplete. Use the explicit delivery-safeguard override only after reviewing the order and documenting why an emergency release is justified.",
        code: "DELIVERY_SAFEGUARDS_REQUIRED",
        safeguardProblems,
      });
    }
    if (safeguardProblems.length && overrideDeliverySafeguards) {
      if (overrideReason.length < 10) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: "Enter a clear override reason of at least 10 characters.",
          code: "OVERRIDE_REASON_REQUIRED",
        });
      }
      if (overrideReason.length > 1000) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Override reason is too long." });
      }
    }

    // A disputed order stays locked unless the active case has already been
    // explicitly decided in the seller's favor. In that one case, release
    // and dispute resolution happen in the SAME database transaction so
    // there is never a window where the dispute lock is removed first.
    let resolvedDispute = null;
    if (order.is_disputed) {
      const disputeResult = await client.query(
        `SELECT * FROM dispute_cases
         WHERE order_id = $1 AND status <> 'resolved' AND resolution = 'seller_release'
         ORDER BY updated_at DESC LIMIT 1 FOR UPDATE`,
        [req.params.id]
      );
      if (!disputeResult.rows.length) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: "Payment cannot be released while this order has an active dispute unless the dispute decision is 'Release to seller'.",
        });
      }
      const resolved = await client.query(
        `UPDATE dispute_cases SET
           status = 'resolved', resolved_by_id = $1, resolved_at = NOW(), updated_at = NOW()
         WHERE id = $2 RETURNING *`,
        [req.user.id, disputeResult.rows[0].id]
      );
      resolvedDispute = resolved.rows[0];
    }

    const updated = await client.query(
      `UPDATE orders SET payment_status = 'released', is_disputed = false
       WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    await client.query("COMMIT");

    const usedDeliveryOverride = safeguardProblems.length > 0 && overrideDeliverySafeguards;
    logAdminAction(
      req.user.id,
      usedDeliveryOverride ? "payment_release_delivery_override" : "payment_released",
      usedDeliveryOverride
        ? `OVERRIDE DELIVERY SAFEGUARDS for order #${updated.rows[0].id} (${formatMoneyServer(updated.rows[0].total, updated.rows[0].currency)}). Missing safeguards: ${safeguardProblems.join("; ")}. Admin reason: ${overrideReason}${resolvedDispute ? `; resolved dispute #${resolvedDispute.id}` : ""}`
        : `Released payment for order #${updated.rows[0].id} (${formatMoneyServer(updated.rows[0].total, updated.rows[0].currency)})${resolvedDispute ? ` and resolved dispute #${resolvedDispute.id}` : ""}`
    );
    const sellerIds = await pool.query(
      "SELECT DISTINCT seller_id FROM order_items WHERE order_id = $1",
      [req.params.id]
    );
    for (const row of sellerIds.rows) {
      createNotification(row.seller_id, "funds_released", "Funds released for order — payment is now in your available balance.");
      if (!usedDeliveryOverride) {
        await queueAutomaticSellerPayouts(Number(req.params.id), row.seller_id).catch((err) => {
          console.error(`Automatic payout scheduling failed after finance release for order #${req.params.id}, seller #${row.seller_id}:`, err.message);
        });
      }
    }
    if (resolvedDispute) {
      const buyer = await pool.query("SELECT buyer_id FROM orders WHERE id = $1", [req.params.id]);
      if (buyer.rows[0]?.buyer_id) {
        createNotification(buyer.rows[0].buyer_id, "dispute_status", `Your dispute for order #${req.params.id} has been resolved. Payment was released to the seller.`);
      }
    }
    res.json({
      order: updated.rows[0],
      resolvedDispute,
      deliverySafeguardsOverridden: usedDeliveryOverride,
      safeguardProblems: usedDeliveryOverride ? safeguardProblems : [],
    });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.post("/orders/:id/buyer-cancel-refund", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  const client = await pool.connect();
  let order;
  try {
    const reason = String(req.body?.reason || "").trim();
    if (!reason) return res.status(400).json({ error: "Enter a reason for cancelling or refunding this order" });
    if (reason.length > 1000) return res.status(400).json({ error: "Reason is too long" });
    if (!process.env.PAYSTACK_SECRET_KEY) return res.status(500).json({ error: "Paystack refunds aren't configured — contact support" });

    await client.query("BEGIN");
    const orderResult = await client.query("SELECT * FROM orders WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (!orderResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Order not found" });
    }
    order = orderResult.rows[0];
    if (Number(order.buyer_id) !== Number(req.user.id)) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "Only the buyer can cancel or refund this order" });
    }
    if (order.payment_status !== "held") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This order can no longer be cancelled or refunded" });
    }
    if (!order.paystack_reference) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This order has no Paystack reference for an automatic refund" });
    }
    const itemsResult = await client.query("SELECT * FROM order_items WHERE order_id = $1 FOR UPDATE", [order.id]);
    const items = itemsResult.rows;
    if (!items.length || items.some((item) => item.delivery_token_sent_at || item.delivery_token_redeemed_at)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Cancellation and refund are permanently closed because a delivery token was sent to a seller" });
    }
    const payoutLock = await client.query(
      `SELECT 1 FROM seller_payouts WHERE order_id = $1 AND status IN ('queued', 'processing', 'request_unknown', 'paid') LIMIT 1`,
      [order.id]
    );
    if (payoutLock.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Seller payout has already started, so this order cannot be refunded" });
    }
    if (order.is_disputed || items.some((item) => ["requested", "approved"].includes(item.return_status))) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Resolve the existing return or dispute before requesting this refund" });
    }
    const total = Number(order.total || 0);
    const cancellationFee = Math.round(total * 0.02 * 100) / 100;
    const refundAmount = Math.round((total - cancellationFee) * 100) / 100;
    if (!(refundAmount > 0)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This order has no refundable balance" });
    }
    const received = items.some((item) => item.fulfillment_status === "delivered" || item.buyer_confirmed_at || item.proof_of_delivery_url);
    const locked = await client.query(
      `UPDATE orders SET payment_status = 'refund_pending', refund_status = 'requesting',
       refund_previous_payment_status = 'held', refund_reason = $1, refund_requested_by = $2,
       refund_type = 'buyer_cancellation', refund_amount = $3, cancellation_fee = $4,
       buyer_exit_type = $5, refund_requested_at = NOW(), refunded_at = NULL, refund_failure_reason = NULL
       WHERE id = $6 RETURNING *`,
      [reason, req.user.id, refundAmount, cancellationFee, received ? "return_refund" : "cancellation", order.id]
    );
    order = locked.rows[0];
    await client.query("COMMIT");

    let paystackRes;
    let paystackData;
    try {
      paystackRes = await fetch("https://api.paystack.co/refund", {
        method: "POST",
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          transaction: order.paystack_reference,
          amount: Math.round(refundAmount * 100),
          currency: order.currency || "NGN",
          customer_note: `Stallyard ${received ? "return" : "cancellation"} refund for order #${order.id}; 2% cancellation fee retained.`,
          merchant_note: `Automatic buyer refund for order #${order.id}; fee ${cancellationFee}.`,
        }),
      });
      paystackData = await paystackRes.json();
    } catch (err) {
      await pool.query("UPDATE orders SET refund_status = 'request_unknown', refund_failure_reason = $1 WHERE id = $2", ["Could not confirm whether Paystack received the refund request.", order.id]);
      return res.status(502).json({ error: "Refund submission could not be confirmed. The order remains locked while Stallyard verifies it." });
    }
    if (!paystackRes.ok || !paystackData.status) {
      const message = paystackData.message || "Paystack rejected the refund request";
      const restored = await pool.query(
        `UPDATE orders SET payment_status = 'held', refund_status = 'failed', refund_failure_reason = $1 WHERE id = $2 RETURNING *`,
        [message, order.id]
      );
      return res.status(400).json({ error: message, order: restored.rows[0] });
    }
    const refund = paystackData.data || {};
    const updated = await pool.query(
      `UPDATE orders SET refund_status = $1, paystack_refund_id = $2, refund_failure_reason = NULL WHERE id = $3 RETURNING *`,
      [refund.status || "pending", refund.id || null, order.id]
    );
    createNotification(order.buyer_id, "refund_started", `Your ${formatMoneyServer(refundAmount, order.currency)} refund for order #${order.id} was submitted. Stallyard retained the disclosed ${formatMoneyServer(cancellationFee, order.currency)} cancellation fee.`);
    res.json({ order: updated.rows[0], refundAmount, cancellationFee, buyerExitType: received ? "return_refund" : "cancellation" });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.patch("/orders/:id/refund", authenticate, requirePermission("finance"), async (req, res) => {
  const client = await pool.connect();
  let order;
  try {
    const reason = String(req.body?.reason || "").trim();
    if (!reason) {
      return res.status(400).json({ error: "Enter a reason for the refund" });
    }
    if (reason.length > 1000) {
      return res.status(400).json({ error: "Refund reason is too long" });
    }
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: "Paystack refunds aren't configured — contact support" });
    }

    await client.query("BEGIN");
    const orderResult = await client.query(
      "SELECT * FROM orders WHERE id = $1 FOR UPDATE",
      [req.params.id]
    );
    if (orderResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Order not found" });
    }
    order = orderResult.rows[0];

    if (order.payment_status !== "held") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Refunds are closed because seller payment is no longer being held" });
    }
    const sentToken = await client.query(
      "SELECT 1 FROM order_items WHERE order_id = $1 AND (delivery_token_sent_at IS NOT NULL OR delivery_token_redeemed_at IS NOT NULL) LIMIT 1",
      [order.id]
    );
    if (sentToken.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Refunds are permanently closed because a delivery token was sent to a seller" });
    }

    const sellerPayoutLock = await client.query(
      `SELECT id, status FROM seller_payouts
       WHERE order_id = $1 AND status IN ('queued', 'processing', 'request_unknown', 'paid')
       LIMIT 1`,
      [order.id]
    );
    if (sellerPayoutLock.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "A seller bank payout has already started for this order. Finance must resolve or recover that payout before refunding the buyer.",
        code: "SELLER_PAYOUT_ALREADY_STARTED",
      });
    }

    if (!order.paystack_reference) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This order has no Paystack transaction reference, so it can't be refunded automatically." });
    }
    if (order.payment_status === "refunded") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This order has already been refunded" });
    }
    if (order.payment_status === "refund_pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "A refund is already in progress for this order" });
    }

    const previousStatus = order.payment_status || "held";
    const locked = await client.query(
      `UPDATE orders SET
         payment_status = 'refund_pending',
         refund_status = 'requesting',
         refund_previous_payment_status = $1,
         refund_reason = $2,
         refund_requested_by = $3,
         refund_type = 'full',
         refund_amount = total,
         refund_requested_at = NOW(),
         refunded_at = NULL,
         refund_failure_reason = NULL
       WHERE id = $4
       RETURNING *`,
      [previousStatus, reason, req.user.id, req.params.id]
    );
    order = locked.rows[0];
    await client.query("COMMIT");

    let paystackRes;
    let paystackData;
    try {
      paystackRes = await fetch("https://api.paystack.co/refund", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          transaction: order.paystack_reference,
          amount: Math.round(Number(order.total) * 100),
          currency: order.currency || "NGN",
          customer_note: `Refund for Stallyard order #${order.id}: ${reason.slice(0, 180)}`,
          merchant_note: `Admin ${req.user.username} initiated refund for Stallyard order #${order.id}: ${reason.slice(0, 180)}`,
        }),
      });
      paystackData = await paystackRes.json();
    } catch (err) {
      await pool.query(
        `UPDATE orders SET refund_status = 'request_unknown', refund_failure_reason = $1 WHERE id = $2`,
        ["Could not confirm whether Paystack received the refund request. Check Paystack before retrying.", req.params.id]
      );
      return res.status(502).json({
        error: "Couldn't confirm the refund request with Paystack. The order is locked as refund pending so it isn't paid out twice. Check Paystack before retrying.",
      });
    }

    if (!paystackRes.ok || !paystackData.status) {
      const message = paystackData.message || "Paystack rejected the refund request";
      const restored = await pool.query(
        `UPDATE orders SET
           payment_status = COALESCE(refund_previous_payment_status, 'held'),
           refund_status = 'failed',
           refund_failure_reason = $1
         WHERE id = $2
         RETURNING *`,
        [message, req.params.id]
      );
      return res.status(400).json({ error: message, order: restored.rows[0] });
    }

    const refund = paystackData.data || {};
    const updated = await pool.query(
      `UPDATE orders SET
         payment_status = 'refund_pending',
         refund_status = $1,
         paystack_refund_id = $2,
         refund_failure_reason = NULL
       WHERE id = $3
       RETURNING *`,
      [refund.status || "pending", refund.id || null, req.params.id]
    );

    logAdminAction(
      req.user.id,
      "refund_requested",
      `Requested Paystack refund for order #${order.id} (${formatMoneyServer(order.total, order.currency)})`
    );
    createNotification(
      order.buyer_id,
      "refund_started",
      `Your refund for order #${order.id} has been submitted for processing.`
    );
    res.json({ order: updated.rows[0], paystackMessage: paystackData.message || "Refund queued" });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.patch("/orders/:id/refund/partial", authenticate, requirePermission("finance"), async (req, res) => {
  const client = await pool.connect();
  let order;
  try {
    const amount = Math.round(Number(req.body?.amount) * 100) / 100;
    const reason = String(req.body?.reason || "").trim();
    const disputeId = Number(req.body?.disputeId);
    if (!(amount > 0)) return res.status(400).json({ error: "Enter a partial refund amount greater than zero" });
    if (!reason) return res.status(400).json({ error: "Enter the reason / negotiated outcome for the partial refund" });
    if (reason.length > 1000) return res.status(400).json({ error: "Refund reason is too long" });
    if (!disputeId) return res.status(400).json({ error: "A linked dispute case is required for a partial refund" });
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: "Paystack refunds aren't configured — contact support" });
    }

    await client.query("BEGIN");
    const orderResult = await client.query("SELECT * FROM orders WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (!orderResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Order not found" });
    }
    order = orderResult.rows[0];
    if (order.payment_status !== "held") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Refunds are closed because seller payment is no longer being held" });
    }
    const sentToken = await client.query(
      "SELECT 1 FROM order_items WHERE order_id = $1 AND (delivery_token_sent_at IS NOT NULL OR delivery_token_redeemed_at IS NOT NULL) LIMIT 1",
      [order.id]
    );
    if (sentToken.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Refunds are permanently closed because a delivery token was sent to a seller" });
    }
    const startedSellerPayout = await client.query(
      `SELECT id FROM seller_payouts
       WHERE order_id = $1 AND status IN ('queued', 'processing', 'request_unknown', 'paid') LIMIT 1`,
      [order.id]
    );
    if (startedSellerPayout.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "A seller bank payout has already started. Resolve or recover it before issuing a partial refund." });
    }
    const disputeResult = await client.query(
      "SELECT * FROM dispute_cases WHERE id = $1 AND order_id = $2 FOR UPDATE",
      [disputeId, req.params.id]
    );
    if (!disputeResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Linked dispute case not found" });
    }
    if (disputeResult.rows[0].status === "resolved") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This dispute is already resolved" });
    }
    if (!order.paystack_reference) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This order has no Paystack transaction reference" });
    }
    if (order.payment_status === "refunded") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This order has already been fully refunded" });
    }
    if (order.payment_status === "refund_pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "A refund is already in progress for this order" });
    }
    if (order.refund_status === "processed" && Number(order.refund_amount || 0) > 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "A refund has already been processed for this order. Additional partial refunds require manual review." });
    }

    const sellerCountResult = await client.query(
      "SELECT COUNT(DISTINCT seller_id)::int AS count FROM order_items WHERE order_id = $1",
      [req.params.id]
    );
    if ((sellerCountResult.rows[0]?.count || 0) !== 1) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Partial refunds are currently limited to single-seller orders so Stallyard can reduce the correct seller balance safely. Use a full refund or handle the multi-seller case manually.",
      });
    }

    const sellerPayable = Math.max(0,
      (Number(order.subtotal) || 0) + (Number(order.shipping_total) || 0) - (Number(order.commission_amount) || 0)
    );
    if (amount >= Number(order.total || 0)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "For the entire order amount, use Full refund instead" });
    }
    if (amount > sellerPayable) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: `Partial refund cannot exceed the seller payable amount of ${formatMoneyServer(sellerPayable, order.currency)}.`,
      });
    }

    const previousStatus = order.payment_status || "held";
    const locked = await client.query(
      `UPDATE orders SET
         payment_status = 'refund_pending',
         refund_status = 'requesting',
         refund_previous_payment_status = $1,
         refund_reason = $2,
         refund_requested_by = $3,
         refund_type = 'partial',
         refund_amount = $4,
         refund_requested_at = NOW(),
         refunded_at = NULL,
         refund_failure_reason = NULL,
         is_disputed = true
       WHERE id = $5 RETURNING *`,
      [previousStatus, reason, req.user.id, amount, req.params.id]
    );
    order = locked.rows[0];
    await client.query(
      `UPDATE dispute_cases SET status = 'in_review', resolution = 'partial_refund', resolution_note = $1,
       resolved_by_id = NULL, resolved_at = NULL, updated_at = NOW() WHERE id = $2`,
      [reason, disputeId]
    );
    await client.query("COMMIT");

    let paystackRes;
    let paystackData;
    try {
      paystackRes = await fetch("https://api.paystack.co/refund", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          transaction: order.paystack_reference,
          amount: Math.round(amount * 100),
          currency: order.currency || "NGN",
          customer_note: `Partial refund for Stallyard order #${order.id}: ${reason.slice(0, 180)}`,
          merchant_note: `Admin ${req.user.username} initiated partial refund of ${formatMoneyServer(amount, order.currency)} for dispute #${disputeId}`,
        }),
      });
      paystackData = await paystackRes.json();
    } catch {
      await pool.query(
        `UPDATE orders SET refund_status = 'request_unknown', refund_failure_reason = $1 WHERE id = $2`,
        ["Could not confirm whether Paystack received the partial refund request. Check Paystack before retrying.", req.params.id]
      );
      return res.status(502).json({ error: "Couldn't confirm the partial refund request with Paystack. The order remains locked for manual review." });
    }

    if (!paystackRes.ok || !paystackData.status) {
      const message = paystackData.message || "Paystack rejected the partial refund request";
      const restored = await pool.query(
        `UPDATE orders SET payment_status = COALESCE(refund_previous_payment_status, 'held'),
         refund_status = 'failed', refund_failure_reason = $1 WHERE id = $2 RETURNING *`,
        [message, req.params.id]
      );
      return res.status(400).json({ error: message, order: restored.rows[0] });
    }

    const refund = paystackData.data || {};
    const updated = await pool.query(
      `UPDATE orders SET payment_status = 'refund_pending', refund_status = $1,
       paystack_refund_id = $2, refund_failure_reason = NULL WHERE id = $3 RETURNING *`,
      [refund.status || "pending", refund.id || null, req.params.id]
    );
    logAdminAction(req.user.id, "partial_refund_requested",
      `Requested partial refund of ${formatMoneyServer(amount, order.currency)} for order #${order.id}, dispute #${disputeId}`);
    createNotification(order.buyer_id, "refund_started",
      `A partial refund of ${formatMoneyServer(amount, order.currency)} for order #${order.id} has been submitted for processing.`);
    res.json({ order: updated.rows[0], paystackMessage: paystackData.message || "Partial refund queued" });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.patch("/orders/:id/dispute", authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { isDisputed, reason, statement, evidenceUrls } = req.body;
    await client.query("BEGIN");
    const orderCheck = await client.query("SELECT buyer_id, payment_status FROM orders WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (orderCheck.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Order not found" });
    }

    const buyerId = orderCheck.rows[0].buyer_id;
    const isBuyer = buyerId === req.user.id;
    const sellerCheck = await client.query(
      "SELECT 1 FROM order_items WHERE order_id = $1 AND seller_id = $2 LIMIT 1",
      [req.params.id, req.user.id]
    );
    const isSeller = sellerCheck.rows.length > 0;
    const isAdminResolver = hasPermission(req.user, "dispute_resolution");
    const isParty = isBuyer || isSeller;

    if (!isParty && !isAdminResolver) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "You can only dispute orders you're part of" });
    }
    // Buyers/sellers may open a case, but only a dispute admin may close one.
    if (!isDisputed && !isAdminResolver) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "Only a dispute administrator can resolve an open case" });
    }
    if (isDisputed && orderCheck.rows[0].payment_status !== "held") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "A dispute cannot be opened after seller payment has been released" });
    }
    if (isDisputed) {
      const sentToken = await client.query(
        "SELECT 1 FROM order_items WHERE order_id = $1 AND (delivery_token_sent_at IS NOT NULL OR delivery_token_redeemed_at IS NOT NULL) LIMIT 1",
        [req.params.id]
      );
      if (sentToken.rows.length) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "A case cannot be opened after a delivery token has been sent to a seller" });
      }
    }

    const result = await client.query(
      "UPDATE orders SET is_disputed = $1 WHERE id = $2 RETURNING *",
      [!!isDisputed, req.params.id]
    );

    let dispute = null;
    if (isDisputed) {
      const buyerStatement = isBuyer ? String(statement || "").trim() : "";
      const sellerStatement = isSeller ? String(statement || "").trim() : "";
      const cleanReason = String(reason || "").trim();
      const cleanEvidence = Array.isArray(evidenceUrls) ? evidenceUrls.filter(Boolean).slice(0, 10) : [];
      const caseResult = await client.query(
        `INSERT INTO dispute_cases (
           order_id, opened_by_id, reason, buyer_statement, seller_statement, evidence_urls,
           status, resolution, resolution_note, resolved_by_id, resolved_at, updated_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, 'open', NULL, '', NULL, NULL, NOW())
         ON CONFLICT (order_id) DO UPDATE SET
           opened_by_id = EXCLUDED.opened_by_id,
           reason = CASE WHEN EXCLUDED.reason <> '' THEN EXCLUDED.reason ELSE dispute_cases.reason END,
           buyer_statement = CASE WHEN EXCLUDED.buyer_statement <> '' THEN EXCLUDED.buyer_statement ELSE dispute_cases.buyer_statement END,
           seller_statement = CASE WHEN EXCLUDED.seller_statement <> '' THEN EXCLUDED.seller_statement ELSE dispute_cases.seller_statement END,
           evidence_urls = CASE WHEN jsonb_array_length(EXCLUDED.evidence_urls) > 0 THEN EXCLUDED.evidence_urls ELSE dispute_cases.evidence_urls END,
           status = 'open', resolution = NULL, resolution_note = '', resolved_by_id = NULL, resolved_at = NULL, updated_at = NOW()
         RETURNING *`,
        [req.params.id, req.user.id, cleanReason, buyerStatement, sellerStatement, JSON.stringify(cleanEvidence)]
      );
      dispute = caseResult.rows[0];
    } else {
      const caseResult = await client.query(
        `UPDATE dispute_cases SET status = 'resolved', resolved_by_id = $1,
           resolved_at = NOW(), updated_at = NOW()
         WHERE order_id = $2 RETURNING *`,
        [req.user.id, req.params.id]
      );
      dispute = caseResult.rows[0] || null;
    }

    await client.query("COMMIT");
    if (isAdminResolver && !isParty) {
      logAdminAction(req.user.id, "dispute_updated", `${isDisputed ? "Opened" : "Resolved"} dispute on order #${req.params.id}`);
    }
    if (isDisputed) {
      const sellerIds = await pool.query("SELECT DISTINCT seller_id FROM order_items WHERE order_id = $1", [req.params.id]);
      for (const row of sellerIds.rows) {
        if (row.seller_id !== req.user.id) createNotification(row.seller_id, "dispute_opened", "A dispute was opened on one of your orders. Open Sales to review and respond.");
      }
      if (!isBuyer) createNotification(buyerId, "dispute_opened", "A dispute was opened on your order. Open Purchases to review it.");
    }
    res.json({ order: result.rows[0], dispute });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

const DISPUTE_STATUSES = new Set(["open", "in_review", "resolved"]);
const DISPUTE_RESOLUTIONS = new Set(["buyer_refund", "seller_release", "partial_refund", "no_action", "cancelled"]);

app.get("/disputes", authenticate, requirePermission("dispute_resolution"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT dc.*,
        opener.username AS opened_by_username, opener.display_name AS opened_by_name,
        resolver.username AS resolved_by_username, resolver.display_name AS resolved_by_name,
        buyer.username AS buyer_username, buyer.display_name AS buyer_name,
        o.total, o.currency, o.payment_status, o.created_at AS order_created_at,
        COALESCE(string_agg(DISTINCT seller.username, ', '), '') AS seller_usernames,
        COALESCE(string_agg(DISTINCT seller.display_name, ', '), '') AS seller_names
      FROM dispute_cases dc
      JOIN orders o ON o.id = dc.order_id
      JOIN users buyer ON buyer.id = o.buyer_id
      LEFT JOIN users opener ON opener.id = dc.opened_by_id
      LEFT JOIN users resolver ON resolver.id = dc.resolved_by_id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      LEFT JOIN users seller ON seller.id = oi.seller_id
      GROUP BY dc.id, opener.username, opener.display_name, resolver.username, resolver.display_name,
        buyer.username, buyer.display_name, o.total, o.currency, o.payment_status, o.created_at
      ORDER BY CASE dc.status WHEN 'open' THEN 0 WHEN 'in_review' THEN 1 ELSE 2 END, dc.updated_at DESC
    `);
    res.json({ disputes: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/disputes/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT dc.*
      FROM dispute_cases dc
      JOIN orders o ON o.id = dc.order_id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      WHERE o.buyer_id = $1 OR oi.seller_id = $1
      ORDER BY dc.updated_at DESC
    `, [req.user.id]);
    res.json({ disputes: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/disputes/:id/statement", authenticate, async (req, res) => {
  try {
    const statement = String(req.body.statement || "").trim();
    if (!statement) return res.status(400).json({ error: "Enter a statement first" });
    if (statement.length > 5000) return res.status(400).json({ error: "Statement is too long" });
    const check = await pool.query(`
      SELECT dc.*, o.buyer_id,
        EXISTS(SELECT 1 FROM order_items oi WHERE oi.order_id = dc.order_id AND oi.seller_id = $2) AS is_seller
      FROM dispute_cases dc JOIN orders o ON o.id = dc.order_id
      WHERE dc.id = $1
    `, [req.params.id, req.user.id]);
    if (!check.rows.length) return res.status(404).json({ error: "Dispute case not found" });
    const row = check.rows[0];
    const isBuyer = row.buyer_id === req.user.id;
    const isSeller = !!row.is_seller;
    if (!isBuyer && !isSeller) return res.status(403).json({ error: "You are not part of this dispute" });
    if (row.status === "resolved") return res.status(409).json({ error: "This dispute has already been resolved" });
    const field = isBuyer ? "buyer_statement" : "seller_statement";
    const result = await pool.query(
      `UPDATE dispute_cases SET ${field} = $1, updated_at = NOW() WHERE id = $2 RETURNING *`,
      [statement, req.params.id]
    );
    res.json({ dispute: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/disputes/:id", authenticate, requirePermission("dispute_resolution"), async (req, res) => {
  const client = await pool.connect();
  try {
    const { status, resolution, resolutionNote, adminNotes } = req.body;
    if (status && !DISPUTE_STATUSES.has(status)) return res.status(400).json({ error: "Invalid dispute status" });
    if (resolution && !DISPUTE_RESOLUTIONS.has(resolution)) return res.status(400).json({ error: "Invalid resolution" });
    await client.query("BEGIN");
    const existing = await client.query("SELECT * FROM dispute_cases WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (!existing.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Dispute case not found" });
    }
    const current = existing.rows[0];
    const nextStatus = status || current.status;
    const nextResolution = resolution === undefined ? current.resolution : (resolution || null);

    const orderStateResult = await client.query(
      "SELECT id, payment_status, is_disputed FROM orders WHERE id = $1 FOR UPDATE",
      [current.order_id]
    );
    if (!orderStateResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Linked order not found" });
    }
    const orderState = orderStateResult.rows[0];

    // Never remove the dispute money lock before the financial outcome is
    // actually complete. A refund decision remains in review until Paystack
    // confirms refund.processed. A seller-release decision remains in review
    // until the finance release succeeds. Partial refunds are intentionally
    // blocked from final resolution until the real partial-refund flow exists.
    if (nextStatus === "resolved") {
      if (!nextResolution) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "Choose a final decision before resolving this dispute" });
      }
      if (nextResolution === "buyer_refund" && orderState.payment_status !== "refunded") {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: "Keep this case In review until Paystack confirms the refund as processed. The dispute lock will stay on automatically.",
        });
      }
      if (nextResolution === "seller_release" && orderState.payment_status !== "released") {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: "Release the seller payment first. The dispute will resolve atomically when that release succeeds.",
        });
      }
      if (nextResolution === "partial_refund" && !(orderState.payment_status === "released")) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: "Keep this case In review until Paystack confirms the partial refund. The remaining seller payment will be released automatically when the refund is processed.",
        });
      }
    }

    const result = await client.query(`
      UPDATE dispute_cases SET
        status = $1,
        resolution = $2,
        resolution_note = $3,
        admin_notes = $4,
        resolved_by_id = CASE WHEN $1 = 'resolved' THEN $5 ELSE NULL END,
        resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE NULL END,
        updated_at = NOW()
      WHERE id = $6 RETURNING *
    `, [
      nextStatus,
      nextResolution,
      resolutionNote === undefined ? current.resolution_note : String(resolutionNote || ""),
      adminNotes === undefined ? current.admin_notes : String(adminNotes || ""),
      req.user.id,
      req.params.id,
    ]);

    // The order stays disputed until the case is genuinely complete.
    await client.query("UPDATE orders SET is_disputed = $1 WHERE id = $2", [nextStatus !== "resolved", current.order_id]);
    await client.query("COMMIT");
    logAdminAction(req.user.id, "dispute_case_updated", `Updated dispute #${req.params.id} for order #${current.order_id} to ${nextStatus}${nextResolution ? ` (${nextResolution})` : ""}`);
    const orderParties = await pool.query(`
      SELECT o.buyer_id, array_agg(DISTINCT oi.seller_id) FILTER (WHERE oi.seller_id IS NOT NULL) AS seller_ids
      FROM orders o LEFT JOIN order_items oi ON oi.order_id = o.id WHERE o.id = $1 GROUP BY o.buyer_id
    `, [current.order_id]);
    if (orderParties.rows.length) {
      const message = nextStatus === "resolved"
        ? `Your dispute for order #${current.order_id} has been resolved${resolutionNote ? `: ${String(resolutionNote).slice(0, 180)}` : "."}`
        : `Your dispute for order #${current.order_id} is now ${nextStatus === "in_review" ? "under review" : "open"}.`;
      createNotification(orderParties.rows[0].buyer_id, "dispute_status", message);
      for (const sellerId of orderParties.rows[0].seller_ids || []) createNotification(sellerId, "dispute_status", message);
    }
    res.json({ dispute: result.rows[0] });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

const ORDER_ITEM_STATUSES = new Set(["new", "preparing", "shipped", "delivered", "cancelled", "returned"]);

app.patch("/order-items/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query(
      "SELECT seller_id, cancellation_status, fulfillment_status, estimated_delivery_start, estimated_delivery_end FROM order_items WHERE id = $1",
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const isOwnSellerItem = existing.rows[0].seller_id === req.user.id;
    if (!isOwnSellerItem && !hasPermission(req.user, "order_management")) {
      return res.status(403).json({ error: "Only the seller, Order/Dispute Admin, or Super Admin can update fulfillment details" });
    }
    const {
      fulfillmentStatus,
      trackingNumber,
      carrier,
      proofOfDeliveryUrl,
      estimatedDeliveryStart,
      estimatedDeliveryEnd,
      liveLocationEnabled,
      liveLocationLatitude,
      liveLocationLongitude,
      liveLocationAccuracy,
    } = req.body;
    if (fulfillmentStatus && existing.rows[0].cancellation_status === "requested") {
      return res.status(409).json({ error: "Approve or deny the buyer's cancellation request before changing fulfillment status" });
    }
    if (fulfillmentStatus && !ORDER_ITEM_STATUSES.has(fulfillmentStatus)) {
      return res.status(400).json({ error: "Invalid fulfillment status" });
    }
    const sets = [];
    const values = [];
    let i = 1;
    const parseDeliveryDate = (value, fieldLabel) => {
      if (value === undefined) return undefined;
      if (value === null || value === "") return null;
      if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        throw Object.assign(new Error(`${fieldLabel} must use YYYY-MM-DD format`), { statusCode: 400 });
      }
      const [year, month, day] = value.split("-").map(Number);
      const parsed = new Date(Date.UTC(year, month - 1, day));
      if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
        throw Object.assign(new Error(`${fieldLabel} is not a valid date`), { statusCode: 400 });
      }
      return value;
    };
    const deliveryStart = parseDeliveryDate(estimatedDeliveryStart, "Estimated delivery start");
    const deliveryEnd = parseDeliveryDate(estimatedDeliveryEnd, "Estimated delivery end");
    const existingStart = existing.rows[0].estimated_delivery_start
      ? String(existing.rows[0].estimated_delivery_start).slice(0, 10)
      : null;
    const existingEnd = existing.rows[0].estimated_delivery_end
      ? String(existing.rows[0].estimated_delivery_end).slice(0, 10)
      : null;
    const effectiveStart = deliveryStart !== undefined ? deliveryStart : existingStart;
    const effectiveEnd = deliveryEnd !== undefined ? deliveryEnd : existingEnd;
    if (effectiveStart && effectiveEnd && effectiveEnd < effectiveStart) {
      return res.status(400).json({ error: "Estimated delivery end cannot be earlier than the start date" });
    }
    const hasLocation = liveLocationLatitude !== undefined || liveLocationLongitude !== undefined;
    if (hasLocation && existing.rows[0].fulfillment_status !== "shipped") {
      return res.status(409).json({ error: "Mark the order shipped before sharing a delivery location" });
    }
    if (hasLocation && fulfillmentStatus && ["delivered", "cancelled", "returned"].includes(fulfillmentStatus)) {
      return res.status(400).json({ error: "Location sharing cannot continue after delivery closes" });
    }
    if (fulfillmentStatus) {
      sets.push(`fulfillment_status = $${i++}`);
      values.push(fulfillmentStatus);
      if (fulfillmentStatus === "shipped") {
        sets.push(`shipped_at = COALESCE(shipped_at, NOW())`);
      }
      if (["delivered", "cancelled", "returned"].includes(fulfillmentStatus)) {
        sets.push(`live_location_enabled = FALSE`);
        sets.push(`live_location_expires_at = NULL`);
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
    if (deliveryStart !== undefined) {
      sets.push(`estimated_delivery_start = $${i++}`);
      values.push(deliveryStart);
    }
    if (deliveryEnd !== undefined) {
      sets.push(`estimated_delivery_end = $${i++}`);
      values.push(deliveryEnd);
    }
    if (typeof liveLocationEnabled === "boolean" && !hasLocation && !(fulfillmentStatus && ["delivered", "cancelled", "returned"].includes(fulfillmentStatus))) {
      sets.push(`live_location_enabled = $${i++}`);
      values.push(liveLocationEnabled);
      if (!liveLocationEnabled) {
        sets.push(`live_location_updated_at = NOW()`);
        sets.push(`live_location_expires_at = NULL`);
      }
    }
    if (hasLocation) {
      const latitude = Number(liveLocationLatitude);
      const longitude = Number(liveLocationLongitude);
      const accuracy = liveLocationAccuracy === undefined ? null : Number(liveLocationAccuracy);
      if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
          !Number.isFinite(longitude) || longitude < -180 || longitude > 180 ||
          (accuracy !== null && (!Number.isFinite(accuracy) || accuracy < 0))) {
        return res.status(400).json({ error: "Invalid delivery location" });
      }
      sets.push(`live_location_latitude = $${i++}`);
      values.push(latitude);
      sets.push(`live_location_longitude = $${i++}`);
      values.push(longitude);
      sets.push(`live_location_accuracy = $${i++}`);
      values.push(accuracy);
      sets.push(`live_location_updated_at = NOW()`);
      sets.push(`live_location_expires_at = NOW() + INTERVAL '30 minutes'`);
      sets.push(`live_location_enabled = TRUE`);
    }
    if (sets.length === 0) return res.status(400).json({ error: "No valid fields to update" });
    values.push(req.params.id);
    const result = await pool.query(
      `UPDATE order_items SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
      values
    );
    if (!isOwnSellerItem) {
      logAdminAction(req.user.id, "order_item_fulfillment_updated", `Updated fulfillment details for order item #${req.params.id}`);
    }
    res.json({ item: result.rows[0] });
  } catch (err) {
    if (err.statusCode === 400) return res.status(400).json({ error: err.message });
    sendInternalError(res, err);
  }
});

async function markItemReceivedAndMaybeRelease(itemId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const locked = await client.query(
      `SELECT oi.*, o.payment_status, o.is_disputed
       FROM order_items oi JOIN orders o ON o.id = oi.order_id
       WHERE oi.id = $1
       FOR UPDATE OF oi, o`,
      [itemId]
    );
    if (!locked.rows.length) throw new Error("Order item not found");
    const current = locked.rows[0];
    if (current.payment_status !== "held" || current.is_disputed) {
      throw new Error("Payment is no longer eligible for release");
    }
    if (["requested", "approved"].includes(current.return_status)) {
      throw new Error("Payment is locked because a return is in progress");
    }
    if (["requested", "approved"].includes(current.cancellation_status)) {
      throw new Error("Payment is locked because a cancellation is pending or approved");
    }

    const result = await client.query(
      `UPDATE order_items
       SET delivery_token = NULL, delivery_token_generated_at = NULL, delivery_token_redeemed_at = NOW(),
           live_location_enabled = FALSE, live_location_expires_at = NULL
       WHERE id = $1 AND delivery_token IS NOT NULL
       RETURNING *`,
      [itemId]
    );
    if (!result.rows.length) throw new Error("This delivery token has already been redeemed");
    const item = result.rows[0];

    const allItems = await client.query(
      "SELECT * FROM order_items WHERE order_id = $1 FOR UPDATE",
      [item.order_id]
    );
    const relevant = allItems.rows.filter((r) => !["cancelled", "returned"].includes(r.fulfillment_status));
    const allConfirmed = relevant.length > 0 && relevant.every(
      (r) => r.proof_of_delivery_url && r.delivery_token_redeemed_at &&
        !["requested", "approved"].includes(r.return_status)
    );
    let order = null;
    if (allConfirmed) {
      const orderRes = await client.query(
        `UPDATE orders SET payment_status = 'released'
         WHERE id = $1 AND payment_status = 'held' AND COALESCE(is_disputed, false) = false
         RETURNING *`,
        [item.order_id]
      );
      order = orderRes.rows[0] || null;
    }
    await client.query("COMMIT");

    createNotification(item.seller_id, "delivery_completed", `Delivery token redeemed for "${item.title}"`);
    if (order) {
      const sellerIds = [...new Set(relevant.map((r) => r.seller_id))];
      for (const sellerId of sellerIds) {
        createNotification(sellerId, "funds_released", "Funds released for order — payment is now in your available balance.");
      }
    }
    try {
      await queueAutomaticSellerPayouts(item.order_id, item.seller_id);
    } catch (payoutErr) {
      // Delivery remains valid even if payout scheduling needs finance review.
      // Never roll back or repeat a redeemed token after the token was accepted.
      console.error(`Automatic payout scheduling failed for order #${item.order_id}, seller #${item.seller_id}:`, payoutErr.message);
    }
    return { item, order };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

app.post("/order-items/:id/send-delivery-token", authenticate, codeRateLimit, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query(
      `SELECT oi.*, o.buyer_id, o.payment_status, o.is_disputed
       FROM order_items oi JOIN orders o ON o.id = oi.order_id
       WHERE oi.id = $1 FOR UPDATE OF oi, o`,
      [req.params.id]
    );
    if (!existing.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Order item not found" });
    }
    const item = existing.rows[0];
    if (Number(item.buyer_id) !== Number(req.user.id)) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "Only the buyer can send this delivery token" });
    }
    if (item.payment_status !== "held" || !item.delivery_token) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This delivery token is no longer available" });
    }
    if (item.is_disputed || ["requested", "approved"].includes(item.return_status)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "The token cannot be sent while a dispute or return is active" });
    }
    if (["requested", "approved"].includes(item.cancellation_status)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "The token cannot be sent while a cancellation is pending or approved" });
    }
    if (item.delivery_token_sent_at) {
      await client.query("ROLLBACK");
      return res.json({ item, alreadySent: true });
    }

    let threadResult = await client.query(
      "SELECT * FROM threads WHERE listing_id = $1 AND buyer_id = $2 AND seller_id = $3 LIMIT 1",
      [item.listing_id, item.buyer_id, item.seller_id]
    );
    if (!threadResult.rows.length) {
      threadResult = await client.query(
        "INSERT INTO threads (listing_id, buyer_id, seller_id) VALUES ($1, $2, $3) RETURNING *",
        [item.listing_id, item.buyer_id, item.seller_id]
      );
    }
    const body = `Delivery token for order #${item.order_id}, ${item.title}: ${item.delivery_token}`;
    const messageResult = await client.query(
      `INSERT INTO messages (thread_id, sender_id, message_type, body, order_id)
       VALUES ($1, $2, 'text', $3, $4) RETURNING *`,
      [threadResult.rows[0].id, item.buyer_id, body, item.order_id]
    );
    const updated = await client.query(
      "UPDATE order_items SET delivery_token_sent_at = NOW() WHERE id = $1 RETURNING *",
      [item.id]
    );
    await client.query("COMMIT");
    createNotification(item.seller_id, "delivery_token_sent", `Buyer sent the delivery token for order #${item.order_id}: ${item.title}`);
    res.json({ item: updated.rows[0], message: messageResult.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.patch("/order-items/:id/confirm-receipt", authenticate, async (req, res) => {
  try {
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id, o.payment_status, o.is_disputed
       FROM order_items oi
       JOIN orders o ON o.id = oi.order_id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can confirm delivery for this item" });
    }
    if (item.payment_status !== "held") {
      return res.status(400).json({ error: "This order is no longer awaiting delivery confirmation" });
    }
    if (item.is_disputed) {
      return res.status(409).json({ error: "You cannot release a delivery token while this order has an active dispute" });
    }
    if (["requested", "approved"].includes(item.return_status)) {
      return res.status(409).json({ error: "You cannot release a delivery token while a return is in progress" });
    }
    if (["requested", "approved"].includes(item.cancellation_status)) {
      return res.status(409).json({ error: "You cannot confirm receipt while cancellation is pending or approved" });
    }
    if (!["shipped", "delivered"].includes(item.fulfillment_status)) {
      return res.status(400).json({ error: "Confirm delivery only after the item has been shipped and received" });
    }

    if (item.buyer_confirmed_at && item.delivery_token) {
      return res.json({ item, token: item.delivery_token });
    }

    const token = item.delivery_token || generateDeliveryTokenValue();
    const result = await pool.query(
      `UPDATE order_items
       SET buyer_confirmed_at = COALESCE(buyer_confirmed_at, NOW()),
           delivery_token = $1,
           delivery_token_generated_at = COALESCE(delivery_token_generated_at, NOW())
       WHERE id = $2
       RETURNING *`,
      [token, req.params.id]
    );
    createNotification(
      item.seller_id,
      "buyer_confirmed_delivery",
      `Buyer confirmed delivery for "${item.title}". Ask the buyer for the delivery token only after handoff, then upload delivery proof and enter the token.`
    );
    res.json({ item: result.rows[0], token });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/order-items/:id/request-cancellation", authenticate, async (req, res) => {
  try {
    return res.status(410).json({ error: "Item-level cancellation was replaced by the automatic whole-order refund with a 2% fee" });
    /* Legacy handler retained below for deployed-request compatibility. */
    const reason = String(req.body?.reason || "").trim();
    if (!reason) return res.status(400).json({ error: "Enter a reason for the cancellation request" });
    if (reason.length > 1000) return res.status(400).json({ error: "Cancellation reason is too long" });
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id, o.payment_status, o.is_disputed
       FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE oi.id = $1`,
      [req.params.id]
    );
    if (!existing.rows.length) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (Number(item.buyer_id) !== Number(req.user.id)) {
      return res.status(403).json({ error: "Only the buyer can request cancellation" });
    }
    if (item.payment_status !== "held") return res.status(409).json({ error: "This order can no longer be cancelled" });
    if (item.is_disputed || ["requested", "approved"].includes(item.return_status)) {
      return res.status(409).json({ error: "Cancellation is unavailable while a dispute or return is active" });
    }
    if (item.fulfillment_status === "delivered" || item.buyer_confirmed_at || item.delivery_token_sent_at || item.delivery_token_redeemed_at) {
      return res.status(409).json({ error: "Cancellation is allowed only before you receive the order or send its delivery token" });
    }
    if (["cancelled", "returned"].includes(item.fulfillment_status)) {
      return res.status(409).json({ error: "This item is already cancelled or returned" });
    }
    if (item.cancellation_status === "requested" || item.cancellation_status === "approved") {
      return res.status(409).json({ error: "A cancellation request already exists for this item" });
    }
    const result = await pool.query(
      `UPDATE order_items SET cancellation_status = 'requested', cancellation_reason = $1,
       cancellation_requested_at = NOW(), cancellation_responded_at = NULL
       WHERE id = $2 AND fulfillment_status NOT IN ('delivered', 'cancelled', 'returned')
         AND buyer_confirmed_at IS NULL AND delivery_token_sent_at IS NULL AND delivery_token_redeemed_at IS NULL
         AND COALESCE(cancellation_status, '') NOT IN ('requested', 'approved')
       RETURNING *`,
      [reason, item.id]
    );
    if (!result.rows.length) return res.status(409).json({ error: "Cancellation is allowed only before you receive the order or send its delivery token" });
    createNotification(item.seller_id, "cancellation_requested", `Buyer requested cancellation for order #${item.order_id}: ${item.title}`);
    res.json({ item: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/order-items/:id/cancellation-response", authenticate, async (req, res) => {
  try {
    const decision = String(req.body?.decision || "");
    if (!["approved", "denied"].includes(decision)) {
      return res.status(400).json({ error: "Decision must be approved or denied" });
    }
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id, o.payment_status
       FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE oi.id = $1`,
      [req.params.id]
    );
    if (!existing.rows.length) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    const isSeller = Number(item.seller_id) === Number(req.user.id);
    if (!isSeller && !hasPermission(req.user, "order_management")) {
      return res.status(403).json({ error: "Only the seller or Order Admin can answer this cancellation request" });
    }
    if (item.cancellation_status !== "requested") {
      return res.status(409).json({ error: "There is no pending cancellation request for this item" });
    }
    if (decision === "approved" && (item.fulfillment_status === "delivered" || item.buyer_confirmed_at || item.delivery_token_sent_at || item.delivery_token_redeemed_at)) {
      return res.status(409).json({ error: "This cancellation cannot be approved because the buyer has received the order or sent the delivery token" });
    }
    const result = await pool.query(
      `UPDATE order_items SET cancellation_status = $1, cancellation_responded_at = NOW(),
       fulfillment_status = CASE WHEN $1 = 'approved' THEN 'cancelled' ELSE fulfillment_status END,
       delivery_token = CASE WHEN $1 = 'approved' THEN NULL ELSE delivery_token END
       WHERE id = $2 AND cancellation_status = 'requested'
         AND ($1 = 'denied' OR (fulfillment_status <> 'delivered' AND buyer_confirmed_at IS NULL
           AND delivery_token_sent_at IS NULL AND delivery_token_redeemed_at IS NULL))
       RETURNING *`,
      [decision, item.id]
    );
    if (!result.rows.length) return res.status(409).json({ error: "This cancellation can no longer be approved" });
    createNotification(item.buyer_id, "cancellation_response", `Your cancellation request for "${item.title}" was ${decision}.`);
    if (decision === "approved") {
      await pool.query(
        `INSERT INTO notifications (user_id, type, message)
         SELECT id, 'cancellation_refund_review', $1 FROM users
         WHERE is_admin = true AND admin_role IN ('super_admin', 'finance')`,
        [`Cancellation approved for order #${item.order_id}, item #${item.id}. Review the buyer refund.`]
      ).catch((notifyErr) => console.error("Failed to notify finance about approved cancellation:", notifyErr.message));
    }
    res.json({ item: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/order-items/:id/request-return", authenticate, async (req, res) => {
  try {
    return res.status(410).json({ error: "Item-level returns were replaced by the automatic whole-order refund available before token handoff" });
    /* Legacy handler retained below for deployed-request compatibility. */
    const { reason, note, evidenceUrls } = req.body;
    if (!reason) return res.status(400).json({ error: "Pick a reason for the return" });
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id, o.payment_status
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can request a return on this item" });
    }
    if (item.payment_status !== "held") {
      return res.status(409).json({ error: "A return can no longer be opened because seller payment has already been released" });
    }
    if (item.delivery_token_sent_at || item.delivery_token_redeemed_at) {
      return res.status(409).json({ error: "Returns and refunds are permanently closed because the delivery token was sent to the seller" });
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
    sendInternalError(res, err);
  }
});

app.patch("/order-items/:id/return-response", authenticate, async (req, res) => {
  try {
    const { decision } = req.body;
    if (!["approved", "denied"].includes(decision)) {
      return res.status(400).json({ error: "Invalid decision" });
    }
    const existing = await pool.query("SELECT * FROM order_items WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.seller_id !== req.user.id && !hasPermission(req.user, "dispute_resolution")) {
      return res.status(403).json({ error: "You can only respond to returns on your own items" });
    }
    if (item.return_status !== "requested") {
      return res.status(400).json({ error: "This item doesn't have a pending return request" });
    }
    const result =
      decision === "approved"
        ? await pool.query(
            `UPDATE order_items SET return_status = 'approved', fulfillment_status = 'returned', live_location_enabled = FALSE, live_location_expires_at = NULL WHERE id = $1 RETURNING *`,
            [req.params.id]
          )
        : await pool.query(`UPDATE order_items SET return_status = 'denied' WHERE id = $1 RETURNING *`, [req.params.id]);
    if (item.seller_id !== req.user.id) {
      logAdminAction(req.user.id, "return_decided", `${decision === "approved" ? "Approved" : "Denied"} return on item "${item.title}"`);
    }
    res.json({ item: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

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
    sendInternalError(res, err);
  }
});

app.post("/order-items/:id/generate-delivery-token", authenticate, async (req, res) => {
  try {
    const existing = await pool.query(
      `SELECT oi.*, o.buyer_id, o.payment_status, o.is_disputed
       FROM order_items oi JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer can access a delivery code for this item" });
    }
    if (item.payment_status !== "held") {
      return res.status(400).json({ error: "This order is no longer awaiting delivery confirmation" });
    }
    if (item.is_disputed || ["requested", "approved"].includes(item.return_status)) {
      return res.status(409).json({ error: "The delivery token is unavailable while a dispute or return is active" });
    }
    if (item.delivery_token) return res.json({ token: item.delivery_token });

    // Recovery path only: if a paid buyer's token is missing because of a
    // legacy order or interrupted response, create a fresh one immediately.
    const token = generateDeliveryTokenValue();
    await pool.query(
      "UPDATE order_items SET delivery_token = $1, delivery_token_generated_at = NOW() WHERE id = $2",
      [token, req.params.id]
    );
    res.json({ token });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/order-items/:id/redeem-delivery-token", authenticate, codeRateLimit, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Enter the code the buyer gave you" });
    const existing = await pool.query(
      `SELECT oi.*, o.payment_status, o.is_disputed
       FROM order_items oi
       JOIN orders o ON oi.order_id = o.id
       WHERE oi.id = $1`,
      [req.params.id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const item = existing.rows[0];
    if (item.seller_id !== req.user.id) {
      return res.status(403).json({ error: "Only the seller for this item can redeem the buyer's delivery code" });
    }
    if (item.payment_status !== "held") {
      return res.status(400).json({ error: "This order's payment is not currently being held" });
    }
    if (item.fulfillment_status !== "delivered") {
      return res.status(409).json({ error: "Mark the item delivered before confirming delivery" });
    }
    if (item.is_disputed) {
      return res.status(409).json({ error: "Payment is locked because this order has an active dispute" });
    }
    if (["requested", "approved"].includes(item.return_status)) {
      return res.status(409).json({ error: "Payment is locked because a return is in progress" });
    }
    if (["requested", "approved"].includes(item.cancellation_status)) {
      return res.status(409).json({ error: "Payment is locked because a cancellation is pending or approved" });
    }
    if (!item.proof_of_delivery_url) {
      return res.status(400).json({ error: "Upload a delivery picture before entering the buyer's code" });
    }
    if (!item.delivery_token) {
      return res.status(400).json({ error: "No active delivery code exists for this item" });
    }
    if (item.delivery_token !== String(token).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    const { item: updatedItem, order } = await markItemReceivedAndMaybeRelease(req.params.id);
    res.json({ item: updatedItem, order });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/checkout/single-item-payment", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, (req, res) => {
  return res.status(410).json({
    error: "Legacy single-item payment is disabled. Use the protected Paystack checkout flow.",
    code: "LEGACY_PAYMENT_DISABLED",
  });
});

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
      try {
        const intent = await loadCheckoutIntent(event.data.reference);
        assertPaystackMatchesCheckoutIntent(intent, event.data);
        await finalizeOrderFromPaystackCharge(event.data.reference, event.data);
      } catch (err) {
        if (event.data?.reference) {
          await markCheckoutIntent(event.data.reference, "integrity_failed", err.message).catch(() => {});
        }
        console.error("Webhook order finalization blocked:", err.message);
      }
    }

    if (["transfer.success", "transfer.failed", "transfer.reversed"].includes(event.event)) {
      const data = event.data || {};
      const reference = String(data.reference || "");
      const transferCode = data.transfer_code || null;
      const payoutResult = await pool.query(
        `SELECT * FROM seller_payouts
         WHERE paystack_reference = $1 OR ($2::text IS NOT NULL AND paystack_transfer_code = $2)
         LIMIT 1`,
        [reference, transferCode]
      );
      if (payoutResult.rows.length) {
        const payout = payoutResult.rows[0];
        if (event.event === "transfer.success") {
          await pool.query(
            `UPDATE seller_payouts SET status = 'paid', paystack_transfer_code = COALESCE($1, paystack_transfer_code),
               completed_at = NOW(), failure_reason = NULL, updated_at = NOW() WHERE id = $2`,
            [transferCode, payout.id]
          );
          createNotification(payout.seller_id, "payout_completed", `Paystack paid ${formatMoneyServer(payout.amount)} to your bank for order #${payout.order_id}.`);
        } else if (event.event === "transfer.failed") {
          await pool.query(
            `UPDATE seller_payouts SET status = 'failed', paystack_transfer_code = COALESCE($1, paystack_transfer_code),
               failure_reason = $2, updated_at = NOW() WHERE id = $3`,
            [transferCode, data.reason || "Paystack reported that the transfer failed", payout.id]
          );
          createNotification(payout.seller_id, "payout_failed", `Your payout for order #${payout.order_id} failed. Stallyard support will review it.`);
        } else {
          await pool.query(
            `UPDATE seller_payouts SET status = 'reversed', paystack_transfer_code = COALESCE($1, paystack_transfer_code),
               reversed_at = NOW(), failure_reason = $2, updated_at = NOW() WHERE id = $3`,
            [transferCode, data.reason || "Paystack reversed the transfer", payout.id]
          );
          createNotification(payout.seller_id, "payout_reversed", `Paystack reversed your payout for order #${payout.order_id}. The amount is protected while support reviews it.`);
        }
      }
    }

    if (event.event && event.event.startsWith("refund.")) {
      const data = event.data || {};
      const transactionReference = data.transaction_reference || data.transaction?.reference || null;
      if (transactionReference) {
        try {
          const orderResult = await pool.query(
            "SELECT id, buyer_id, payment_status, refund_previous_payment_status, refund_type, refund_amount, cancellation_fee, buyer_exit_type, currency FROM orders WHERE paystack_reference = $1",
            [transactionReference]
          );
          if (orderResult.rows.length) {
            const order = orderResult.rows[0];
            const refundStatus = data.status || event.event.replace("refund.", "");

            if (event.event === "refund.processed") {
              const isPartialRefund = order.refund_type === "partial";
              await pool.query(
                `UPDATE orders SET
                   payment_status = $1,
                   refund_status = 'processed',
                   paystack_refund_id = COALESCE($2, paystack_refund_id),
                   refunded_at = NOW(),
                   refund_failure_reason = NULL
                 WHERE id = $3`,
                [isPartialRefund ? "released" : "refunded", data.id || null, order.id]
              );
              if (order.refund_type === "buyer_cancellation") {
                await pool.query(
                  `UPDATE order_items SET
                     fulfillment_status = CASE WHEN $1 = 'return_refund' THEN 'returned' ELSE 'cancelled' END,
                     cancellation_status = 'approved', cancellation_responded_at = NOW(),
                     delivery_token = NULL, delivery_token_generated_at = NULL,
                     live_location_enabled = FALSE, live_location_expires_at = NULL
                   WHERE order_id = $2 AND delivery_token_sent_at IS NULL AND delivery_token_redeemed_at IS NULL`,
                  [order.buyer_exit_type, order.id]
                );
              }

              // Resolve only the matching financial outcome after Paystack
              // confirms the money movement. For partial refunds the remaining
              // seller proceeds are released immediately; computeAvailableBalance
              // subtracts the processed partial-refund amount from that order.
              const resolvedCases = await pool.query(
                `UPDATE dispute_cases SET
                   status = 'resolved', resolved_at = NOW(), updated_at = NOW()
                 WHERE order_id = $1 AND status <> 'resolved' AND resolution = $2
                 RETURNING id`,
                [order.id, isPartialRefund ? "partial_refund" : "buyer_refund"]
              );
              if (resolvedCases.rows.length) {
                const remaining = await pool.query(
                  "SELECT COUNT(*)::int AS count FROM dispute_cases WHERE order_id = $1 AND status <> 'resolved'",
                  [order.id]
                );
                if ((remaining.rows[0]?.count || 0) === 0) {
                  await pool.query("UPDATE orders SET is_disputed = false WHERE id = $1", [order.id]);
                }
                for (const row of resolvedCases.rows) {
                  logAdminAction(null, "dispute_auto_resolved_after_refund", `Resolved dispute #${row.id} after Paystack processed refund for order #${order.id}`);
                }
              }
              createNotification(order.buyer_id, "refund_processed", order.refund_type === "buyer_cancellation"
                ? `Your refund of ${formatMoneyServer(order.refund_amount || 0, order.currency)} for order #${order.id} has been processed after the ${formatMoneyServer(order.cancellation_fee || 0, order.currency)} cancellation fee.`
                : isPartialRefund
                ? `Your partial refund of ${formatMoneyServer(order.refund_amount || 0, order.currency)} for order #${order.id} has been processed.`
                : `Your refund for order #${order.id} has been processed.`);
            } else if (event.event === "refund.failed") {
              await pool.query(
                `UPDATE orders SET
                   payment_status = COALESCE(refund_previous_payment_status, 'held'),
                   refund_status = 'failed',
                   paystack_refund_id = COALESCE($1, paystack_refund_id),
                   refund_failure_reason = $2
                 WHERE id = $3`,
                [data.id || null, data.reason || "Paystack reported that the refund failed", order.id]
              );
              createNotification(order.buyer_id, "refund_failed", `The refund for order #${order.id} could not be completed. Stallyard support will review it.`);
            } else {
              await pool.query(
                `UPDATE orders SET
                   payment_status = 'refund_pending',
                   refund_status = $1,
                   paystack_refund_id = COALESCE($2, paystack_refund_id),
                   refund_failure_reason = $3
                 WHERE id = $4`,
                [refundStatus, data.id || null, event.event === "refund.needs-attention" ? (data.reason || "Customer bank details are required") : null, order.id]
              );
            }
          }
        } catch (err) {
          console.error("Refund webhook handling error:", err.message);
        }
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err.message);
    res.sendStatus(500);
  }
});

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
    sendInternalError(res, err);
  }
});

function bankNameTokens(value) {
  return String(value || "").toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter((token) => token.length > 1);
}

function bankOwnerMatchesIdentity(accountName, identityNames) {
  const accountTokens = new Set(bankNameTokens(accountName));
  return identityNames.filter(Boolean).some((identityName) => {
    const identityTokens = [...new Set(bankNameTokens(identityName))];
    if (!identityTokens.length) return false;
    const common = identityTokens.filter((token) => accountTokens.has(token)).length;
    return identityTokens.length === 1 ? common === 1 : common >= 2;
  });
}

async function resolvePaystackBankAccount(userId, bankCode, accountNumber) {
  const normalizedCode = String(bankCode || "").trim();
  const normalizedNumber = String(accountNumber || "").replace(/\D/g, "");
  if (!normalizedCode || !/^\d{10}$/.test(normalizedNumber)) return { error: "Enter a valid 10-digit Nigerian account number", status: 400 };
  const paystackRes = await fetch(`https://api.paystack.co/bank/resolve?account_number=${encodeURIComponent(normalizedNumber)}&bank_code=${encodeURIComponent(normalizedCode)}`, {
    headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
  });
  const paystackData = await paystackRes.json().catch(() => ({}));
  if (!paystackRes.ok || !paystackData.status || !paystackData.data?.account_name) {
    return { error: paystackData.message || "Paystack could not verify that bank account", status: 400 };
  }
  const identityResult = await pool.query(
    `SELECT u.first_name,u.last_name,u.other_name,u.display_name,
            (SELECT legal_name FROM casual_seller_applications WHERE user_id=u.id AND status='approved' ORDER BY approved_at DESC LIMIT 1) AS verified_legal_name
       FROM users u WHERE u.id=$1`, [userId]
  );
  if (!identityResult.rows.length) return { error: "User not found", status: 404 };
  const identity = identityResult.rows[0];
  const identityNames = [identity.verified_legal_name, `${identity.last_name || ""} ${identity.first_name || ""} ${identity.other_name || ""}`.trim(), identity.display_name];
  const accountName = String(paystackData.data.account_name).trim();
  return {
    accountName,
    accountNumber: String(paystackData.data.account_number || normalizedNumber),
    bankCode: normalizedCode,
    nameMatches: bankOwnerMatchesIdentity(accountName, identityNames),
  };
}

app.post("/paystack/resolve-account", authenticate, rejectAdminMarketplaceUse, bankAccountResolveRateLimit, async (req, res) => {
  try {
    const result = await resolvePaystackBankAccount(req.user.id, req.body?.bankCode, req.body?.accountNumber);
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json({ accountName: result.accountName, accountNumber: result.accountNumber, bankCode: result.bankCode, nameMatches: result.nameMatches });
  } catch (err) { sendInternalError(res, err, "bank account resolution"); }
});

async function verifyAndSaveBankDetails(userId, bankCode, accountNumber, expectedAccountName = null) {
  const userResult = await pool.query("SELECT display_name FROM users WHERE id = $1", [userId]);
  if (userResult.rows.length === 0) {
    return { error: "User not found", status: 404 };
  }
  const resolved = await resolvePaystackBankAccount(userId, bankCode, accountNumber);
  if (resolved.error) return resolved;
  if (!resolved.nameMatches) return { error: "The bank account owner name does not match your verified Stallyard identity", status: 400 };
  if (expectedAccountName && resolved.accountName.toLowerCase() !== String(expectedAccountName).trim().toLowerCase()) {
    return { error: "The bank account owner name changed during confirmation — start again", status: 409 };
  }
  const recipientRes = await fetch("https://api.paystack.co/transferrecipient", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      type: "nuban",
      name: resolved.accountName,
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
    "UPDATE users SET bank_code = $1, account_number = $2, paystack_recipient_code = $3, bank_account_name = $4 WHERE id = $5",
    [encryptField(bankCode), encryptField(accountNumber), encryptField(recipientData.data.recipient_code), encryptField(resolved.accountName), userId]
  );
  return { recipientCode: recipientData.data.recipient_code, accountName: resolved.accountName };
}

app.post(
  "/sellers/bank-details",
  authenticate,
  bankChangeSendIpRateLimit,
  bankChangeSendUserRateLimit,
  async (req, res) => {
  try {
    const { userId, bankCode, accountNumber, adminOverrideReason, confirmedAccountName } = req.body;

    if (!userId || !bankCode || !accountNumber) {
      return res.status(400).json({ error: "Missing userId, bankCode, or accountNumber" });
    }

    const targetUserId = Number(userId);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      return res.status(400).json({ error: "Invalid seller userId" });
    }

    const isOwnBankAccount = req.user.id === targetUserId;
    const isAdminOverride = !isOwnBankAccount;

    // Changing where ANOTHER seller's payout money goes is a finance action.
    // Do not treat every admin as trusted for this: listing moderators,
    // seller-verification staff, support staff, etc. must never be able to
    // redirect a seller's payouts.
    if (isAdminOverride && !hasPermission(req.user, "finance")) {
      return res.status(403).json({ error: "Finance Admin or Super Admin access is required to change another seller's bank details" });
    }

    if (isAdminOverride && String(adminOverrideReason || "").trim().length < 10) {
      return res.status(400).json({ error: "Enter an admin override reason of at least 10 characters" });
    }

    const existing = await pool.query(
      "SELECT account_number, email, username, display_name, is_admin, is_approved FROM users WHERE id = $1",
      [targetUserId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "User not found" });

    // Admin override is only for marketplace sellers, never another staff
    // account. Staff/admin identities are deliberately separated from seller
    // identities in Stallyard.
    if (isAdminOverride && existing.rows[0].is_admin) {
      return res.status(400).json({ error: "Admin/staff accounts cannot receive seller payout bank overrides" });
    }
    if (isAdminOverride && !existing.rows[0].is_approved) {
      return res.status(400).json({ error: "Bank overrides are only available for approved sellers" });
    }

    const hadAccountBefore = !!existing.rows[0].account_number;

    if (isOwnBankAccount && !String(confirmedAccountName || "").trim()) {
      return res.status(400).json({ error: "Resolve and confirm the Paystack account owner name first" });
    }

    if (!hadAccountBefore || isAdminOverride) {
      const result = await verifyAndSaveBankDetails(targetUserId, bankCode, accountNumber, isOwnBankAccount ? confirmedAccountName : null);
      if (result.error) return res.status(result.status).json({ error: result.error });

      if (isAdminOverride) {
        logAdminAction(
          req.user.id,
          "seller_bank_details_overridden",
          `Changed payout bank details for seller ${existing.rows[0].username}; reason: ${String(adminOverrideReason).trim()}`
        );
        await createNotification(
          targetUserId,
          "bank_details_changed",
          "Your Stallyard payout bank details were changed by an authorized finance administrator. If you did not expect this, contact Stallyard support immediately."
        );
      }

      return res.json({ success: true, recipientCode: result.recipientCode, accountName: result.accountName });
    }

    const email = existing.rows[0].email;
    if (!email) {
      return res.status(400).json({ error: "No email on file to confirm this change — contact support" });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Bank-change confirmation isn't configured yet" });
    }

    const resolvedAccount = await resolvePaystackBankAccount(targetUserId, bankCode, accountNumber);
    if (resolvedAccount.error) return res.status(resolvedAccount.status).json({ error: resolvedAccount.error });
    if (isOwnBankAccount && resolvedAccount.accountName.toLowerCase() !== String(confirmedAccountName).trim().toLowerCase()) {
      return res.status(409).json({ error: "The Paystack account owner name changed — resolve and confirm it again" });
    }
    if (!resolvedAccount.nameMatches && !isAdminOverride) {
      return res.status(400).json({ error: "The bank account owner name does not match your verified Stallyard identity" });
    }

    const existingPendingChange = await getSecurityState("bank-change", req.user.id);
    if (existingPendingChange && Date.now() - existingPendingChange.sentAt < BANK_CHANGE_RESEND_COOLDOWN_MS) {
      const retryAfterSeconds = Math.max(1, Math.ceil((BANK_CHANGE_RESEND_COOLDOWN_MS - (Date.now() - existingPendingChange.sentAt)) / 1000));
      res.setHeader("Retry-After", String(retryAfterSeconds));
      return res.status(429).json({
        error: `A bank-change code was just sent — wait ${retryAfterSeconds} seconds before requesting another one.`,
        retryAfterSeconds,
      });
    }

    const code = generateSecurityCode();
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
    await setSecurityState("bank-change", req.user.id, {
      code,
      sentAt: Date.now(),
      bankCode,
      accountNumber,
      accountName: resolvedAccount.accountName,
      failedAttempts: 0,
    }, BANK_CHANGE_CODE_TTL_MS);
    res.json({ confirmationRequired: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post(
  "/sellers/bank-details/confirm",
  authenticate,
  bankChangeConfirmRateLimit,
  async (req, res) => {
  try {
    const submittedCode = String(req.body?.code || "").trim();
    if (!/^\d{6}$/.test(submittedCode)) {
      return res.status(400).json({ error: "Enter the 6-digit code we emailed you" });
    }

    const pending = await getSecurityState("bank-change", req.user.id);
    if (!pending || Date.now() - pending.sentAt > BANK_CHANGE_CODE_TTL_MS) {
      await deleteSecurityState("bank-change", req.user.id);
      return res.status(400).json({ error: "That code has expired — start the change again" });
    }

    const expectedBuffer = Buffer.from(String(pending.code));
    const submittedBuffer = Buffer.from(submittedCode);
    const codeMatches = expectedBuffer.length === submittedBuffer.length &&
      crypto.timingSafeEqual(expectedBuffer, submittedBuffer);

    if (!codeMatches) {
      pending.failedAttempts = Number(pending.failedAttempts || 0) + 1;
      if (pending.failedAttempts >= BANK_CHANGE_MAX_CODE_ATTEMPTS) {
        await deleteSecurityState("bank-change", req.user.id);
        return res.status(429).json({
          error: "Too many incorrect bank-change codes — start the bank change again to receive a new code.",
        });
      }
      await setSecurityState("bank-change", req.user.id, pending, BANK_CHANGE_CODE_TTL_MS);
      return res.status(400).json({
        error: "That code doesn't match — check and try again",
        attemptsRemaining: BANK_CHANGE_MAX_CODE_ATTEMPTS - pending.failedAttempts,
      });
    }

    await deleteSecurityState("bank-change", req.user.id);
    const result = await verifyAndSaveBankDetails(req.user.id, pending.bankCode, pending.accountNumber, pending.accountName);
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json({ success: true, recipientCode: result.recipientCode, accountName: result.accountName });
  } catch (err) {
    sendInternalError(res, err);
  }
});

async function sendPaystackTransfer(recipientCode, amountInKobo, reason, reference = null) {
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
      ...(reference ? { reference } : {}),
    }),
  });
  return transferRes.json();
}

async function queueAutomaticSellerPayouts(orderId, onlySellerId = null) {
  const proceeds = await pool.query(
    `SELECT oi.seller_id,
       ROUND(SUM((oi.price * oi.qty) - (oi.price * oi.qty * o.commission_rate) + (oi.shipping_fee * oi.qty))::numeric, 2) AS amount
     FROM order_items oi JOIN orders o ON o.id = oi.order_id
     WHERE o.id = $1 AND o.payment_status IN ('held', 'released') AND COALESCE(o.is_disputed, false) = false
       AND ($2::int IS NULL OR oi.seller_id = $2)
       AND oi.fulfillment_status NOT IN ('cancelled', 'returned')
       AND NOT EXISTS (
         SELECT 1 FROM order_items pending
         WHERE pending.order_id = o.id AND pending.seller_id = oi.seller_id
           AND pending.fulfillment_status NOT IN ('cancelled', 'returned')
           AND (COALESCE(pending.proof_of_delivery_url, '') = '' OR pending.delivery_token_redeemed_at IS NULL
             OR pending.return_status IN ('requested', 'approved')
             OR pending.cancellation_status IN ('requested', 'approved'))
       )
     GROUP BY oi.seller_id`,
    [orderId, onlySellerId]
  );

  for (const row of proceeds.rows) {
    const sellerId = Number(row.seller_id);
    const amount = Number(row.amount);
    if (!(amount > 0)) continue;
    const reference = `STL-PAYOUT-${orderId}-${sellerId}`;
    const inserted = await pool.query(
      `INSERT INTO seller_payouts (order_id, seller_id, amount, currency, status, paystack_reference)
       VALUES ($1, $2, $3, 'NGN', 'queued', $4)
       ON CONFLICT (order_id, seller_id) DO NOTHING
       RETURNING *`,
      [orderId, sellerId, amount, reference]
    );
    if (!inserted.rows.length) continue;
    const payout = inserted.rows[0];
    const userResult = await pool.query("SELECT paystack_recipient_code FROM users WHERE id = $1", [sellerId]);
    const encryptedRecipient = userResult.rows[0]?.paystack_recipient_code;
    if (!encryptedRecipient) {
      await pool.query(
        "UPDATE seller_payouts SET status = 'needs_bank', failure_reason = 'Seller bank details are missing', updated_at = NOW() WHERE id = $1",
        [payout.id]
      );
      createNotification(sellerId, "payout_needs_bank", `Add verified bank details to receive your payout for order #${orderId}.`);
      continue;
    }
    try {
      await pool.query("UPDATE seller_payouts SET status = 'processing', initiated_at = NOW(), updated_at = NOW() WHERE id = $1", [payout.id]);
      const recipientCode = decryptFieldSafe(encryptedRecipient);
      const transferData = await sendPaystackTransfer(
        recipientCode,
        Math.round(amount * 100),
        `Stallyard order #${orderId} automatic seller payout`,
        reference
      );
      if (!transferData.status) {
        await pool.query(
          "UPDATE seller_payouts SET status = 'failed', failure_reason = $1, updated_at = NOW() WHERE id = $2",
          [transferData.message || "Paystack rejected the payout", payout.id]
        );
        createNotification(sellerId, "payout_failed", `Automatic payout for order #${orderId} could not be initiated. Support will review it.`);
        continue;
      }
      await pool.query(
        `UPDATE seller_payouts SET status = 'processing', paystack_transfer_code = $1,
           failure_reason = NULL, updated_at = NOW() WHERE id = $2`,
        [transferData.data?.transfer_code || null, payout.id]
      );
      createNotification(sellerId, "payout_processing", `Paystack is sending ${formatMoneyServer(amount)} to your bank for order #${orderId}.`);
    } catch (err) {
      await pool.query(
        "UPDATE seller_payouts SET status = 'request_unknown', failure_reason = $1, updated_at = NOW() WHERE id = $2",
        ["Could not confirm whether Paystack received the payout request. Support must verify before retrying.", payout.id]
      );
      console.error(`Automatic payout request uncertain for order #${orderId}, seller #${sellerId}:`, err.message);
    }
  }
}

app.get("/seller-payouts/mine", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM seller_payouts WHERE seller_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ payouts: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/seller-payouts/:id/retry", authenticate, requirePermission("finance"), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const locked = await client.query("SELECT * FROM seller_payouts WHERE id = $1 FOR UPDATE", [req.params.id]);
    if (!locked.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Seller payout not found" });
    }
    const payout = locked.rows[0];
    if (!["failed", "reversed", "needs_bank"].includes(payout.status)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Only confirmed failed, reversed, or bank-details-required payouts can be retried" });
    }
    const userResult = await client.query("SELECT paystack_recipient_code FROM users WHERE id = $1", [payout.seller_id]);
    const encryptedRecipient = userResult.rows[0]?.paystack_recipient_code;
    if (!encryptedRecipient) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "The seller must add verified bank details first" });
    }
    const retryReference = `STL-PAYOUT-${payout.order_id}-${payout.seller_id}-R${Date.now()}`;
    await client.query(
      `UPDATE seller_payouts SET status = 'processing', paystack_reference = $1,
         paystack_transfer_code = NULL, failure_reason = NULL, initiated_at = NOW(), updated_at = NOW()
       WHERE id = $2`,
      [retryReference, payout.id]
    );
    await client.query("COMMIT");

    try {
      const transferData = await sendPaystackTransfer(
        decryptFieldSafe(encryptedRecipient), Math.round(Number(payout.amount) * 100),
        `Stallyard order #${payout.order_id} payout retry`, retryReference
      );
      if (!transferData.status) {
        const failed = await pool.query(
          "UPDATE seller_payouts SET status = 'failed', failure_reason = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
          [transferData.message || "Paystack rejected the payout retry", payout.id]
        );
        return res.status(400).json({ error: transferData.message || "Paystack rejected the payout retry", payout: failed.rows[0] });
      }
      const updated = await pool.query(
        "UPDATE seller_payouts SET paystack_transfer_code = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
        [transferData.data?.transfer_code || null, payout.id]
      );
      logAdminAction(req.user.id, "seller_payout_retried", `Retried payout #${payout.id} for order #${payout.order_id}`);
      res.json({ payout: updated.rows[0] });
    } catch (err) {
      await pool.query(
        "UPDATE seller_payouts SET status = 'request_unknown', failure_reason = $1, updated_at = NOW() WHERE id = $2",
        ["Could not confirm whether Paystack received the retry. Verify in Paystack before another attempt.", payout.id]
      );
      return res.status(502).json({ error: "Payout retry status is uncertain. Verify it in Paystack before retrying again." });
    }
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.post("/sellers/payout", authenticate, requirePermission("finance"), async (req, res) => {
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

    const recipientCode = decryptFieldSafe(userResult.rows[0].paystack_recipient_code);
    const amountInKobo = Math.round(Number(amount) * 100);
    const transferData = await sendPaystackTransfer(recipientCode, amountInKobo, reason);

    if (!transferData.status) {
      return res.status(400).json({ error: transferData.message || "Payout failed" });
    }

    logAdminAction(req.user.id, "manual_payout", `Manually paid out $${amount} to user #${userId}${reason ? ` (${reason})` : ""}`);
    res.json({ success: true, transfer: transferData.data });
  } catch (err) {
    sendInternalError(res, err);
  }
});

async function computeAvailableBalance(client, sellerId) {
  const releasedResult = await client.query(
    `WITH seller_orders AS (
       SELECT o.id, o.refund_type, COALESCE(o.refund_amount, 0) AS refund_amount,
         SUM(CASE WHEN oi.fulfillment_status NOT IN ('cancelled', 'returned')
           THEN (oi.price * oi.qty) - (oi.price * oi.qty * o.commission_rate) + (oi.shipping_fee * oi.qty)
           ELSE 0 END) AS seller_proceeds
       FROM order_items oi
       JOIN orders o ON oi.order_id = o.id
       WHERE oi.seller_id = $1 AND o.payment_status = 'released'
       GROUP BY o.id, o.refund_type, o.refund_amount
     )
     SELECT COALESCE(SUM(
       seller_proceeds - CASE WHEN refund_type = 'partial' THEN refund_amount ELSE 0 END
     ), 0) AS released_total
     FROM seller_orders`,
    [sellerId]
  );
  const reservedResult = await client.query(
    `SELECT
       COALESCE((SELECT SUM(amount) FROM withdrawals WHERE seller_id = $1 AND status IN ('processing', 'paid')), 0) +
       COALESCE((SELECT SUM(amount) FROM seller_payouts WHERE seller_id = $1 AND status IN ('queued', 'processing', 'request_unknown', 'paid')), 0)
       AS reserved`,
    [sellerId]
  );
  const released = Number(releasedResult.rows[0].released_total);
  const reserved = Number(reservedResult.rows[0].reserved);
  return Math.max(0, Math.round((released - reserved) * 100) / 100);
}

app.post("/withdrawals", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  const client = await pool.connect();
  try {
    const amount = Math.round(Number(req.body.amount) * 100) / 100;
    if (!(amount > 0)) {
      return res.status(400).json({ error: "Amount must be a positive number" });
    }

    await client.query("BEGIN");
    await client.query("SELECT id, paystack_recipient_code FROM users WHERE id = $1 FOR UPDATE", [req.user.id]);

    const available = await computeAvailableBalance(client, req.user.id);
    if (amount > available) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: `You can't withdraw more than your available balance of $${available.toFixed(2)}` });
    }

    const userResult = await client.query("SELECT paystack_recipient_code FROM users WHERE id = $1", [req.user.id]);
    const recipientCode = userResult.rows[0]?.paystack_recipient_code
      ? decryptFieldSafe(userResult.rows[0].paystack_recipient_code)
      : null;
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
    sendInternalError(res, err);
  } finally {
    client.release();
  }
});

app.get("/withdrawals/mine", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM withdrawals WHERE seller_id = $1 ORDER BY requested_at DESC",
      [req.user.id]
    );
    res.json({ withdrawals: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/withdrawals", authenticate, requirePermission("finance"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM withdrawals ORDER BY requested_at DESC");
    res.json({ withdrawals: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});


// Buyer risk dashboard. This is a human-review aid only: the score never automatically
// suspends, blocks, refunds, or otherwise penalizes a buyer.
app.get("/admin/buyer-risk", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const hasPaymentAttempts = await pool.query(`SELECT to_regclass('public.payment_attempts') AS name`);
    const paymentAttemptsReady = !!hasPaymentAttempts.rows[0]?.name;
    const paymentAttemptSelect = paymentAttemptsReady
      ? `(SELECT COUNT(*) FROM payment_attempts pa WHERE pa.user_id = u.id AND pa.status = 'failed') AS failed_payment_count,`
      : `0 AS failed_payment_count,`;

    const result = await pool.query(`
      SELECT
        u.id AS user_id,
        u.username,
        u.display_name,
        u.email,
        u.phone,
        u.is_suspended,
        u.is_email_verified,
        u.is_phone_verified,
        u.created_at AS joined_at,
        (SELECT MAX(lh.created_at) FROM login_history lh WHERE lh.user_id = u.id) AS last_login_at,
        (SELECT COUNT(*) FROM orders o WHERE o.buyer_id = u.id) AS order_count,
        (SELECT COUNT(*) FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE o.buyer_id = u.id) AS item_count,
        (SELECT COUNT(*) FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE o.buyer_id = u.id AND oi.fulfillment_status = 'delivered') AS completed_items,
        (SELECT COUNT(*) FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE o.buyer_id = u.id AND oi.fulfillment_status = 'cancelled') AS cancelled_items,
        (SELECT COUNT(*) FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE o.buyer_id = u.id AND oi.return_status IS NOT NULL) AS return_count,
        (SELECT COUNT(*) FROM dispute_cases dc JOIN orders o ON o.id = dc.order_id WHERE o.buyer_id = u.id) AS dispute_count,
        (SELECT COUNT(*) FROM dispute_cases dc JOIN orders o ON o.id = dc.order_id WHERE o.buyer_id = u.id AND dc.status <> 'resolved') AS open_disputes,
        (SELECT COUNT(*) FROM orders o WHERE o.buyer_id = u.id AND (o.refund_status IS NOT NULL OR o.payment_status = 'refunded')) AS refund_count,
        (SELECT COUNT(*) FROM account_reports ar WHERE ar.user_id = u.id) AS report_count,
        (SELECT COUNT(*) FROM account_reports ar WHERE ar.user_id = u.id AND ar.status = 'open') AS open_report_count,
        ${paymentAttemptSelect}
        (SELECT COALESCE(SUM(o.total), 0) FROM orders o WHERE o.buyer_id = u.id) AS lifetime_spend
      FROM users u
      WHERE u.is_admin = false
        AND EXISTS (SELECT 1 FROM orders o WHERE o.buyer_id = u.id)
      ORDER BY u.display_name ASC, u.username ASC
    `);

    const buyers = result.rows.map((row) => {
      const orderCount = Number(row.order_count) || 0;
      const itemCount = Number(row.item_count) || 0;
      const completedItems = Number(row.completed_items) || 0;
      const cancelledItems = Number(row.cancelled_items) || 0;
      const returnCount = Number(row.return_count) || 0;
      const disputeCount = Number(row.dispute_count) || 0;
      const openDisputes = Number(row.open_disputes) || 0;
      const refundCount = Number(row.refund_count) || 0;
      const reportCount = Number(row.report_count) || 0;
      const openReportCount = Number(row.open_report_count) || 0;
      const failedPaymentCount = Number(row.failed_payment_count) || 0;
      const returnRate = itemCount ? (returnCount / itemCount) * 100 : 0;
      const cancellationRate = itemCount ? (cancelledItems / itemCount) * 100 : 0;
      const disputeRate = orderCount ? (disputeCount / orderCount) * 100 : 0;

      let score = 0;
      const signals = [];
      if (openDisputes > 0) {
        score += Math.min(30, openDisputes * 12);
        signals.push({ severity: "high", message: `${openDisputes} unresolved dispute${openDisputes === 1 ? "" : "s"}` });
      }
      if (openReportCount > 0) {
        score += Math.min(30, openReportCount * 15);
        signals.push({ severity: "high", message: `${openReportCount} open suspicious-activity report${openReportCount === 1 ? "" : "s"}` });
      } else if (reportCount > 0) {
        score += Math.min(12, reportCount * 4);
        signals.push({ severity: "medium", message: `${reportCount} suspicious-activity report${reportCount === 1 ? "" : "s"} on record` });
      }
      if (returnRate > 30 && itemCount >= 3) {
        score += 20;
        signals.push({ severity: "high", message: `High return rate (${returnRate.toFixed(1)}%)` });
      } else if (returnRate > 15 && itemCount >= 3) {
        score += 10;
        signals.push({ severity: "medium", message: `Elevated return rate (${returnRate.toFixed(1)}%)` });
      }
      if (disputeRate > 25 && orderCount >= 3) {
        score += 20;
        signals.push({ severity: "high", message: `High dispute rate (${disputeRate.toFixed(1)}%)` });
      } else if (disputeRate > 10 && orderCount >= 3) {
        score += 10;
        signals.push({ severity: "medium", message: `Elevated dispute rate (${disputeRate.toFixed(1)}%)` });
      }
      if (cancellationRate > 35 && itemCount >= 3) {
        score += 10;
        signals.push({ severity: "medium", message: `High cancellation rate (${cancellationRate.toFixed(1)}%)` });
      }
      if (failedPaymentCount >= 5) {
        score += 15;
        signals.push({ severity: "medium", message: `${failedPaymentCount} failed payment attempts` });
      } else if (failedPaymentCount >= 2) {
        score += 6;
        signals.push({ severity: "low", message: `${failedPaymentCount} failed payment attempts` });
      }
      if (refundCount >= 3 && orderCount >= 3) {
        score += 10;
        signals.push({ severity: "medium", message: `${refundCount} refunded order${refundCount === 1 ? "" : "s"}` });
      }
      if (row.is_suspended) {
        score = Math.max(score, 80);
        signals.push({ severity: "high", message: "Account is currently suspended" });
      }

      score = Math.min(100, Math.round(score));
      const riskBand = score >= 60 ? "high" : score >= 25 ? "watch" : "low";
      return {
        userId: row.user_id,
        username: row.username,
        displayName: row.display_name,
        email: row.email,
        phone: row.phone,
        isSuspended: !!row.is_suspended,
        isEmailVerified: !!row.is_email_verified,
        isPhoneVerified: !!row.is_phone_verified,
        joinedAt: row.joined_at,
        lastLoginAt: row.last_login_at,
        orderCount,
        itemCount,
        completedItems,
        cancelledItems,
        returnCount,
        returnRate,
        cancellationRate,
        disputeCount,
        openDisputes,
        disputeRate,
        refundCount,
        reportCount,
        openReportCount,
        failedPaymentCount,
        lifetimeSpend: Number(row.lifetime_spend) || 0,
        riskScore: score,
        riskBand,
        riskSignals: signals,
      };
    });

    res.json({
      buyers,
      paymentAttemptTrackingReady: paymentAttemptsReady,
      summary: {
        buyerCount: buyers.length,
        highRisk: buyers.filter((b) => b.riskBand === "high").length,
        watch: buyers.filter((b) => b.riskBand === "watch").length,
        openReports: buyers.reduce((sum, b) => sum + b.openReportCount, 0),
      },
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

// Seller performance dashboard. These are deterministic operational indicators
// for human review, not an automated enforcement system. No seller is suspended,
// rejected, or otherwise penalized from this score alone.
app.get("/admin/seller-performance", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id AS user_id,
        u.username,
        u.display_name,
        u.email,
        u.phone,
        u.is_suspended,
        u.verification_status,
        u.created_at AS joined_at,
        (SELECT MAX(lh.created_at) FROM login_history lh WHERE lh.user_id = u.id) AS last_login_at,
        (SELECT COUNT(DISTINCT oi.order_id) FROM order_items oi WHERE oi.seller_id = u.id) AS order_count,
        (SELECT COUNT(*) FROM order_items oi WHERE oi.seller_id = u.id) AS item_count,
        (SELECT COUNT(*) FROM order_items oi WHERE oi.seller_id = u.id AND oi.fulfillment_status = 'delivered') AS completed_deliveries,
        (SELECT COUNT(*) FROM order_items oi WHERE oi.seller_id = u.id AND oi.fulfillment_status = 'cancelled') AS cancelled_count,
        (SELECT COUNT(*) FROM order_items oi WHERE oi.seller_id = u.id AND oi.fulfillment_status = 'returned') AS returned_count,
        (SELECT COUNT(*) FROM order_items oi WHERE oi.seller_id = u.id AND oi.ship_reminder_sent_at IS NOT NULL) AS ship_reminder_count,
        (SELECT COUNT(*) FROM order_items oi WHERE oi.seller_id = u.id AND oi.fulfillment_status = 'new' AND oi.created_at < NOW() - INTERVAL '24 hours') AS active_ship_reminders,
        (SELECT AVG(EXTRACT(EPOCH FROM (oi.shipped_at - oi.created_at)) / 3600.0)
           FROM order_items oi WHERE oi.seller_id = u.id AND oi.shipped_at IS NOT NULL AND oi.shipped_at >= oi.created_at) AS average_hours_to_ship,
        (SELECT COALESCE(SUM((oi.price * oi.qty) + (oi.shipping_fee * oi.qty)), 0)
           FROM order_items oi WHERE oi.seller_id = u.id AND oi.fulfillment_status NOT IN ('cancelled', 'returned')) AS gross_merchandise,
        (SELECT COUNT(*) FROM reviews r WHERE r.seller_id = u.id) AS review_count,
        (SELECT COALESCE(AVG(r.rating), 0) FROM reviews r WHERE r.seller_id = u.id) AS average_rating,
        (SELECT COUNT(*) FROM seller_warnings sw WHERE sw.user_id = u.id) AS warning_count,
        (SELECT COUNT(DISTINCT dc.id)
           FROM dispute_cases dc
           WHERE EXISTS (SELECT 1 FROM order_items oi WHERE oi.order_id = dc.order_id AND oi.seller_id = u.id)) AS dispute_count,
        (SELECT COUNT(DISTINCT dc.id)
           FROM dispute_cases dc
           WHERE dc.status <> 'resolved'
             AND EXISTS (SELECT 1 FROM order_items oi WHERE oi.order_id = dc.order_id AND oi.seller_id = u.id)) AS open_disputes,
        (SELECT COALESCE(SUM(amount), 0) FROM withdrawals w WHERE w.seller_id = u.id AND w.status = 'failed') AS failed_withdrawal_amount
      FROM users u
      WHERE u.is_admin = false
        AND (
          u.is_approved = true
          OR u.has_applied_to_sell = true
          OR EXISTS (SELECT 1 FROM order_items oi WHERE oi.seller_id = u.id)
        )
      ORDER BY u.display_name ASC, u.username ASC
    `);

    const sellers = [];
    for (const row of result.rows) {
      const orderCount = Number(row.order_count) || 0;
      const itemCount = Number(row.item_count) || 0;
      const completedDeliveries = Number(row.completed_deliveries) || 0;
      const cancelledCount = Number(row.cancelled_count) || 0;
      const returnedCount = Number(row.returned_count) || 0;
      const shipReminderCount = Number(row.ship_reminder_count) || 0;
      const activeShipReminders = Number(row.active_ship_reminders) || 0;
      const disputeCount = Number(row.dispute_count) || 0;
      const openDisputes = Number(row.open_disputes) || 0;
      const warningCount = Number(row.warning_count) || 0;
      const reviewCount = Number(row.review_count) || 0;
      const averageRating = Number(row.average_rating) || 0;
      const returnRate = itemCount ? (returnedCount / itemCount) * 100 : 0;
      const cancelRate = itemCount ? (cancelledCount / itemCount) * 100 : 0;
      const reminderRate = itemCount ? (shipReminderCount / itemCount) * 100 : 0;

      let score = 100;
      const signals = [];
      if (openDisputes > 0) {
        const deduction = Math.min(36, openDisputes * 12);
        score -= deduction;
        signals.push({ severity: "high", message: `${openDisputes} unresolved dispute${openDisputes === 1 ? "" : "s"}` });
      }
      if (warningCount > 0) {
        score -= Math.min(24, warningCount * 8);
        signals.push({ severity: warningCount >= 2 ? "high" : "medium", message: `${warningCount} admin warning${warningCount === 1 ? "" : "s"} on record` });
      }
      if (returnRate > 20) {
        score -= 20;
        signals.push({ severity: "high", message: `High return rate (${returnRate.toFixed(1)}%)` });
      } else if (returnRate > 10) {
        score -= 10;
        signals.push({ severity: "medium", message: `Elevated return rate (${returnRate.toFixed(1)}%)` });
      } else if (returnRate > 5) {
        score -= 5;
        signals.push({ severity: "low", message: `Return rate is ${returnRate.toFixed(1)}%` });
      }
      if (cancelRate > 20) {
        score -= 15;
        signals.push({ severity: "high", message: `High cancellation rate (${cancelRate.toFixed(1)}%)` });
      } else if (cancelRate > 10) {
        score -= 8;
        signals.push({ severity: "medium", message: `Elevated cancellation rate (${cancelRate.toFixed(1)}%)` });
      } else if (cancelRate > 5) {
        score -= 4;
        signals.push({ severity: "low", message: `Cancellation rate is ${cancelRate.toFixed(1)}%` });
      }
      if (reminderRate > 25) {
        score -= 15;
        signals.push({ severity: "medium", message: `${reminderRate.toFixed(1)}% of items triggered a 24-hour shipping reminder` });
      } else if (reminderRate > 10) {
        score -= 8;
        signals.push({ severity: "low", message: `${reminderRate.toFixed(1)}% of items triggered a 24-hour shipping reminder` });
      }
      if (reviewCount >= 3 && averageRating < 3) {
        score -= 15;
        signals.push({ severity: "high", message: `Low buyer rating (${averageRating.toFixed(1)}/5 across ${reviewCount} reviews)` });
      } else if (reviewCount >= 3 && averageRating < 4) {
        score -= 7;
        signals.push({ severity: "medium", message: `Buyer rating is ${averageRating.toFixed(1)}/5 across ${reviewCount} reviews` });
      }
      if (activeShipReminders > 0) {
        signals.push({ severity: "medium", message: `${activeShipReminders} item${activeShipReminders === 1 ? " is" : "s are"} still unshipped after 24 hours` });
      }
      score = Math.max(0, Math.min(100, Math.round(score)));
      const healthBand = score < 60 ? "review" : score < 80 ? "watch" : "good";
      const healthLabel = healthBand === "review" ? "Needs review" : healthBand === "watch" ? "Watch" : "Good standing";

      // Uses the exact same balance logic as seller withdrawals so the admin view
      // cannot disagree with what the seller is actually allowed to withdraw.
      const balance = await computeAvailableBalance(pool, row.user_id);
      sellers.push({
        userId: row.user_id,
        username: row.username,
        displayName: row.display_name,
        email: row.email,
        phone: row.phone,
        isSuspended: !!row.is_suspended,
        verificationStatus: row.verification_status || "none",
        joinedAt: row.joined_at,
        lastLoginAt: row.last_login_at,
        orderCount,
        itemCount,
        completedDeliveries,
        cancelledCount,
        returnedCount,
        shipReminderCount,
        activeShipReminders,
        averageHoursToShip: row.average_hours_to_ship == null ? null : Number(row.average_hours_to_ship),
        grossMerchandise: Math.round((Number(row.gross_merchandise) || 0) * 100) / 100,
        availableBalance: balance,
        reviewCount,
        averageRating,
        warningCount,
        disputeCount,
        openDisputes,
        failedWithdrawalAmount: Math.round((Number(row.failed_withdrawal_amount) || 0) * 100) / 100,
        returnRate,
        cancelRate,
        healthScore: score,
        healthBand,
        healthLabel,
        riskSignals: signals,
      });
    }

    sellers.sort((a, b) => a.healthScore - b.healthScore || b.openDisputes - a.openDisputes || a.username.localeCompare(b.username));
    res.json({
      generatedAt: new Date().toISOString(),
      summary: {
        sellerCount: sellers.length,
        needsReview: sellers.filter((s) => s.healthBand === "review").length,
        watch: sellers.filter((s) => s.healthBand === "watch").length,
        openDisputes: sellers.reduce((sum, seller) => sum + seller.openDisputes, 0),
        activeShipReminders: sellers.reduce((sum, seller) => sum + seller.activeShipReminders, 0),
      },
      sellers,
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});


// Admin CSV/business reports. The endpoint returns structured rows so the
// authenticated admin frontend can preview the report and build a CSV locally.
// Financial reports require the finance permission; the seller directory report
// also permits seller-verification staff. Super Admin can access every report.
function normalizeReportDate(value, endOfDay = false) {
  if (!value) return null;
  const d = new Date(`${value}${endOfDay ? "T23:59:59.999Z" : "T00:00:00.000Z"}`);
  return Number.isNaN(d.getTime()) ? null : d;
}

function reportPermissionAllowed(user, type) {
  if (!user?.isAdmin || !user.twoFactorEnabled) return false;
  if (!user.adminRole || user.adminRole === "super_admin") return true;
  if (type === "sellers") return hasPermission(user, "seller_verification") || hasPermission(user, "finance");
  return hasPermission(user, "finance");
}

app.get("/admin/reports/:type", authenticate, async (req, res) => {
  try {
    const type = String(req.params.type || "").toLowerCase();
    const allowedTypes = new Set(["sales", "orders", "commissions", "payouts", "refunds", "sellers", "taxes"]);
    if (!allowedTypes.has(type)) return res.status(400).json({ error: "Unknown report type" });
    if (!reportPermissionAllowed(req.user, type)) {
      return res.status(403).json({ error: "You don't have permission to view that report" });
    }

    const from = normalizeReportDate(req.query.from, false);
    const to = normalizeReportDate(req.query.to, true);
    if (req.query.from && !from) return res.status(400).json({ error: "Invalid from date" });
    if (req.query.to && !to) return res.status(400).json({ error: "Invalid to date" });
    if (from && to && from > to) return res.status(400).json({ error: "From date must be before To date" });

    const params = [];
    const dateWhere = (column) => {
      const clauses = [];
      if (from) { params.push(from); clauses.push(`${column} >= $${params.length}`); }
      if (to) { params.push(to); clauses.push(`${column} <= $${params.length}`); }
      return clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    };

    let columns = [];
    let rows = [];
    let summary = {};

    if (["sales", "orders", "commissions", "taxes", "refunds"].includes(type)) {
      const where = dateWhere("o.created_at");
      const result = await pool.query(`
        SELECT o.id, o.created_at, o.buyer_username, o.currency, o.subtotal, o.shipping_total,
               o.tax_amount, o.total, o.commission_rate, o.commission_amount, o.payment_status,
               o.is_disputed, o.paystack_reference, o.payment_channel, o.refund_status,
               o.refund_reason, o.refund_requested_at, o.refunded_at, o.refund_failure_reason,
               COALESCE(string_agg(DISTINCT oi.seller_username, ', '), '') AS sellers,
               COALESCE(string_agg(DISTINCT oi.title, ' | '), '') AS items,
               COALESCE(SUM(oi.qty), 0) AS item_quantity
        FROM orders o
        LEFT JOIN order_items oi ON oi.order_id = o.id
        ${where}
        GROUP BY o.id
        ORDER BY o.created_at DESC
        LIMIT 10000
      `, params);
      const base = result.rows.map((r) => ({
        order_number: `STL-${String(r.id).replace(/[^a-z0-9]/gi, "").slice(-8).toUpperCase()}`,
        order_id: r.id,
        date: r.created_at,
        buyer: r.buyer_username || "",
        sellers: r.sellers || "",
        items: r.items || "",
        item_quantity: Number(r.item_quantity) || 0,
        currency: r.currency || "NGN",
        subtotal: Number(r.subtotal) || 0,
        shipping: Number(r.shipping_total) || 0,
        tax: Number(r.tax_amount) || 0,
        total: Number(r.total) || 0,
        commission_rate: Number(r.commission_rate) || 0,
        commission: Number(r.commission_amount) || 0,
        seller_payable: Math.round(((Number(r.subtotal) || 0) + (Number(r.shipping_total) || 0) - (Number(r.commission_amount) || 0)) * 100) / 100,
        payment_status: r.payment_status || "",
        disputed: !!r.is_disputed,
        paystack_reference: r.paystack_reference || "",
        payment_channel: r.payment_channel || "",
        refund_status: r.refund_status || "",
        refund_reason: r.refund_reason || "",
        refund_requested_at: r.refund_requested_at || "",
        refunded_at: r.refunded_at || "",
        refund_failure_reason: r.refund_failure_reason || "",
      }));

      if (type === "sales") {
        columns = ["order_number","date","buyer","sellers","currency","subtotal","shipping","tax","total","payment_status","paystack_reference"];
        rows = base.map((r) => Object.fromEntries(columns.map((c) => [c, r[c]])));
      } else if (type === "orders") {
        columns = ["order_number","order_id","date","buyer","sellers","items","item_quantity","currency","subtotal","shipping","tax","total","commission","seller_payable","payment_status","disputed","refund_status","paystack_reference","payment_channel"];
        rows = base.map((r) => Object.fromEntries(columns.map((c) => [c, r[c]])));
      } else if (type === "commissions") {
        columns = ["order_number","date","currency","subtotal","commission_rate","commission","payment_status","paystack_reference"];
        rows = base.map((r) => Object.fromEntries(columns.map((c) => [c, r[c]])));
      } else if (type === "taxes") {
        columns = ["order_number","date","buyer","currency","subtotal","shipping","tax","total","payment_status"];
        rows = base.map((r) => Object.fromEntries(columns.map((c) => [c, r[c]])));
      } else {
        columns = ["order_number","date","buyer","currency","total","payment_status","refund_status","refund_reason","refund_requested_at","refunded_at","refund_failure_reason","paystack_reference"];
        rows = base.filter((r) => r.refund_status || r.payment_status === "refunded" || r.payment_status === "refund_pending")
          .map((r) => Object.fromEntries(columns.map((c) => [c, r[c]])));
      }

      const currencies = {};
      for (const r of base) {
        const c = r.currency || "NGN";
        currencies[c] ||= { orders: 0, gross: 0, commission: 0, tax: 0, refunded: 0 };
        currencies[c].orders += 1;
        currencies[c].gross += r.total;
        currencies[c].commission += r.commission;
        currencies[c].tax += r.tax;
        if (r.payment_status === "refunded") currencies[c].refunded += r.total;
      }
      for (const c of Object.values(currencies)) {
        for (const k of ["gross","commission","tax","refunded"]) c[k] = Math.round(c[k] * 100) / 100;
      }
      summary = { rowCount: rows.length, currencies };
    } else if (type === "payouts") {
      const where = dateWhere("w.requested_at");
      const result = await pool.query(`
        SELECT w.id, w.seller_username, w.amount, w.status, w.failure_reason,
               w.paystack_transfer_code, w.requested_at, w.processed_at
        FROM withdrawals w
        ${where}
        ORDER BY w.requested_at DESC
        LIMIT 10000
      `, params);
      columns = ["withdrawal_id","requested_at","seller","amount","status","processed_at","paystack_transfer_code","failure_reason"];
      rows = result.rows.map((r) => ({
        withdrawal_id: r.id,
        requested_at: r.requested_at,
        seller: r.seller_username || "",
        amount: Number(r.amount) || 0,
        status: r.status || "",
        processed_at: r.processed_at || "",
        paystack_transfer_code: r.paystack_transfer_code || "",
        failure_reason: r.failure_reason || "",
      }));
      summary = {
        rowCount: rows.length,
        paid: Math.round(rows.filter((r) => r.status === "paid").reduce((s, r) => s + r.amount, 0) * 100) / 100,
        processing: Math.round(rows.filter((r) => r.status === "processing").reduce((s, r) => s + r.amount, 0) * 100) / 100,
        failed: Math.round(rows.filter((r) => r.status === "failed").reduce((s, r) => s + r.amount, 0) * 100) / 100,
      };
    } else if (type === "sellers") {
      const where = dateWhere("u.created_at");
      const result = await pool.query(`
        SELECT u.id, u.username, u.display_name, u.email, u.phone, u.country, u.account_type,
               u.verification_status, u.is_approved, u.is_verified, u.is_suspended, u.created_at,
               COALESCE((SELECT COUNT(DISTINCT oi.order_id) FROM order_items oi WHERE oi.seller_id = u.id), 0) AS order_count,
               COALESCE((
                 SELECT SUM(oi.price * oi.qty)
                 FROM order_items oi
                 JOIN orders o ON o.id = oi.order_id
                 WHERE oi.seller_id = u.id AND o.payment_status = 'released'
               ), 0) AS released_merchandise,
               COALESCE((SELECT AVG(rv.rating) FROM reviews rv WHERE rv.seller_id = u.id), 0) AS avg_rating,
               COALESCE((SELECT COUNT(*) FROM reviews rv WHERE rv.seller_id = u.id), 0) AS review_count
        FROM users u
        ${where ? where + " AND (u.has_applied_to_sell = true OR u.is_approved = true)" : "WHERE (u.has_applied_to_sell = true OR u.is_approved = true)"}
        ORDER BY u.created_at DESC
        LIMIT 10000
      `, params);
      columns = ["seller_id","joined_at","username","display_name","email","phone","country","account_type","verification_status","approved","verified","suspended","order_count","released_merchandise","avg_rating","review_count"];
      rows = result.rows.map((r) => ({
        seller_id: r.id,
        joined_at: r.created_at,
        username: r.username || "",
        display_name: r.display_name || "",
        email: r.email || "",
        phone: r.phone || "",
        country: r.country || "",
        account_type: r.account_type || "",
        verification_status: r.verification_status || "",
        approved: !!r.is_approved,
        verified: !!r.is_verified,
        suspended: !!r.is_suspended,
        order_count: Number(r.order_count) || 0,
        released_merchandise: Math.round((Number(r.released_merchandise) || 0) * 100) / 100,
        avg_rating: Math.round((Number(r.avg_rating) || 0) * 100) / 100,
        review_count: Number(r.review_count) || 0,
      }));
      summary = { rowCount: rows.length, approved: rows.filter((r) => r.approved).length, suspended: rows.filter((r) => r.suspended).length };
    }

    logAdminAction(req.user.id, "report_generated", `${type} report${req.query.from || req.query.to ? ` (${req.query.from || 'start'} to ${req.query.to || 'now'})` : ''}`);
    res.json({ type, generatedAt: new Date().toISOString(), from: req.query.from || null, to: req.query.to || null, columns, rows, summary });
  } catch (err) {
    sendInternalError(res, err);
  }
});

// Finance reconciliation: one server-side view of what buyers paid, what is
// still held, what has been released to sellers, Stallyard commission,
// refunds, and seller withdrawals. This intentionally calculates from the
// database rather than trusting totals assembled in the browser.
app.get("/admin/reconciliation", authenticate, requirePermission("finance"), async (req, res) => {
  try {
    const ordersResult = await pool.query(`
      SELECT
        o.*,
        COALESCE(SUM(CASE WHEN oi.fulfillment_status NOT IN ('cancelled', 'returned')
          THEN oi.price * oi.qty ELSE 0 END), 0) AS eligible_merchandise,
        COALESCE(SUM(CASE WHEN oi.fulfillment_status NOT IN ('cancelled', 'returned')
          THEN oi.shipping_fee * oi.qty ELSE 0 END), 0) AS eligible_shipping,
        COUNT(oi.id) AS item_count,
        COUNT(oi.id) FILTER (
          WHERE oi.fulfillment_status NOT IN ('cancelled', 'returned')
            AND oi.buyer_confirmed_at IS NULL
        ) AS unconfirmed_item_count,
        COUNT(oi.id) FILTER (
          WHERE oi.fulfillment_status NOT IN ('cancelled', 'returned')
            AND COALESCE(oi.proof_of_delivery_url, '') = ''
        ) AS missing_pod_count
      FROM orders o
      LEFT JOIN order_items oi ON oi.order_id = o.id
      GROUP BY o.id
      ORDER BY o.created_at DESC
      LIMIT 500
    `);
    const withdrawalsResult = await pool.query(`
      SELECT status, COALESCE(SUM(amount), 0) AS amount, COUNT(*) AS count
      FROM withdrawals
      GROUP BY status
    `);

    const byCurrency = {};
    const records = [];
    for (const row of ordersResult.rows) {
      const currency = row.currency || "NGN";
      if (!byCurrency[currency]) {
        byCurrency[currency] = {
          currency,
          grossPayments: 0,
          held: 0,
          released: 0,
          refundPending: 0,
          refunded: 0,
          recordedCommission: 0,
          releasedSellerPayable: 0,
          tax: 0,
        };
      }
      const bucket = byCurrency[currency];
      const total = Number(row.total) || 0;
      const subtotal = Number(row.subtotal) || 0;
      const shippingTotal = Number(row.shipping_total) || 0;
      const taxAmount = Number(row.tax_amount) || 0;
      const commissionRate = Number(row.commission_rate) || 0;
      const commissionAmount = Number(row.commission_amount) || 0;
      const expectedTotal = Math.round((subtotal + shippingTotal + taxAmount) * 100) / 100;
      const expectedCommission = Math.round(subtotal * commissionRate * 100) / 100;
      const eligibleMerchandise = Number(row.eligible_merchandise) || 0;
      const eligibleShipping = Number(row.eligible_shipping) || 0;
      const sellerPayable = Math.round((eligibleMerchandise * (1 - commissionRate) + eligibleShipping) * 100) / 100;

      bucket.grossPayments += total;
      bucket.recordedCommission += commissionAmount;
      bucket.tax += taxAmount;
      if (row.payment_status === "held") bucket.held += total;
      else if (row.payment_status === "released") {
        bucket.released += total;
        bucket.releasedSellerPayable += sellerPayable;
      } else if (row.payment_status === "refund_pending") bucket.refundPending += total;
      else if (row.payment_status === "refunded") bucket.refunded += total;

      const flags = [];
      if (["held", "released", "refund_pending", "refunded"].includes(row.payment_status) && !row.paystack_reference) {
        flags.push({ code: "missing_reference", severity: "high", message: "Paid order has no Paystack transaction reference" });
      }
      if (Math.abs(total - expectedTotal) > 0.01) {
        flags.push({ code: "total_mismatch", severity: "high", message: `Order total differs from subtotal + shipping + tax by ${Math.abs(total - expectedTotal).toFixed(2)}` });
      }
      if (Math.abs(commissionAmount - expectedCommission) > 0.01) {
        flags.push({ code: "commission_mismatch", severity: "medium", message: `Recorded commission differs from the order rate by ${Math.abs(commissionAmount - expectedCommission).toFixed(2)}` });
      }
      if (row.payment_status === "released" && row.is_disputed) {
        flags.push({ code: "released_disputed", severity: "high", message: "Payment is released while the order is marked disputed" });
      }
      if (row.payment_status === "released" && Number(row.unconfirmed_item_count) > 0) {
        flags.push({ code: "released_unconfirmed", severity: "high", message: `${row.unconfirmed_item_count} eligible item(s) are not delivery-confirmed` });
      }
      if (row.payment_status === "released" && Number(row.missing_pod_count) > 0) {
        flags.push({ code: "released_no_pod", severity: "high", message: `${row.missing_pod_count} eligible item(s) have no proof-of-delivery image` });
      }
      if (row.payment_status === "refunded" && row.refund_status && row.refund_status !== "processed") {
        flags.push({ code: "refund_status_mismatch", severity: "high", message: `Order says refunded but refund status is ${row.refund_status}` });
      }
      if (row.payment_status === "refund_pending" && row.refund_status === "failed") {
        flags.push({ code: "failed_refund_locked", severity: "medium", message: "Refund failed but order is still locked as refund pending" });
      }

      records.push({
        orderId: row.id,
        buyerUsername: row.buyer_username,
        currency,
        total,
        subtotal,
        shippingTotal,
        taxAmount,
        commissionRate,
        commissionAmount,
        expectedTotal,
        expectedCommission,
        sellerPayable,
        paymentStatus: row.payment_status,
        refundStatus: row.refund_status,
        isDisputed: !!row.is_disputed,
        paystackReference: row.paystack_reference,
        createdAt: row.created_at,
        flags,
      });
    }

    for (const value of Object.values(byCurrency)) {
      for (const key of Object.keys(value)) {
        if (key !== "currency") value[key] = Math.round(Number(value[key] || 0) * 100) / 100;
      }
    }

    const withdrawals = { processing: 0, paid: 0, failed: 0, counts: {} };
    for (const row of withdrawalsResult.rows) {
      const status = row.status || "unknown";
      const amount = Math.round((Number(row.amount) || 0) * 100) / 100;
      withdrawals.counts[status] = Number(row.count) || 0;
      if (status === "processing") withdrawals.processing += amount;
      else if (status === "paid") withdrawals.paid += amount;
      else if (status === "failed") withdrawals.failed += amount;
    }

    const flaggedRecords = records.filter((r) => r.flags.length > 0);
    res.json({
      generatedAt: new Date().toISOString(),
      byCurrency: Object.values(byCurrency),
      withdrawals,
      alerts: {
        total: flaggedRecords.length,
        high: flaggedRecords.filter((r) => r.flags.some((f) => f.severity === "high")).length,
      },
      records,
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

// Live spot-check against Paystack for a single order. We do this on demand
// instead of calling Paystack for hundreds of orders every time the dashboard
// opens, which keeps the finance page fast and avoids unnecessary API traffic.
app.get("/admin/reconciliation/orders/:id/verify-paystack", authenticate, requirePermission("finance"), async (req, res) => {
  try {
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ error: "Paystack isn't configured" });
    }
    const result = await pool.query(
      "SELECT id, total, currency, payment_status, paystack_reference FROM orders WHERE id = $1",
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Order not found" });
    const order = result.rows[0];
    if (!order.paystack_reference) {
      return res.status(400).json({ error: "This order has no Paystack transaction reference" });
    }
    const paystackRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(order.paystack_reference)}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });
    const data = await paystackRes.json();
    if (!paystackRes.ok || !data.status) {
      console.error("Paystack transaction verification failed:", data?.message || data);
      return res.status(502).json({ error: "Something went wrong. Please try again in a moment.", code: "PAYMENT_PROVIDER_ERROR" });
    }
    const tx = data.data || {};
    const paystackAmount = Math.round((Number(tx.amount) || 0)) / 100;
    const expectedAmount = Math.round((Number(order.total) || 0) * 100) / 100;
    const amountMatches = Math.abs(paystackAmount - expectedAmount) <= 0.01;
    const currencyMatches = String(tx.currency || "").toUpperCase() === "NGN";
    const paymentSucceeded = tx.status === "success";
    res.json({
      orderId: order.id,
      reference: order.paystack_reference,
      checkedAt: new Date().toISOString(),
      matches: amountMatches && currencyMatches && paymentSucceeded,
      checks: { amountMatches, currencyMatches, paymentSucceeded },
      stallyard: { amount: expectedAmount, currency: "NGN", paymentStatus: order.payment_status },
      paystack: { amount: paystackAmount, currency: tx.currency || null, status: tx.status || null, paidAt: tx.paid_at || null, channel: tx.channel || null },
    });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/wallet/balance", authenticate, async (req, res) => {
  try {
    const available = await computeAvailableBalance(pool, req.user.id);
    res.json({ available });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/threads", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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
    sendInternalError(res, err);
  }
});

app.get("/threads/:userId", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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
    sendInternalError(res, err);
  }
});

app.post("/messages", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const { threadId, body, messageType, offerAmount, imageUrl, orderId } = req.body;
    const senderId = req.user.id;

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
    sendInternalError(res, err);
  }
});

app.get("/messages/:threadId", authenticate, async (req, res) => {
  try {
    const thread = await pool.query("SELECT buyer_id, seller_id FROM threads WHERE id = $1", [req.params.threadId]);
    if (thread.rows.length === 0) return res.status(404).json({ error: "Thread not found" });
    const isThreadParticipant = thread.rows[0].buyer_id === req.user.id || thread.rows[0].seller_id === req.user.id;
    if (!isThreadParticipant) {
      if (!hasPermission(req.user, "message_moderation")) {
        return res.status(403).json({ error: "You don't have permission to view this conversation" });
      }
      // Customer Support gets deliberately narrow access: only conversations
      // that have actually been reported. Super Admin remains the emergency
      // override through hasPermission(). This prevents support staff from
      // browsing arbitrary buyer/seller private messages by guessing thread IDs.
      if (req.user.adminRole !== "super_admin") {
        const reported = await pool.query(
          "SELECT 1 FROM message_reports WHERE thread_id = $1 LIMIT 1",
          [req.params.threadId]
        );
        if (!reported.rows.length) {
          return res.status(403).json({ error: "Customer Support can only view marketplace conversations that have been reported" });
        }
      }
      logAdminAction(req.user.id, "reported_conversation_viewed", `Viewed reported marketplace conversation thread #${req.params.threadId}`);
    }
    const result = await pool.query(
      "SELECT * FROM messages WHERE thread_id = $1 ORDER BY created_at ASC",
      [req.params.threadId]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

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
    if (req.user.id !== recipientId) {
      return res.status(403).json({ error: "Only the offer recipient can accept or decline it" });
    }

    const result = await pool.query(
      "UPDATE messages SET offer_status = $1 WHERE id = $2 RETURNING *",
      [status, req.params.id]
    );
    res.json({ message: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/messages/:id/report", authenticate, async (req, res) => {
  try {
    const { reason } = req.body;
    const msgResult = await pool.query("SELECT thread_id FROM messages WHERE id = $1", [req.params.id]);
    if (msgResult.rows.length === 0) return res.status(404).json({ error: "Message not found" });
    const threadId = msgResult.rows[0].thread_id;
    const threadResult = await pool.query("SELECT buyer_id, seller_id FROM threads WHERE id = $1", [threadId]);
    if (threadResult.rows.length === 0) return res.status(404).json({ error: "Thread not found" });
    const thread = threadResult.rows[0];
    if (req.user.id !== thread.buyer_id && req.user.id !== thread.seller_id) {
      return res.status(403).json({ error: "Only conversation participants can report a message" });
    }
    const result = await pool.query(
      `INSERT INTO message_reports (message_id, thread_id, reporter_id, reason)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, threadId, req.user.id, reason || ""]
    );
    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/message-reports", authenticate, requirePermission("dispute_resolution"), async (req, res) => {
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
    sendInternalError(res, err);
  }
});

app.patch("/message-reports/:id/resolve", authenticate, requirePermission("dispute_resolution"), async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE message_reports SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    logAdminAction(req.user.id, "message_report_resolved", `Resolved message report #${req.params.id}`);
    res.json({ report: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/reviews", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM reviews ORDER BY created_at DESC");
    res.json({ reviews: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/reviews", authenticate, async (req, res) => {
  try {
    const { orderId, listingId, sellerId, rating, comment } = req.body;
    const buyerId = req.user.id;

    if (!orderId || !listingId || !sellerId || !rating) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
    }

    const purchase = await pool.query(
      `SELECT oi.fulfillment_status, o.payment_status FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       WHERE o.id = $1 AND o.buyer_id = $2 AND oi.listing_id = $3 AND oi.seller_id = $4`,
      [orderId, buyerId, listingId, sellerId]
    );
    if (purchase.rows.length === 0) {
      return res.status(403).json({ error: "You can only review items you've actually purchased" });
    }
    if (purchase.rows[0].fulfillment_status !== "delivered" && purchase.rows[0].payment_status !== "released") {
      return res.status(409).json({ error: "You can review this item only after delivery is completed" });
    }
    if (["cancelled", "returned"].includes(purchase.rows[0].fulfillment_status)) {
      return res.status(409).json({ error: "Cancelled or returned items cannot be reviewed" });
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
    sendInternalError(res, err);
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
    if (existing.rows[0].buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer who wrote this review can edit it" });
    }
    const result = await pool.query(
      "UPDATE reviews SET rating = COALESCE($1, rating), comment = COALESCE($2, comment) WHERE id = $3 RETURNING *",
      [rating ?? null, comment ?? null, req.params.id]
    );
    res.json({ review: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
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
    sendInternalError(res, err);
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
    sendInternalError(res, err);
  }
});

app.patch("/reviews/:id/respond", authenticate, async (req, res) => {
  try {
    const { response } = req.body;
    if (!response || !response.trim()) {
      return res.status(400).json({ error: "Write a response first" });
    }
    const existing = await pool.query("SELECT seller_id FROM reviews WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Review not found" });
    if (existing.rows[0].seller_id !== req.user.id) {
      return res.status(403).json({ error: "Only the seller who received this review can respond to it" });
    }
    const result = await pool.query(
      "UPDATE reviews SET seller_response = $1, seller_response_at = NOW() WHERE id = $2 RETURNING *",
      [response.trim(), req.params.id]
    );
    res.json({ review: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

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
    sendInternalError(res, err);
  }
});

app.get("/review-reports", authenticate, requirePermission("dispute_resolution"), async (req, res) => {
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
    sendInternalError(res, err);
  }
});

app.patch("/review-reports/:id/resolve", authenticate, requirePermission("dispute_resolution"), async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE review_reports SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    logAdminAction(req.user.id, "review_report_resolved", `Resolved review report #${req.params.id}`);
    res.json({ report: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

const SELLER_REPORT_REASONS = new Set(["fraud", "counterfeit", "harassment", "prohibited_item", "misleading_listing", "delivery_misconduct", "other"]);

app.post("/seller-reports", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const sellerId = Number(req.body?.sellerId);
    const orderId = req.body?.orderId ? Number(req.body.orderId) : null;
    const reason = String(req.body?.reason || "").trim();
    const details = String(req.body?.details || "").trim();
    const evidenceUrls = Array.isArray(req.body?.evidenceUrls)
      ? req.body.evidenceUrls.filter((url) => typeof url === "string" && (url.startsWith("https://") || url.startsWith("data:image/")) && url.length <= 2000000).slice(0, 5)
      : [];
    if (!Number.isInteger(sellerId) || sellerId <= 0) return res.status(400).json({ error: "Choose a seller to report" });
    if (sellerId === Number(req.user.id)) return res.status(400).json({ error: "You cannot report your own account" });
    if (!SELLER_REPORT_REASONS.has(reason)) return res.status(400).json({ error: "Choose a valid report reason" });
    if (details.length < 10 || details.length > 2000) return res.status(400).json({ error: "Explain what happened in 10 to 2,000 characters" });
    const seller = await pool.query("SELECT id, username FROM users WHERE id = $1", [sellerId]);
    if (!seller.rows.length) return res.status(404).json({ error: "Seller not found" });
    if (orderId) {
      const related = await pool.query(
        `SELECT 1 FROM orders o JOIN order_items oi ON oi.order_id = o.id
         WHERE o.id = $1 AND o.buyer_id = $2 AND oi.seller_id = $3 LIMIT 1`,
        [orderId, req.user.id, sellerId]
      );
      if (!related.rows.length) return res.status(403).json({ error: "That order is not connected to you and this seller" });
    }
    const reference = `SR-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
    const result = await pool.query(
      `INSERT INTO seller_reports(reference, reporter_id, reported_seller_id, order_id, reason, details, evidence_urls)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [reference, req.user.id, sellerId, orderId, reason, details, JSON.stringify(evidenceUrls)]
    );
    await pool.query(
      `INSERT INTO notifications(user_id, type, message)
       SELECT id, 'seller_report_received', $1 FROM users
       WHERE is_admin = true AND admin_role IN ('super_admin', 'customer_support', 'order_dispute')`,
      [`Seller report ${reference} requires review.`]
    ).catch(() => {});
    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "You already have an open report for this seller and order" });
    sendInternalError(res, err);
  }
});

app.get("/seller-reports/mine", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sr.*, u.username AS seller_username, u.display_name AS seller_display_name
       FROM seller_reports sr JOIN users u ON u.id = sr.reported_seller_id
       WHERE sr.reporter_id = $1 ORDER BY sr.created_at DESC`, [req.user.id]
    );
    res.json({ reports: result.rows });
  } catch (err) { sendInternalError(res, err); }
});

app.get("/seller-reports", authenticate, requirePermission("seller_report_review"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sr.*, reporter.username AS reporter_username, reporter.display_name AS reporter_display_name,
         seller.username AS seller_username, seller.display_name AS seller_display_name
       FROM seller_reports sr JOIN users reporter ON reporter.id = sr.reporter_id
       JOIN users seller ON seller.id = sr.reported_seller_id
       ORDER BY CASE sr.status WHEN 'open' THEN 0 WHEN 'in_review' THEN 1 ELSE 2 END, sr.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) { sendInternalError(res, err); }
});

app.patch("/seller-reports/:id", authenticate, requirePermission("seller_report_review"), async (req, res) => {
  try {
    const status = String(req.body?.status || "");
    const adminNote = String(req.body?.adminNote || "").trim().slice(0, 2000);
    if (!["in_review", "resolved", "dismissed"].includes(status)) return res.status(400).json({ error: "Invalid report status" });
    const result = await pool.query(
      `UPDATE seller_reports SET status=$1, admin_note=$2, reviewed_by=$3, updated_at=NOW(),
         resolved_at=CASE WHEN $1 IN ('resolved','dismissed') THEN NOW() ELSE NULL END
       WHERE id=$4 RETURNING *`, [status, adminNote || null, req.user.id, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Seller report not found" });
    logAdminAction(req.user.id, "seller_report_updated", `Seller report ${result.rows[0].reference} marked ${status}`);
    res.json({ report: result.rows[0] });
  } catch (err) { sendInternalError(res, err); }
});

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
    sendInternalError(res, err);
  }
});

app.get("/account-reports", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ar.*, u.username, u.display_name
       FROM account_reports ar
       JOIN users u ON ar.user_id = u.id
       ORDER BY ar.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/account-reports/:id/resolve", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE account_reports SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    logAdminAction(req.user.id, "account_report_resolved", `Resolved account report #${req.params.id}`);
    res.json({ report: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/users/:id/warnings", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Write a message for the warning" });
    }
    const result = await pool.query(
      "INSERT INTO seller_warnings (user_id, admin_id, message) VALUES ($1, $2, $3) RETURNING *",
      [req.params.id, req.user.id, message.trim()]
    );
    logAdminAction(req.user.id, "warning_issued", `Issued a warning to user #${req.params.id}: ${message.trim()}`);
    res.status(201).json({ warning: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/users/:id/warnings", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM seller_warnings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.params.id]
    );
    res.json({ warnings: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/warnings/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM seller_warnings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json({ warnings: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

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
    sendInternalError(res, err);
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
    sendInternalError(res, err);
  }
});


// Homepage promotional ads. Public visitors only receive the three safe display
// fields; only the Super Admin can change an image or destination hyperlink.
app.get("/homepage-ads", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT slot, image_url, media_type, poster_url, link_url, updated_at FROM homepage_ads ORDER BY slot ASC"
    );
    const bySlot = new Map(result.rows.map((row) => [Number(row.slot), row]));
    const ads = [1, 2, 3].map((slot) => bySlot.get(slot) || {
      slot,
      image_url: "",
      media_type: "image",
      poster_url: "",
      link_url: "",
      updated_at: null,
    });
    res.json({ ads });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.put("/admin/homepage-ads/:slot", authenticate, requireAdmin, async (req, res) => {
  try {
    if (req.user.adminRole && req.user.adminRole !== "super_admin") {
      return res.status(403).json({ error: "Only the Super Admin can manage homepage ads" });
    }
    const slot = Number(req.params.slot);
    if (![1, 2, 3].includes(slot)) {
      return res.status(400).json({ error: "Invalid homepage ad slot" });
    }

    const imageUrl = String(req.body?.imageUrl || "").trim(); // primary media URL (image or Ad 1 video)
    const requestedMediaType = String(req.body?.mediaType || "image").trim().toLowerCase();
    const mediaType = requestedMediaType === "video" ? "video" : requestedMediaType === "image" ? "image" : "";
    const posterUrl = String(req.body?.posterUrl || "").trim();
    const linkUrl = String(req.body?.linkUrl || "").trim();

    if (!mediaType) {
      return res.status(400).json({ error: "Ad media type must be image or video" });
    }
    if (slot !== 1 && mediaType !== "image") {
      return res.status(400).json({ error: "Only homepage Ad 1 can use video" });
    }

    for (const [url, label] of [[imageUrl, "Ad media"], [posterUrl, "Video poster"]]) {
      if (!url) continue;
      try {
        const parsed = new URL(url);
        if (parsed.protocol !== "https:") throw new Error("unsafe protocol");
      } catch {
        return res.status(400).json({ error: `${label} must use a valid HTTPS URL` });
      }
    }

    if (linkUrl && !linkUrl.startsWith("/")) {
      try {
        const parsedLink = new URL(linkUrl);
        if (!["https:", "http:"].includes(parsedLink.protocol)) throw new Error("unsafe link protocol");
      } catch {
        return res.status(400).json({ error: "Use a valid http(s) link or a Stallyard path beginning with /" });
      }
    }

    const result = await pool.query(
      `INSERT INTO homepage_ads (slot, image_url, media_type, poster_url, link_url, updated_at, updated_by)
       VALUES ($1, $2, $3, $4, $5, NOW(), $6)
       ON CONFLICT (slot) DO UPDATE SET
         image_url = EXCLUDED.image_url,
         media_type = EXCLUDED.media_type,
         poster_url = EXCLUDED.poster_url,
         link_url = EXCLUDED.link_url,
         updated_at = NOW(),
         updated_by = EXCLUDED.updated_by
       RETURNING slot, image_url, media_type, poster_url, link_url, updated_at`,
      [slot, imageUrl, mediaType, mediaType === "video" ? posterUrl : "", linkUrl, req.user.id]
    );
    logAdminAction(req.user.id, "homepage_ad_updated", `Updated homepage ad slot #${slot}`);
    res.json({ ad: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/content", async (req, res) => {
  try {
    const [banners, articles, faqs] = await Promise.all([
      pool.query("SELECT * FROM banners ORDER BY created_at DESC"),
      pool.query("SELECT * FROM help_articles ORDER BY created_at DESC"),
      pool.query("SELECT * FROM help_faqs ORDER BY created_at ASC"),
    ]);
    res.json({ banners: banners.rows, articles: articles.rows, faqs: faqs.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/content/banners", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    const { message, tone, mediaType, imageUrl, videoUrl } = req.body;
    if (!message || !message.trim()) return res.status(400).json({ error: "Missing banner message" });
    const result = await pool.query(
      `INSERT INTO banners (message, tone, media_type, image_url, video_url)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [message.trim(), tone || "info", mediaType || "none", imageUrl || "", videoUrl || ""]
    );
    logAdminAction(req.user.id, "banner_created", `Created banner #${result.rows[0].id}`);
    res.status(201).json({ banner: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/content/banners/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    const { message, tone, isActive, mediaType, imageUrl, videoUrl } = req.body;
    const sets = [];
    const values = [];
    let i = 1;
    if (typeof message === "string") { sets.push(`message = $${i++}`); values.push(message); }
    if (typeof tone === "string") { sets.push(`tone = $${i++}`); values.push(tone); }
    if (typeof isActive === "boolean") { sets.push(`is_active = $${i++}`); values.push(isActive); }
    if (typeof mediaType === "string") { sets.push(`media_type = $${i++}`); values.push(mediaType); }
    if (typeof imageUrl === "string") { sets.push(`image_url = $${i++}`); values.push(imageUrl); }
    if (typeof videoUrl === "string") { sets.push(`video_url = $${i++}`); values.push(videoUrl); }
    if (sets.length === 0) return res.status(400).json({ error: "No valid fields to update" });
    values.push(req.params.id);
    const result = await pool.query(`UPDATE banners SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`, values);
    if (result.rows.length === 0) return res.status(404).json({ error: "Banner not found" });
    logAdminAction(req.user.id, "banner_updated", `Updated banner #${req.params.id} (${Object.keys(req.body || {}).join(", ")})`);
    res.json({ banner: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/content/banners/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    await pool.query("DELETE FROM banners WHERE id = $1", [req.params.id]);
    logAdminAction(req.user.id, "banner_removed", `Removed banner #${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/content/articles", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    const { title, body } = req.body;
    if (!title?.trim() || !body?.trim()) return res.status(400).json({ error: "Missing title or body" });
    const result = await pool.query(
      "INSERT INTO help_articles (title, body) VALUES ($1, $2) RETURNING *",
      [title.trim(), body.trim()]
    );
    logAdminAction(req.user.id, "article_created", `Created help article #${result.rows[0].id}: ${result.rows[0].title}`);
    res.status(201).json({ article: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/content/articles/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    const { title, body } = req.body;
    const result = await pool.query(
      `UPDATE help_articles SET title = COALESCE($1, title), body = COALESCE($2, body), updated_at = NOW()
       WHERE id = $3 RETURNING *`,
      [title?.trim() || null, body?.trim() || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Article not found" });
    logAdminAction(req.user.id, "article_updated", `Updated help article #${req.params.id}: ${result.rows[0].title}`);
    res.json({ article: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/content/articles/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    await pool.query("DELETE FROM help_articles WHERE id = $1", [req.params.id]);
    logAdminAction(req.user.id, "article_removed", `Removed help article #${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/content/faqs", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    const { question, answer } = req.body;
    if (!question?.trim() || !answer?.trim()) return res.status(400).json({ error: "Missing question or answer" });
    const result = await pool.query(
      "INSERT INTO help_faqs (question, answer) VALUES ($1, $2) RETURNING *",
      [question.trim(), answer.trim()]
    );
    logAdminAction(req.user.id, "faq_created", `Created FAQ #${result.rows[0].id}`);
    res.status(201).json({ faq: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.patch("/content/faqs/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    const { question, answer } = req.body;
    const result = await pool.query(
      `UPDATE help_faqs SET question = COALESCE($1, question), answer = COALESCE($2, answer)
       WHERE id = $3 RETURNING *`,
      [question?.trim() || null, answer?.trim() || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "FAQ not found" });
    logAdminAction(req.user.id, "faq_updated", `Updated FAQ #${req.params.id}`);
    res.json({ faq: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.delete("/content/faqs/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    await pool.query("DELETE FROM help_faqs WHERE id = $1", [req.params.id]);
    logAdminAction(req.user.id, "faq_removed", `Removed FAQ #${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/policies", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM marketplace_policies");
    res.json({ policies: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

const POLICY_CATEGORIES = new Set([
  "seller_rules", "prohibited_items", "fees", "payment_rules", "shipping_rules", "returns_disputes",
]);

app.patch("/policies/:category", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    if (!POLICY_CATEGORIES.has(req.params.category)) {
      return res.status(400).json({ error: "Invalid policy category" });
    }
    const { body } = req.body;
    const result = await pool.query(
      `INSERT INTO marketplace_policies (category, body, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (category) DO UPDATE SET body = $2, updated_at = NOW()
       RETURNING *`,
      [req.params.category, body || ""]
    );
    logAdminAction(req.user.id, "policy_updated", `Updated the "${req.params.category}" policy`);
    res.json({ policy: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/support-tickets", authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!subject?.trim() || !message?.trim()) {
      return res.status(400).json({ error: "Give it a subject and a message" });
    }
    const ticketResult = await pool.query(
      "INSERT INTO support_tickets (user_id, subject) VALUES ($1, $2) RETURNING *",
      [req.user.id, subject.trim()]
    );
    const ticket = ticketResult.rows[0];
    const messageResult = await pool.query(
      "INSERT INTO support_ticket_messages (ticket_id, sender_id, body) VALUES ($1, $2, $3) RETURNING *",
      [ticket.id, req.user.id, message.trim()]
    );
    res.status(201).json({ ticket, message: messageResult.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/support-tickets/mine", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM support_tickets WHERE user_id = $1 ORDER BY updated_at DESC",
      [req.user.id]
    );
    res.json({ tickets: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.get("/support-tickets", authenticate, requirePermission("support_tickets"), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT st.*, u.username, u.display_name
       FROM support_tickets st JOIN users u ON st.user_id = u.id
       ORDER BY st.updated_at DESC`
    );
    res.json({ tickets: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});


// Super-admin-only, non-destructive health checks. Live checks are used only
// where a read-only endpoint is available; services whose validation would
// consume quota or create user-visible side effects are reported as configured.
async function fetchWithTimeout(url, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

app.get("/admin/system-health", authenticate, requirePermission("role_assignment"), async (req, res) => {
  const services = [];
  const add = (key, name, purpose, status, message, extra = {}) => {
    services.push({ key, name, purpose, status, message, ...extra });
  };
  const timed = async (fn) => {
    const started = Date.now();
    try {
      const value = await fn();
      return { ok: true, value, latencyMs: Date.now() - started };
    } catch (error) {
      return { ok: false, error, latencyMs: Date.now() - started };
    }
  };

  // The request itself proves Express/Railway is serving traffic.
  add("backend", "Railway backend", "API server", "healthy", "Stallyard backend is responding.", { liveCheck: true, latencyMs: 0 });

  const db = await timed(() => pool.query("SELECT 1 AS ok"));
  add(
    "postgres",
    "PostgreSQL",
    "Marketplace database",
    db.ok ? "healthy" : "unhealthy",
    db.ok ? "Database connection and query succeeded." : `Database check failed: ${db.error?.message || "unknown error"}`,
    { liveCheck: true, latencyMs: db.latencyMs }
  );

  const supabaseUrl = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  const supabaseBucket = process.env.SUPABASE_STORAGE_BUCKET || "stallyard-media";
  if (!supabaseUrl || !supabaseKey) {
    add("supabase", "Supabase Storage", "Listing and marketplace media", "not_configured", "Supabase URL or server key is missing.", { liveCheck: false });
  } else {
    const sb = await timed(async () => {
      const response = await fetchWithTimeout(`${supabaseUrl}/storage/v1/bucket/${encodeURIComponent(supabaseBucket)}`, {
        headers: { apikey: supabaseKey, Authorization: `Bearer ${supabaseKey}` },
      });
      if (!response.ok) throw new Error(`Storage API returned HTTP ${response.status}`);
      return response;
    });
    add("supabase", "Supabase Storage", "Listing and marketplace media", sb.ok ? "healthy" : "unhealthy",
      sb.ok ? `Storage bucket “${supabaseBucket}” is reachable.` : `Storage check failed: ${sb.error?.message || "unknown error"}`,
      { liveCheck: true, latencyMs: sb.latencyMs });
  }

  if (!process.env.PAYSTACK_SECRET_KEY) {
    add("paystack", "Paystack", "Buyer payments, refunds, seller payouts", "not_configured", "PAYSTACK_SECRET_KEY is missing.", { liveCheck: false });
  } else {
    const ps = await timed(async () => {
      const response = await fetchWithTimeout("https://api.paystack.co/bank?country=nigeria&perPage=1", {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.status === false) throw new Error(data.message || `Paystack returned HTTP ${response.status}`);
      return data;
    });
    add("paystack", "Paystack", "Buyer payments, refunds, seller payouts", ps.ok ? "healthy" : "unhealthy",
      ps.ok ? "Paystack API authentication and connectivity succeeded." : `Paystack check failed: ${ps.error?.message || "unknown error"}`,
      { liveCheck: true, latencyMs: ps.latencyMs });
  }

  // Resend production keys can intentionally be restricted to Sending access.
  // A send-only key is not allowed to call account-level endpoints such as
  // GET /domains, so using that endpoint as a health check produces a false
  // HTTP 401 even while Stallyard email delivery is working correctly.
  // Do not send a test email from System Health either: that would create a
  // user-visible side effect and consume sending quota. Instead, report the
  // email integration as configured when the server-side sending key exists.
  if (!process.env.RESEND_API_KEY) {
    add("resend", "Resend", "Verification and security email", "not_configured", "RESEND_API_KEY is missing.", { liveCheck: false });
  } else {
    add(
      "resend",
      "Resend",
      "Verification and security email",
      "configured",
      "Sending API key is present. A live account-level check is intentionally skipped because Stallyard uses a restricted send-only key; no test email is sent by System Health.",
      { liveCheck: false }
    );
  }

  const sightengineConfigured = !!(process.env.SIGHTENGINE_API_USER && process.env.SIGHTENGINE_API_SECRET);
  add("sightengine", "Sightengine", "Listing-image moderation", sightengineConfigured ? "configured" : "not_configured",
    sightengineConfigured ? "Moderation credentials are present. Live image analysis is skipped to avoid consuming moderation quota." : "Sightengine credentials are missing.",
    { liveCheck: false });

  const ipqsConfigured = !!process.env.IPQS_API_KEY;
  add("ipqs", "IPQualityScore", "VPN/proxy and phone-risk checks", ipqsConfigured ? "configured" : "not_configured",
    ipqsConfigured ? "Risk-check API key is present. Live lookup is skipped to avoid consuming quota." : "IPQS_API_KEY is missing; VPN/phone risk checks will be skipped.",
    { liveCheck: false });

  const termiiConfigured = !!process.env.TERMII_API_KEY;
  add("termii", "Termii", "SMS/phone verification", termiiConfigured ? "configured" : "not_configured",
    termiiConfigured ? "SMS API key is present. No test SMS is sent by this health check." : "TERMII_API_KEY is missing; SMS verification is unavailable.",
    { liveCheck: false });

  const problems = services.filter((service) => service.status === "unhealthy");
  res.json({
    checkedAt: new Date().toISOString(),
    overall: problems.length ? "degraded" : "operational",
    services,
  });
});

async function requireTicketAccess(req, res, next) {
  try {
    const result = await pool.query("SELECT user_id FROM support_tickets WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Ticket not found" });
    if (result.rows[0].user_id !== req.user.id && !hasPermission(req.user, "support_tickets")) {
      return res.status(403).json({ error: "You can only view your own tickets" });
    }
    next();
  } catch (err) {
    sendInternalError(res, err);
  }
}

app.get("/support-tickets/:id/messages", authenticate, requireTicketAccess, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT stm.*, u.username, u.display_name, u.is_admin
       FROM support_ticket_messages stm JOIN users u ON stm.sender_id = u.id
       WHERE stm.ticket_id = $1 ORDER BY stm.created_at ASC`,
      [req.params.id]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    sendInternalError(res, err);
  }
});

app.post("/support-tickets/:id/messages", authenticate, requireTicketAccess, async (req, res) => {
  try {
    const { body } = req.body;
    if (!body?.trim()) return res.status(400).json({ error: "Message can't be empty" });
    const result = await pool.query(
      "INSERT INTO support_ticket_messages (ticket_id, sender_id, body) VALUES ($1, $2, $3) RETURNING *",
      [req.params.id, req.user.id, body.trim()]
    );
    await pool.query("UPDATE support_tickets SET updated_at = NOW() WHERE id = $1", [req.params.id]);
    if (req.user.isAdmin && hasPermission(req.user, "support_tickets")) {
      logAdminAction(req.user.id, "support_reply_sent", `Sent an admin reply on support ticket #${req.params.id}`);
    }
    res.status(201).json({ message: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
  }
});

const TICKET_STATUSES = new Set(["open", "in_progress", "resolved"]);

app.patch("/support-tickets/:id/status", authenticate, requirePermission("support_tickets"), async (req, res) => {
  try {
    const { status } = req.body;
    if (!TICKET_STATUSES.has(status)) return res.status(400).json({ error: "Invalid status" });
    const result = await pool.query(
      "UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
      [status, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Ticket not found" });
    logAdminAction(req.user.id, "support_ticket_status_changed", `Changed support ticket #${req.params.id} to ${status}`);
    res.json({ ticket: result.rows[0] });
  } catch (err) {
    sendInternalError(res, err);
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
    sendInternalError(res, err);
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
    sendInternalError(res, err);
  }
});

app.patch("/notifications/mark-all-read", authenticate, async (req, res) => {
  try {
    await pool.query("UPDATE notifications SET read = true WHERE user_id = $1 AND read = false", [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    sendInternalError(res, err);
  }
});

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
// Final Express safety net for unexpected middleware/route failures. Never send
// stack traces, SQL text, or provider internals to the browser.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  return sendInternalError(res, err, `${req.method} ${req.path}`);
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await applyPendingMigrations();
    await ensurePrivateVerificationBucket();
    await encryptLegacyTotpSecrets();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      setInterval(sendShipReminders, 60 * 60 * 1000).unref();
      // Check hourly; the persisted report date and advisory lock guarantee a
      // single daily send at/after 08:00 Africa/Lagos, even across restarts.
      setInterval(() => sendDailyCasualSellerReport(false), 60 * 60 * 1000).unref();
      setInterval(() => sendDailyVerifiedSellerReport(false), 60 * 60 * 1000).unref();
      sendShipReminders();
      sendDailyCasualSellerReport(false);
      sendDailyVerifiedSellerReport(false);
    });
  } catch (err) {
    // Fail the deployment instead of starting against a half-migrated schema.
    console.error("Database migration failed; backend will not start:", err.message);
    process.exit(1);
  }
}

startServer();
