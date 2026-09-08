const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const fetch = require("node-fetch");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

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
    production ? "SameSite=None" : "SameSite=Lax",
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
    production ? "SameSite=None" : "SameSite=Lax",
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
    res.status(500).json({ error: err.message });
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
  order_dispute: new Set(["dispute_resolution", "order_access", "order_management"]),
  finance: new Set(["finance", "order_access"]),
  customer_support: new Set(["support_tickets", "message_moderation"]),
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

const vpnCheckCache = new Map();
const VPN_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.ip;
}

function rateLimit({ windowMs, max, message, keyFn }) {
  const hits = new Map();
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [key, entry] of hits) {
      if (entry.start < cutoff) hits.delete(key);
    }
  }, Math.max(windowMs, 60000)).unref();
  return (req, res, next) => {
    const key = keyFn ? keyFn(req) : (getClientIp(req) || "unknown");
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

const codeRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, message: "Too many attempts — please wait 15 minutes and try again." });

// Payout-bank changes are especially sensitive because they control where seller
// money is sent. Protect both code issuance and verification independently from
// the general authentication limiter.
const bankChangeSendUserRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: "Too many bank-change confirmation codes requested — wait 15 minutes and try again.",
  keyFn: (req) => `bank-change-send:user:${req.user?.id || "unknown"}`,
});
const bankChangeSendIpRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6,
  message: "Too many bank-change confirmation requests from this connection — wait 15 minutes and try again.",
  keyFn: (req) => `bank-change-send:ip:${getClientIp(req) || "unknown"}`,
});
const bankChangeConfirmRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: "Too many bank-change code attempts — wait 15 minutes and request a new code.",
  keyFn: (req) => `bank-change-confirm:${req.user?.id || "unknown"}:${getClientIp(req) || "unknown"}`,
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

async function createCheckoutIntent({ reference, buyerId, buyerUsername, buyerEmail, amountKobo, items, shippingAddress, saveCard = false }) {
  await pool.query(
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
          listing.owner_id, seller?.username, seller?.display_name, generateDeliveryTokenValue(),
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
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many SMS code requests from this connection — wait 15 minutes and try again.",
});
const smsSendPhoneRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: "Too many SMS codes were requested for this phone number — wait 15 minutes and try again.",
  keyFn: (req) => `phone:${normalizePhoneForRateLimit(req.body?.phone) || "missing"}`,
});
const smsCheckRateLimit = rateLimit({
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
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: "You've uploaded a lot of images recently — wait 15 minutes before uploading more.",
  keyFn: (req) => `user:${req.user?.id || "unknown"}`,
});
const imageUploadIpBurstRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: "Too many image uploads from this connection — wait 15 minutes and try again.",
  keyFn: (req) => `ip:${getClientIp(req) || "unknown"}`,
});
const imageUploadUserDailyRateLimit = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 120,
  message: "Daily image upload limit reached — try again tomorrow or contact support if you need help.",
  keyFn: (req) => `user:${req.user?.id || "unknown"}`,
});
const MAX_IMAGE_UPLOAD_BYTES = 8 * 1024 * 1024;

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

const termiiPinIds = new Map();
const TERMII_PIN_TTL_MS = 10 * 60 * 1000;

const verifiedPhones = new Map();
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
    termiiPinIds.set(phone, { pinId: data.pinId, sentAt: Date.now() });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/phone-verify/check", smsCheckRateLimit, async (req, res) => {
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

const emailCodes = new Map();
const EMAIL_CODE_TTL_MS = 15 * 60 * 1000;

const verifiedEmails = new Map();
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
    emailCodes.set(email.toLowerCase(), { code, sentAt: Date.now() });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

const passwordResetCodes = new Map();
const PASSWORD_RESET_CODE_TTL_MS = 15 * 60 * 1000;

// Tracks an admin who used a Super-Admin-issued temporary password for step 1.
// The temporary password itself is stored only as a bcrypt hash in PostgreSQL;
// this short-lived marker only carries the recovery state through TOTP + email.
const adminTemporaryLoginMarkers = new Map();
const ADMIN_TEMP_PASSWORD_TTL_MS = 10 * 60 * 1000;

const twoFactorCodes = new Map();
const TWO_FACTOR_CODE_TTL_MS = 10 * 60 * 1000;

const twoFactorEnableCodes = new Map();

const totpVerifiedMarkers = new Map();
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

function hashField(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

const pendingBankChanges = new Map();
const BANK_CHANGE_CODE_TTL_MS = 15 * 60 * 1000;

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
    passwordResetCodes.set(key, { code, sentAt: Date.now() });
    const maskedEmail = email.replace(/^(.{1,2}).*(@.*)$/, (m, a, b) => `${a}***${b}`);
    res.json({ success: true, maskedEmail });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    res.status(500).json({ error: err.message });
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
    if (!result.rows[0].is_admin) setAuthCookie(res, result.rows[0]);
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username or email already in use" });
    }
    res.status(500).json({ error: err.message });
  }
});

app.patch("/profile/complete", authenticate, async (req, res) => {
  try {
    const {
      firstName, lastName, phone, officeLocation, country, accountType,
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

    const hasCore = firstName && lastName && country;
    const hasId = !!idVerificationExempt || (idType && licenseNumber);
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.post("/addresses", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    const { label, street, city, state, zip, country, isDefault } = req.body;
    if (!street || !city || !country) {
      return res.status(400).json({ error: "Street, city, and country are required" });
    }
    if (!isNigeriaCountry(country)) {
      return res.status(400).json({ error: "Stallyard shipping addresses must be in Nigeria" });
    }
    const existingCount = await pool.query("SELECT COUNT(*) FROM user_addresses WHERE user_id = $1", [req.user.id]);
    const shouldBeDefault = !!isDefault || Number(existingCount.rows[0].count) === 0;
    if (shouldBeDefault) {
      await pool.query("UPDATE user_addresses SET is_default = false WHERE user_id = $1", [req.user.id]);
    }
    const result = await pool.query(
      `INSERT INTO user_addresses (user_id, label, street, city, state, zip, country, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.user.id, label || "", street, city, state || "", zip || "", country, shouldBeDefault]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/addresses/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT * FROM user_addresses WHERE id = $1", [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: "Address not found" });
    if (existing.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only edit your own addresses" });
    }
    const { label, street, city, state, zip, country } = req.body;
    const current = existing.rows[0];
    const nextCountry = country ?? current.country;
    if (!isNigeriaCountry(nextCountry)) {
      return res.status(400).json({ error: "Stallyard shipping addresses must be in Nigeria" });
    }
    const result = await pool.query(
      `UPDATE user_addresses SET label = $1, street = $2, city = $3, state = $4, zip = $5, country = $6
       WHERE id = $7 RETURNING *`,
      [
        label ?? current.label,
        street ?? current.street,
        city ?? current.city,
        state ?? current.state,
        zip ?? current.zip,
        country ?? current.country,
        req.params.id,
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    twoFactorEnableCodes.set(req.user.id, { code, sentAt: Date.now() });
    res.json({ sent: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/profile/two-factor/enable/verify", authenticate, async (req, res) => {
  try {
    if (req.user.isAdmin) {
      return res.status(400).json({ error: "Admin accounts use an authenticator app — see /admin/totp/setup" });
    }
    const { code } = req.body;
    const stored = twoFactorEnableCodes.get(req.user.id);
    if (!stored || Date.now() - stored.sentAt > TWO_FACTOR_CODE_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — request a new one" });
    }
    if (stored.code !== String(code || "").trim()) {
      return res.status(400).json({ error: "That code doesn't match" });
    }
    twoFactorEnableCodes.delete(req.user.id);
    const result = await pool.query(
      "UPDATE users SET two_factor_enabled = true WHERE id = $1 RETURNING two_factor_enabled",
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });
    res.json({ twoFactorEnabled: result.rows[0].two_factor_enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/admin/totp/setup", authenticate, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const secret = generateTotpSecret();
    await pool.query("UPDATE users SET totp_secret = $1 WHERE id = $2", [secret, req.user.id]);
    const label = encodeURIComponent(`Stallyard:${req.user.username}`);
    const issuer = encodeURIComponent("Stallyard");
    const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(otpauthUrl)}`;
    res.json({ secret, otpauthUrl, qrCodeUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    if (!verifyTotpCode(result.rows[0].totp_secret, code)) {
      return res.status(400).json({ error: "That code doesn't match — check your authenticator app and try again" });
    }
    const updated = await pool.query(
      "UPDATE users SET two_factor_enabled = true WHERE id = $1 RETURNING two_factor_enabled",
      [req.user.id]
    );
    res.json({ twoFactorEnabled: updated.rows[0].two_factor_enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.json({ twoFactorRequired: true, method: "totp" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/admin/reauth/verify", authenticate, authRateLimit, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const { code } = req.body;
    const result = await pool.query("SELECT email, totp_secret FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: "Account not found" });

    if (!result.rows[0].totp_secret || !verifyTotpCode(result.rows[0].totp_secret, code)) {
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
    twoFactorCodes.set(req.user.id, { code: emailCode, sentAt: Date.now() });
    totpVerifiedMarkers.set(req.user.id, Date.now());
    res.json({ emailStepRequired: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/admin/reauth/verify-email", authenticate, authRateLimit, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required" });
    const { code } = req.body;
    const marker = totpVerifiedMarkers.get(req.user.id);
    if (!marker || Date.now() - marker > TOTP_VERIFIED_MARKER_TTL_MS) {
      return res.status(400).json({ error: "Your authenticator step expired — start over" });
    }
    const stored = twoFactorCodes.get(req.user.id);
    if (!stored || Date.now() - stored.sentAt > TWO_FACTOR_CODE_TTL_MS) {
      return res.status(400).json({ error: "That email code has expired — start over" });
    }
    if (stored.code !== String(code || "").trim()) {
      return res.status(400).json({ error: "That code doesn't match" });
    }
    twoFactorCodes.delete(req.user.id);
    totpVerifiedMarkers.delete(req.user.id);

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
    res.status(500).json({ error: err.message });
  }
});

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
    res.status(500).json({ error: err.message });
  }
});

const USER_PUBLIC_FIELDS = `id, username, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, verification_status, created_at,
  avatar_url, store_bio, store_policies, is_email_verified, is_phone_verified`;

const USER_FULL_FIELDS = `id, username, email, phone, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, verification_status,
  bank_statement_url, rejection_reason, created_at, avatar_url, store_bio, store_policies, two_factor_enabled,
  is_email_verified, is_phone_verified, admin_role`;

// Safe admin directory fields. Admin roles that do not perform seller verification
// can still resolve role/2FA state for UI permissions, but do NOT receive member
// email, phone, ID/license data, ID photos, bank statements, or rejection details.
const USER_ADMIN_SAFE_FIELDS = `${USER_PUBLIC_FIELDS}, two_factor_enabled, admin_role`;

app.get("/users", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const hasBearerToken = authHeader.startsWith("Bearer ");
    let fields = USER_PUBLIC_FIELDS;

    // /users is public for storefront/profile discovery, but a caller that
    // presents a token must not get any privileged behavior from stale JWT
    // claims. Revalidate the account against PostgreSQL every time before
    // exposing admin-only directory fields.
    if (hasBearerToken) {
      const requester = getRequester(req);
      if (!requester?.id) {
        return res.status(401).json({ error: "Your session is no longer valid — log in again" });
      }

      const authCheck = await pool.query(
        `SELECT is_admin, is_suspended, token_version, admin_role, two_factor_enabled
         FROM users WHERE id = $1`,
        [requester.id]
      );
      if (!authCheck.rows.length) {
        return res.status(401).json({ error: "Account no longer exists" });
      }

      const current = authCheck.rows[0];
      if (current.is_suspended) {
        return res.status(403).json({ error: "This account has been suspended" });
      }
      if ((requester.tokenVersion || 0) !== (current.token_version || 0)) {
        return res.status(401).json({ error: "Your session was signed out from another device — log in again" });
      }

      if (current.is_admin) {
        // A revoked admin token can never reach this branch because both the
        // current DB role and token_version are checked above. Full seller
        // verification documents additionally require mandatory admin 2FA and
        // the specific role that needs those documents.
        const role = current.admin_role || "super_admin";
        if (!current.two_factor_enabled) {
          return res.status(403).json({
            error: "Two-factor authentication is required for admin accounts",
            code: "2FA_REQUIRED",
          });
        }
        const canReviewSellerPrivateData = role === "super_admin" || role === "seller_verification";
        fields = canReviewSellerPrivateData ? USER_FULL_FIELDS : USER_ADMIN_SAFE_FIELDS;
      }
    }

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
  is_email_verified, is_phone_verified, token_version, admin_role`;

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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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

    passwordResetCodes.set(target.username.trim().toLowerCase(), { code, sentAt: Date.now() });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.patch("/users/:id/approve", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users SET is_approved = true, verification_status = 'approved', rejection_reason = NULL
       WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.user.id, "seller_approved", `Approved ${result.rows[0].username}'s seller application`);
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch("/users/:id/reject", authenticate, requirePermission("seller_verification"), async (req, res) => {
  try {
    const { reason } = req.body;
    const result = await pool.query(
      `UPDATE users SET is_approved = false, verification_status = 'rejected', rejection_reason = $1
       WHERE id = $2 RETURNING ${USER_RETURNING_FIELDS}`,
      [reason || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.user.id, "seller_rejected", `Rejected ${result.rows[0].username}'s seller application${reason ? ": " + reason : ""}`);
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.get("/follows", async (req, res) => {
  try {
    const result = await pool.query("SELECT follower_username, followed_username FROM follows");
    res.json({ follows: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    if (temporaryPasswordMatches) {
      adminTemporaryLoginMarkers.set(Number(user.id), { expiresAt: tempExpiry });
    } else {
      adminTemporaryLoginMarkers.delete(Number(user.id));
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

    // Password is step 1. The existing verify-2fa endpoint performs TOTP
    // (step 2), then sends the email code required for step 3.
    res.json({ twoFactorRequired: true, userId: user.id, method: "totp" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Keep session restoration deliberately small. This endpoint is called on page
// load, so it must never return seller verification documents, bank data,
// government-ID details, or other private profile records.
const SESSION_USER_FIELDS = `id, username, email, phone, display_name, first_name, last_name,
  country, is_admin, is_approved, is_verified, is_suspended, account_type,
  has_applied_to_sell, verification_status, avatar_url, store_bio, store_policies,
  two_factor_enabled, is_email_verified, is_phone_verified, token_version, admin_role`;

app.get("/session/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT ${SESSION_USER_FIELDS} FROM users WHERE id = $1`, [req.user.id]);
    if (!result.rows.length) {
      clearAuthCookie(res);
      return res.status(401).json({ error: "Session account no longer exists" });
    }
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/logout", (req, res) => {
  clearAuthCookie(res);
  res.json({ success: true });
});

app.post("/login", authRateLimit, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing username or password" });
    }

    const result = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS}, password_hash, totp_secret
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
      twoFactorCodes.set(user.id, { code, sentAt: Date.now() });
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
    res.status(500).json({ error: err.message });
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
      if (!user.totp_secret || !verifyTotpCode(user.totp_secret, code)) {
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
      twoFactorCodes.set(Number(userId), { code: emailCode, sentAt: Date.now() });
      totpVerifiedMarkers.set(Number(userId), Date.now());
      return res.json({ emailStepRequired: true, userId: user.id });
    }

    const stored = twoFactorCodes.get(Number(userId));
    if (!stored || Date.now() - stored.sentAt > TWO_FACTOR_CODE_TTL_MS) {
      return res.status(400).json({ error: "That code has expired — log in again to get a new one" });
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    twoFactorCodes.delete(Number(userId));

    delete user.totp_secret;
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    pool
      .query("INSERT INTO login_history (user_id, ip, user_agent) VALUES ($1, $2, $3)", [user.id, ip, userAgent])
      .catch((err) => console.error("Failed to record login history:", err.message));
    setAuthCookie(res, user);
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/login/verify-2fa-email", authRateLimit, async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: "Missing userId or code" });

    const marker = totpVerifiedMarkers.get(Number(userId));
    if (!marker || Date.now() - marker > TOTP_VERIFIED_MARKER_TTL_MS) {
      return res.status(400).json({ error: "Your authenticator step expired — log in again from the start" });
    }
    const stored = twoFactorCodes.get(Number(userId));
    if (!stored || Date.now() - stored.sentAt > TWO_FACTOR_CODE_TTL_MS) {
      return res.status(400).json({ error: "That email code has expired — log in again to get a new one" });
    }
    if (stored.code !== String(code).trim()) {
      return res.status(400).json({ error: "That code doesn't match — check and try again" });
    }
    twoFactorCodes.delete(Number(userId));
    totpVerifiedMarkers.delete(Number(userId));

    const result = await pool.query(
      `SELECT ${USER_RETURNING_FIELDS}
       FROM users WHERE id = $1`,
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found" });
    const user = result.rows[0];
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";

    const tempMarker = user.is_admin ? adminTemporaryLoginMarkers.get(Number(user.id)) : null;
    if (tempMarker && tempMarker.expiresAt > Date.now()) {
      adminTemporaryLoginMarkers.delete(Number(user.id));
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
    adminTemporaryLoginMarkers.delete(Number(user.id));

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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

// Publishes a new listing. RETURNING * only pulls columns from the
// listings table itself, so seller_name/owner_username (which the
// frontend needs to attribute the listing to the right seller, e.g. for
// "My Stall" filtering) aren't in that row — they only come from the JOIN
// in GET /listings. Fetching them here and merging them into the response
// keeps a freshly published listing consistent with what a page refresh
// would show, instead of silently missing its owner until then.
app.post("/listings", authenticate, rejectAdminMarketplaceUse, requireNigeriaMarketplaceUser, async (req, res) => {
  try {
    const {
      title, description, price, category, condition, shippingFee,
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

    // The frontend already hides the listing form until a seller is
    // approved, but that's only a UI convenience — enforce it here too,
    // since nothing stops someone from calling this endpoint directly.
    const sellerCheck = await pool.query("SELECT is_approved, username, display_name FROM users WHERE id = $1", [ownerId]);
    if (!sellerCheck.rows.length || !sellerCheck.rows[0].is_approved) {
      return res.status(403).json({ error: "Your seller account must be approved before you can list items." });
    }

    // "active" is the one canonical live listing status across browse, checkout, and moderation.
    // Approved sellers may create a draft or publish live; legacy client value "approved" is treated as live.
    const listingStatus = status === "draft" ? "draft" : "active";

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
        listingType || "fixed", "NGN", listingStatus,
        auctionEndTime ? new Date(auctionEndTime) : null,
        quantity === "" || quantity === undefined || quantity === null ? null : Number(quantity),
        sku || "", brand || "", state || "", JSON.stringify(shippingMethods || []),
        returnPolicy || "", vin || "",
      ]
    );

    const listingWithOwner = {
      ...result.rows[0],
      owner_username: sellerCheck.rows[0].username,
      seller_name: sellerCheck.rows[0].display_name,
    };

    res.status(201).json({ listing: listingWithOwner });
    moderateListingImagesAsync(result.rows[0].id, images);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

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
    if (existing.rows[0].owner_id !== req.user.id && !hasPermission(req.user, "listing_moderation")) {
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
        } else if (key === "status") {
          const normalizedStatus = raw === "approved" ? "active" : raw;
          const allowedStatuses = new Set(["draft", "pending", "active", "paused", "sold", "rejected", "removed"]);
          if (!allowedStatuses.has(normalizedStatus)) {
            return res.status(400).json({ error: "Invalid listing status" });
          }
          values.push(normalizedStatus);
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
    if (existing.rows[0].owner_id !== req.user.id) {
      logAdminAction(req.user.id, "listing_moderated", `Updated listing "${result.rows[0].title}" (${Object.keys(req.body).join(", ")})`);
    }
    if (req.body.status === "rejected") {
      createNotification(existing.rows[0].owner_id, "listing_rejected", `Your listing "${result.rows[0].title}" was rejected`);
    }
    res.json({ listing: result.rows[0] });
    if (Object.prototype.hasOwnProperty.call(req.body, "images")) {
      moderateListingImagesAsync(result.rows[0].id, req.body.images);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.delete("/listings/by-owner/:ownerId", authenticate, requirePermission("user_management"), async (req, res) => {
  try {
    const removed = await pool.query("DELETE FROM listings WHERE owner_id = $1 RETURNING id", [req.params.ownerId]);
    logAdminAction(req.user.id, "seller_listings_removed", `Removed ${removed.rowCount} listing${removed.rowCount === 1 ? "" : "s"} belonging to user #${req.params.ownerId}`);
    res.json({ success: true, removedCount: removed.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    await createCheckoutIntent({
      reference, buyerId: req.user.id, buyerUsername: req.user.username, buyerEmail: email,
      amountKobo, items: itemSnapshots, shippingAddress, saveCard: !!saveCard,
    });

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
          shippingAddress: shippingAddress || {},
          currency: "NGN",
          saveCard: !!saveCard,
        },
      }),
    });
    const paystackData = await paystackRes.json();
    if (!paystackData.status) {
      await markCheckoutIntent(reference, "failed", paystackData.message || "Paystack initialization failed");
      await recordPaymentAttempt(req.user.id, { reference, method: "checkout_initialize", status: "failed", amount: total, currency: "NGN", message: paystackData.message || "Paystack error" });
      return res.status(500).json({ error: paystackData.message || "Paystack error" });
    }
    if (String(paystackData.data?.reference || "") !== reference) {
      await markCheckoutIntent(reference, "failed", "Paystack returned a different reference");
      return res.status(502).json({ error: "Payment initialization integrity check failed — please try again" });
    }
    await recordPaymentAttempt(req.user.id, { reference, method: "checkout_initialize", status: "initialized", amount: total, currency: "NGN" });
    res.json({ authorizationUrl: paystackData.data.authorization_url, reference });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/checkout/verify/:reference", authenticate, async (req, res) => {
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
    res.status(500).json({ error: err.message });
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
    await createCheckoutIntent({
      reference, buyerId: req.user.id, buyerUsername: req.user.username, buyerEmail: email,
      amountKobo, items: itemSnapshots, shippingAddress, saveCard: false,
    });

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
          shippingAddress: shippingAddress || {},
          currency: "NGN",
        },
      }),
    });
    const chargeData = await chargeRes.json();
    if (!chargeData.status || chargeData.data.status !== "success") {
      await markCheckoutIntent(reference, "failed", chargeData.data?.gateway_response || chargeData.message || "Payment failed");
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
    res.status(500).json({ error: err.message });
  }
});

async function fetchOrdersWithItems(whereClause, params, { includeDeliveryTokens = false } = {}) {
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
  const safeItems = itemsResult.rows.map((item) => {
    if (includeDeliveryTokens) return item;
    const { delivery_token, ...safe } = item;
    return safe;
  });
  return orders.map((o) => ({
    ...o,
    items: safeItems.filter((i) => i.order_id === o.id),
  }));
}

app.get("/orders/mine", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
  try {
    // Only the buyer may receive the secret delivery token.
    const orders = await fetchOrdersWithItems("buyer_id = $1", [req.user.id], { includeDeliveryTokens: true });
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/orders/selling", authenticate, rejectAdminMarketplaceUse, async (req, res) => {
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

app.get("/orders", authenticate, requirePermission("order_access"), async (req, res) => {
  try {
    const orders = await fetchOrdersWithItems("TRUE", []);
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
      `SELECT id, title, fulfillment_status, buyer_confirmed_at, proof_of_delivery_url, return_status
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
      if (!item.buyer_confirmed_at) {
        safeguardProblems.push(`Item #${item.id} (${item.title}): buyer delivery token has not been redeemed`);
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.patch("/orders/:id/dispute", authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { isDisputed, reason, statement, evidenceUrls } = req.body;
    await client.query("BEGIN");
    const orderCheck = await client.query("SELECT buyer_id FROM orders WHERE id = $1 FOR UPDATE", [req.params.id]);
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

const ORDER_ITEM_STATUSES = new Set(["new", "preparing", "shipped", "delivered", "cancelled", "returned"]);

app.patch("/order-items/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT seller_id FROM order_items WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    const isOwnSellerItem = existing.rows[0].seller_id === req.user.id;
    if (!isOwnSellerItem && !hasPermission(req.user, "order_management")) {
      return res.status(403).json({ error: "Only the seller, Order/Dispute Admin, or Super Admin can update fulfillment details" });
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
    if (!isOwnSellerItem) {
      logAdminAction(req.user.id, "order_item_fulfillment_updated", `Updated fulfillment details for order item #${req.params.id}`);
    }
    res.json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function markItemReceivedAndMaybeRelease(itemId) {
  const result = await pool.query(
    "UPDATE order_items SET buyer_confirmed_at = NOW(), delivery_token = NULL, delivery_token_generated_at = NULL WHERE id = $1 RETURNING *",
    [itemId]
  );
  const item = result.rows[0];
  createNotification(item.seller_id, "delivery_confirmed", `Buyer confirmed delivery for "${item.title}"`);
  const allItems = await pool.query("SELECT * FROM order_items WHERE order_id = $1", [item.order_id]);
  const relevant = allItems.rows.filter((r) => !["cancelled", "returned"].includes(r.fulfillment_status));
  const allConfirmed = relevant.length > 0 && relevant.every(
    (r) => r.buyer_confirmed_at && r.proof_of_delivery_url && !["requested", "approved"].includes(r.return_status)
  );
  let order = null;
  if (allConfirmed) {
    const orderRes = await pool.query(
      `UPDATE orders SET payment_status = 'released'
       WHERE id = $1 AND payment_status = 'held' AND COALESCE(is_disputed, false) = false
       RETURNING *`,
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

app.patch("/order-items/:id/confirm-receipt", authenticate, async (req, res) => {
  // Stallyard's release flow requires the seller to submit BOTH the buyer's
  // delivery token and proof-of-delivery photo. A buyer-side confirmation
  // must not bypass those safeguards.
  return res.status(400).json({
    error: "Delivery is confirmed when the seller submits your delivery code together with proof of delivery."
  });
});

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
            `UPDATE order_items SET return_status = 'approved', fulfillment_status = 'returned' WHERE id = $1 RETURNING *`,
            [req.params.id]
          )
        : await pool.query(`UPDATE order_items SET return_status = 'denied' WHERE id = $1 RETURNING *`, [req.params.id]);
    if (item.seller_id !== req.user.id) {
      logAdminAction(req.user.id, "return_decided", `${decision === "approved" ? "Approved" : "Denied"} return on item "${item.title}"`);
    }
    res.json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

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
      return res.status(403).json({ error: "Only the buyer can access a delivery code for this item" });
    }
    if (item.buyer_confirmed_at) {
      return res.status(400).json({ error: "This item has already been confirmed as received" });
    }
    // Tokens are normally generated automatically when payment succeeds.
    // This endpoint only recovers/creates one for older orders or migrations.
    if (item.delivery_token) return res.json({ token: item.delivery_token });
    const token = generateDeliveryTokenValue();
    await pool.query(
      "UPDATE order_items SET delivery_token = $1, delivery_token_generated_at = NOW() WHERE id = $2",
      [token, req.params.id]
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    if (item.is_disputed) {
      return res.status(409).json({ error: "Payment is locked because this order has an active dispute" });
    }
    if (["requested", "approved"].includes(item.return_status)) {
      return res.status(409).json({ error: "Payment is locked because a return is in progress" });
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
    res.status(500).json({ error: err.message });
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

    if (event.event && event.event.startsWith("refund.")) {
      const data = event.data || {};
      const transactionReference = data.transaction_reference || data.transaction?.reference || null;
      if (transactionReference) {
        try {
          const orderResult = await pool.query(
            "SELECT id, buyer_id, payment_status, refund_previous_payment_status, refund_type, refund_amount, currency FROM orders WHERE paystack_reference = $1",
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
              createNotification(order.buyer_id, "refund_processed", isPartialRefund
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
    res.status(500).json({ error: err.message });
  }
});

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
    [encryptField(bankCode), encryptField(accountNumber), encryptField(recipientData.data.recipient_code), userId]
  );
  return { recipientCode: recipientData.data.recipient_code };
}

app.post(
  "/sellers/bank-details",
  authenticate,
  bankChangeSendIpRateLimit,
  bankChangeSendUserRateLimit,
  async (req, res) => {
  try {
    const { userId, bankCode, accountNumber, adminOverrideReason } = req.body;

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

    if (!hadAccountBefore || isAdminOverride) {
      const result = await verifyAndSaveBankDetails(targetUserId, bankCode, accountNumber);
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

      return res.json({ success: true, recipientCode: result.recipientCode });
    }

    const email = existing.rows[0].email;
    if (!email) {
      return res.status(400).json({ error: "No email on file to confirm this change — contact support" });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ error: "Bank-change confirmation isn't configured yet" });
    }

    const existingPendingChange = pendingBankChanges.get(req.user.id);
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
    pendingBankChanges.set(req.user.id, {
      code,
      sentAt: Date.now(),
      bankCode,
      accountNumber,
      failedAttempts: 0,
    });
    res.json({ confirmationRequired: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
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

    const pending = pendingBankChanges.get(req.user.id);
    if (!pending || Date.now() - pending.sentAt > BANK_CHANGE_CODE_TTL_MS) {
      pendingBankChanges.delete(req.user.id);
      return res.status(400).json({ error: "That code has expired — start the change again" });
    }

    const expectedBuffer = Buffer.from(String(pending.code));
    const submittedBuffer = Buffer.from(submittedCode);
    const codeMatches = expectedBuffer.length === submittedBuffer.length &&
      crypto.timingSafeEqual(expectedBuffer, submittedBuffer);

    if (!codeMatches) {
      pending.failedAttempts = Number(pending.failedAttempts || 0) + 1;
      if (pending.failedAttempts >= BANK_CHANGE_MAX_CODE_ATTEMPTS) {
        pendingBankChanges.delete(req.user.id);
        return res.status(429).json({
          error: "Too many incorrect bank-change codes — start the bank change again to receive a new code.",
        });
      }
      return res.status(400).json({
        error: "That code doesn't match — check and try again",
        attemptsRemaining: BANK_CHANGE_MAX_CODE_ATTEMPTS - pending.failedAttempts,
      });
    }

    pendingBankChanges.delete(req.user.id);
    const result = await verifyAndSaveBankDetails(req.user.id, pending.bankCode, pending.accountNumber);
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json({ success: true, recipientCode: result.recipientCode });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    res.status(500).json({ error: err.message });
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
    `SELECT COALESCE(SUM(amount), 0) AS reserved
     FROM withdrawals WHERE seller_id = $1 AND status IN ('processing', 'paid')`,
    [sellerId]
  );
  const released = Number(releasedResult.rows[0].released_total);
  const reserved = Number(reservedResult.rows[0].reserved);
  return Math.round((released - reserved) * 100) / 100;
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.get("/withdrawals", authenticate, requirePermission("finance"), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM withdrawals ORDER BY requested_at DESC");
    res.json({ withdrawals: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
      return res.status(502).json({ error: data.message || "Couldn't verify this transaction with Paystack" });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

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
    const buyerId = req.user.id;

    if (!orderId || !listingId || !sellerId || !rating) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
    }

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
    if (existing.rows[0].buyer_id !== req.user.id) {
      return res.status(403).json({ error: "Only the buyer who wrote this review can edit it" });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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

app.get("/content", async (req, res) => {
  try {
    const [banners, articles, faqs] = await Promise.all([
      pool.query("SELECT * FROM banners ORDER BY created_at DESC"),
      pool.query("SELECT * FROM help_articles ORDER BY created_at DESC"),
      pool.query("SELECT * FROM help_faqs ORDER BY created_at ASC"),
    ]);
    res.json({ banners: banners.rows, articles: articles.rows, faqs: faqs.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.delete("/content/banners/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    await pool.query("DELETE FROM banners WHERE id = $1", [req.params.id]);
    logAdminAction(req.user.id, "banner_removed", `Removed banner #${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.delete("/content/articles/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    await pool.query("DELETE FROM help_articles WHERE id = $1", [req.params.id]);
    logAdminAction(req.user.id, "article_removed", `Removed help article #${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

app.delete("/content/faqs/:id", authenticate, requirePermission("content_management"), async (req, res) => {
  try {
    await pool.query("DELETE FROM help_faqs WHERE id = $1", [req.params.id]);
    logAdminAction(req.user.id, "faq_removed", `Removed FAQ #${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/policies", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM marketplace_policies");
    res.json({ policies: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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

async function backfillMissingDeliveryTokens() {
  // Orders finalized before automatic token creation may be missing the buyer's
  // delivery code. Only backfill still-held, unconfirmed paid orders.
  const result = await pool.query(
    `SELECT oi.id
     FROM order_items oi
     JOIN orders o ON o.id = oi.order_id
     WHERE o.payment_status = 'held'
       AND oi.buyer_confirmed_at IS NULL
       AND (oi.delivery_token IS NULL OR oi.delivery_token = '')`
  );
  for (const row of result.rows) {
    await pool.query(
      `UPDATE order_items
       SET delivery_token = $1, delivery_token_generated_at = NOW()
       WHERE id = $2 AND (delivery_token IS NULL OR delivery_token = '')`,
      [generateDeliveryTokenValue(), row.id]
    );
  }
  if (result.rows.length) {
    console.log(`Backfilled delivery tokens for ${result.rows.length} held order item(s).`);
  }
}

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
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await applyPendingMigrations();
    await backfillMissingDeliveryTokens();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      setInterval(sendShipReminders, 60 * 60 * 1000).unref();
      sendShipReminders();
    });
  } catch (err) {
    // Fail the deployment instead of starting against a half-migrated schema.
    console.error("Database migration failed; backend will not start:", err.message);
    process.exit(1);
  }
}

startServer();
