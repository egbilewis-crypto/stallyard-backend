const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const fetch = require("node-fetch");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

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
    { id: user.id, username: user.username, isAdmin: !!user.is_admin },
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

// Requires a valid token. Attaches the decoded payload as req.user.
function authenticate(req, res, next) {
  const requester = getRequester(req);
  if (!requester) return res.status(401).json({ error: "Sign in required" });
  req.user = requester;
  next();
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
    if (valid) termiiPinIds.delete(phone);
    res.json({ valid });
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

// One-time migration: adds the columns needed for account type, ID
// verification documents, and admin-facing member data. Safe to visit
// more than once — IF NOT EXISTS means it won't duplicate anything.
app.get("/migrate/members-extra", async (req, res) => {
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
app.get("/migrate/follows", async (req, res) => {
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
app.get("/migrate/listings-extra", async (req, res) => {
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
app.get("/migrate/orders-wallet", async (req, res) => {
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

app.post("/signup", async (req, res) => {
  try {
    const {
      username, email, phone, password, displayName, firstName, lastName,
      officeLocation, country, accountType, idType, idCountry, licenseNumber,
      licensePhotos, idVerificationExempt,
    } = req.body;

    if (!username || !email || !phone || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const vpnDetected = await isVpnOrProxy(getClientIp(req));
    if (vpnDetected) {
      return res.status(403).json({ error: "Sign-ups aren't allowed over a VPN, proxy, or Tor connection. Please disable it and try again." });
    }

    const phoneCheck = await checkPhoneNumber(phone);
    if (phoneCheck?.blocked) {
      return res.status(400).json({ error: phoneCheck.reason });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const countResult = await pool.query("SELECT COUNT(*) FROM users");
    const isFirstUser = Number(countResult.rows[0].count) === 0;
    const usAliases = ["united states", "united states of america", "usa", "us", "u.s.", "u.s.a."];
    const isUS = usAliases.includes((country || "").trim().toLowerCase());
    const isApproved = isFirstUser || isUS;

    const result = await pool.query(
      `INSERT INTO users (
         username, email, phone, password_hash, display_name, first_name, last_name,
         office_location, country, is_admin, is_approved, account_type, id_type,
         id_country, license_number, license_photos, id_verification_exempt
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
       RETURNING id, username, email, phone, display_name, first_name, last_name, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type,
         id_country, license_number, license_photos, id_verification_exempt, created_at`,
      [
        username, email, phone, passwordHash, displayName || username, firstName || "", lastName || "",
        officeLocation || "", country || "", isFirstUser, isApproved, accountType || "personal",
        idType || "", idCountry || "", licenseNumber || "", JSON.stringify(licensePhotos || []),
        !!idVerificationExempt,
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
// Full member list for the admin dashboard. No password hashes returned.
// Fields visible to everyone — used for storefronts, follower lists, etc.
// Deliberately excludes email, phone, and ID/document fields.
const USER_PUBLIC_FIELDS = `id, username, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, created_at`;

// Full fields — only returned to a signed-in admin.
const USER_FULL_FIELDS = `id, username, email, phone, display_name, first_name, last_name, office_location,
  country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, created_at`;

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
  license_number, license_photos, id_verification_exempt, has_applied_to_sell, created_at`;

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
      `UPDATE users SET is_approved = true WHERE id = $1 RETURNING ${USER_RETURNING_FIELDS}`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
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

    const result = await pool.query(
      `INSERT INTO users (username, email, phone, password_hash, display_name, is_admin, is_approved, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING ${USER_RETURNING_FIELDS}`,
      [
        username,
        email || "",
        phone || "",
        passwordHash,
        displayName || username,
        !!isAdmin,
        isApproved !== false,
        !!isVerified,
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

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing username or password" });
    }

    const result = await pool.query(
      `SELECT id, username, email, phone, password_hash, display_name, first_name, last_name, office_location,
         country, is_admin, is_approved, is_verified, is_suspended, account_type, id_type, id_country,
         license_number, license_photos, id_verification_exempt, created_at
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

    delete user.password_hash;
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
      status, auctionEndTime,
    } = req.body;
    const ownerId = req.user.id; // always the signed-in user — never trust a client-supplied owner

    if (!title || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const result = await pool.query(
      `INSERT INTO listings (
         owner_id, title, description, price, category, condition, shipping_fee,
         emoji, fit_make, fit_model, fit_year, images, listing_type, currency,
         status, auction_end_time
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       RETURNING *`,
      [
        ownerId, title, description || "", price, category || "Other", condition || "New", shippingFee || 0,
        emoji || "📦", fitMake || "", fitModel || "", fitYear || "", JSON.stringify(images || []),
        listingType || "fixed", currency || "USD", status || "pending",
        auctionEndTime ? new Date(auctionEndTime) : null,
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
};
const LISTING_JSON_FIELDS = new Set(["images", "bidHistory"]);

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
        values.push(LISTING_JSON_FIELDS.has(key) ? JSON.stringify(raw) : raw);
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
    const result = await pool.query(
      "UPDATE orders SET is_disputed = $1 WHERE id = $2 RETURNING *",
      [!!isDisputed, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Order not found" });
    res.json({ order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const ORDER_ITEM_STATUSES = new Set(["new", "shipped", "delivered", "cancelled", "returned"]);

// Update one item's fulfillment status/tracking — only that item's seller or an admin.
app.patch("/order-items/:id", authenticate, async (req, res) => {
  try {
    const existing = await pool.query("SELECT seller_id FROM order_items WHERE id = $1", [req.params.id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Order item not found" });
    if (!req.user.isAdmin && existing.rows[0].seller_id !== req.user.id) {
      return res.status(403).json({ error: "You can only update your own items" });
    }
    const { fulfillmentStatus, trackingNumber } = req.body;
    if (fulfillmentStatus && !ORDER_ITEM_STATUSES.has(fulfillmentStatus)) {
      return res.status(400).json({ error: "Invalid fulfillment status" });
    }
    const sets = [];
    const values = [];
    let i = 1;
    if (fulfillmentStatus) {
      sets.push(`fulfillment_status = $${i++}`);
      values.push(fulfillmentStatus);
    }
    if (typeof trackingNumber === "string") {
      sets.push(`tracking_number = $${i++}`);
      values.push(trackingNumber);
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
    const signature = req.headers["x-paystack-signature"];
    const expectedSignature = crypto
      .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
      .update(req.rawBody)
      .digest("hex");

    if (signature !== expectedSignature) {
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

app.post("/sellers/bank-details", authenticate, async (req, res) => {
  try {
    const { userId, bankCode, accountNumber } = req.body;

    if (!userId || !bankCode || !accountNumber) {
      return res.status(400).json({ error: "Missing userId, bankCode, or accountNumber" });
    }
    if (req.user.id !== Number(userId) && !req.user.isAdmin) {
      return res.status(403).json({ error: "You can only set your own bank details" });
    }

    const userResult = await pool.query("SELECT display_name FROM users WHERE id = $1", [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
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
      return res.status(400).json({ error: recipientData.message || "Could not verify bank details" });
    }

    await pool.query(
      "UPDATE users SET bank_code = $1, account_number = $2, paystack_recipient_code = $3 WHERE id = $4",
      [bankCode, accountNumber, recipientData.data.recipient_code, userId]
    );

    res.json({ success: true, recipientCode: recipientData.data.recipient_code });
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
    const { threadId, body, messageType, offerAmount } = req.body;
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
      `INSERT INTO messages (thread_id, sender_id, message_type, body, offer_amount, offer_status)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        threadId,
        senderId,
        messageType || "text",
        body || "",
        offerAmount || null,
        messageType === "offer" ? "pending" : null,
      ]
    );

    res.status(201).json({ message: result.rows[0] });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
