const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
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

app.post("/signup", async (req, res) => {
  try {
    const { username, email, phone, password, displayName } = req.body;

    if (!username || !email || !phone || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (username, email, phone, password_hash, display_name)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, email, display_name, created_at`,
      [username, email, phone, passwordHash, displayName || username]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username, email, or phone already in use" });
    }
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
      "SELECT id, username, email, display_name, password_hash, is_suspended FROM users WHERE username = $1",
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

    delete user.password_hash;
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post("/listings", async (req, res) => {
  try {
    const { ownerId, title, description, price, category, condition, shippingFee } = req.body;

    if (!ownerId || !title || !price) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const result = await pool.query(
      `INSERT INTO listings (owner_id, title, description, price, category, condition, shipping_fee)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [ownerId, title, description || "", price, category || "Other", condition || "New", shippingFee || 0]
    );

    res.status(201).json({ listing: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/listings", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT listings.*, users.display_name AS seller_name
       FROM listings
       JOIN users ON listings.owner_id = users.id
       ORDER BY listings.created_at DESC`
    );
    res.json({ listings: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post("/orders", async (req, res) => {
  const client = await pool.connect();
  try {
    const { buyerId, listingId } = req.body;

    if (!buyerId || !listingId) {
      return res.status(400).json({ error: "Missing buyerId or listingId" });
    }

    await client.query("BEGIN");

    const listingResult = await client.query(
      "SELECT * FROM listings WHERE id = $1 AND status != 'sold'",
      [listingId]
    );

    if (listingResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Listing not found or already sold" });
    }

    const listing = listingResult.rows[0];

    const orderResult = await client.query(
      `INSERT INTO orders (buyer_id, total, currency)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [buyerId, listing.price, listing.currency]
    );

    await client.query(
      "UPDATE listings SET status = 'sold' WHERE id = $1",
      [listingId]
    );

    await client.query("COMMIT");
    res.status(201).json({ order: orderResult.rows[0], listing });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get("/orders/:buyerId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM orders WHERE buyer_id = $1 ORDER BY created_at DESC",
      [req.params.buyerId]
    );
    res.json({ orders: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
