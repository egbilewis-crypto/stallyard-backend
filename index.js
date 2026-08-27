const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

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
    const { username, email, phone, password, displayName, firstName, lastName, officeLocation, country } = req.body;

    if (!username || !email || !phone || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const countResult = await pool.query("SELECT COUNT(*) FROM users");
    const isFirstUser = Number(countResult.rows[0].count) === 0;

    const result = await pool.query(
      `INSERT INTO users (username, email, phone, password_hash, display_name, first_name, last_name, office_location, country, is_admin, is_approved)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, username, email, phone, display_name, first_name, last_name, office_location, country, is_admin, is_approved, is_verified, is_suspended, created_at`,
      [username, email, phone, passwordHash, displayName || username, firstName || "", lastName || "", officeLocation || "", country || "", isFirstUser, isFirstUser]
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
      `SELECT id, username, email, phone, password_hash, display_name, first_name, last_name, office_location, country, is_admin, is_approved, is_verified, is_suspended, created_at
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
app.post("/checkout", async (req, res) => {
  try {
    const { buyerId, listingId, email } = req.body;

    if (!buyerId || !listingId || !email) {
      return res.status(400).json({ error: "Missing buyerId, listingId, or email" });
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
        metadata: { buyerId, listingId },
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
app.post("/sellers/bank-details", async (req, res) => {
  try {
    const { userId, bankCode, accountNumber } = req.body;

    if (!userId || !bankCode || !accountNumber) {
      return res.status(400).json({ error: "Missing userId, bankCode, or accountNumber" });
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
app.post("/sellers/payout", async (req, res) => {
  try {
    const { userId, amount, reason } = req.body;

    if (!userId || !amount) {
      return res.status(400).json({ error: "Missing userId or amount" });
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

    const transferData = await transferRes.json();

    if (!transferData.status) {
      return res.status(400).json({ error: transferData.message || "Payout failed" });
    }

    res.json({ success: true, transfer: transferData.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post("/threads", async (req, res) => {
  try {
    const { listingId, buyerId, sellerId } = req.body;

    if (!listingId || !buyerId || !sellerId) {
      return res.status(400).json({ error: "Missing listingId, buyerId, or sellerId" });
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

app.get("/threads/:userId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM threads WHERE buyer_id = $1 OR seller_id = $1 ORDER BY created_at DESC",
      [req.params.userId]
    );
    res.json({ threads: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/messages", async (req, res) => {
  try {
    const { threadId, senderId, body, messageType, offerAmount } = req.body;

    if (!threadId || !senderId) {
      return res.status(400).json({ error: "Missing threadId or senderId" });
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

app.get("/messages/:threadId", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM messages WHERE thread_id = $1 ORDER BY created_at ASC",
      [req.params.threadId]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post("/reviews", async (req, res) => {
  try {
    const { orderId, listingId, buyerId, sellerId, rating, comment } = req.body;

    if (!orderId || !listingId || !buyerId || !sellerId || !rating) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
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
