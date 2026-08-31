import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_ADEZ_SECRET";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =========================
// DATABASE
// =========================

const db = new Database("adez.db");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    service TEXT NOT NULL,
    link TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    rate REAL NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// =========================
// SERVICES
// =========================

const SERVICES = {

  fb_followers: {
    platform: "facebook",
    name: "Facebook Page Followers",
    rate: 50,
    min: 100,
    max: 10000
  },

  fb_likes: {
    platform: "facebook",
    name: "Facebook Page Likes",
    rate: 45,
    min: 100,
    max: 10000
  },

  ig_followers: {
    platform: "instagram",
    name: "Instagram Followers",
    rate: 50,
    min: 100,
    max: 10000
  },

  ig_likes: {
    platform: "instagram",
    name: "Instagram Likes",
    rate: 35,
    min: 100,
    max: 10000
  },

  tt_followers: {
    platform: "tiktok",
    name: "TikTok Followers",
    rate: 50,
    min: 100,
    max: 10000
  },

  tt_likes: {
    platform: "tiktok",
    name: "TikTok Likes",
    rate: 35,
    min: 100,
    max: 10000
  },

  yt_subscribers: {
    platform: "youtube",
    name: "YouTube Subscribers",
    rate: 150,
    min: 100,
    max: 5000
  },

  yt_views: {
    platform: "youtube",
    name: "YouTube Views",
    rate: 30,
    min: 1000,
    max: 100000
  },

  x_followers: {
    platform: "x",
    name: "X Followers",
    rate: 60,
    min: 100,
    max: 10000
  },

  x_likes: {
    platform: "x",
    name: "X Likes",
    rate: 45,
    min: 100,
    max: 10000
  }

};

// =========================
// MIDDLEWARE
// =========================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

// =========================
// AUTH
// =========================

function authenticate(req, res, next) {

  const header =
    req.headers.authorization;

  if (
    !header ||
    !header.startsWith("Bearer ")
  ) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  const token =
    header.substring(7);

  try {

    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();

  } catch {

    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });

  }
}

// =========================
// HEALTH
// =========================

app.get("/api/health", (req, res) => {

  res.json({
    success: true,
    message: "ADEZ TECH server is running"
  });

});

// =========================
// SERVICES API
// =========================

app.get("/api/services", (req, res) => {

  res.json({
    success: true,
    services: Object.entries(SERVICES)
      .map(([id, service]) => ({
        id,
        ...service
      }))
  });

});

// =========================
// REGISTER
// =========================

app.post("/api/register", async (req, res) => {

  try {

    const {
      name,
      email,
      username,
      password
    } = req.body;

    if (
      !name ||
      !email ||
      !username ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    const cleanName =
      String(name).trim();

    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();

    const cleanUsername =
      String(username)
        .trim()
        .toLowerCase();

    if (cleanName.length < 2) {
      return res.status(400).json({
        success: false,
        message: "Please enter your full name."
      });
    }

    if (cleanUsername.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username must be at least 3 characters."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters."
      });
    }

    const emailExists =
      db.prepare(
        "SELECT id FROM users WHERE email = ?"
      ).get(cleanEmail);

    if (emailExists) {
      return res.status(409).json({
        success: false,
        message: "Email is already registered."
      });
    }

    const usernameExists =
      db.prepare(
        "SELECT id FROM users WHERE username = ?"
      ).get(cleanUsername);

    if (usernameExists) {
      return res.status(409).json({
        success: false,
        message: "Username is already taken."
      });
    }

    const hashedPassword =
      await bcrypt.hash(
        password,
        12
      );

    const result =
      db.prepare(`
        INSERT INTO users
        (name, email, username, password)
        VALUES (?, ?, ?, ?)
      `).run(
        cleanName,
        cleanEmail,
        cleanUsername,
        hashedPassword
      );

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      userId: result.lastInsertRowid
    });

  } catch (error) {

    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Unable to create account."
    });

  }

});

// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {

  try {

    const {
      login,
      password
    } = req.body;

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Login and password are required."
      });
    }

    const cleanLogin =
      String(login)
        .trim()
        .toLowerCase();

    const user =
      db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
           OR username = ?
        LIMIT 1
      `).get(
        cleanLogin,
        cleanLogin
      );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username/email or password."
      });
    }

    const correct =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!correct) {
      return res.status(401).json({
        success: false,
        message: "Invalid username/email or password."
      });
    }

    const token =
      jwt.sign(
        {
          id: user.id,
          username: user.username
        },
        JWT_SECRET,
        {
          expiresIn: "7d"
        }
      );

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        username: user.username,
        balance: user.balance
      }
    });

  } catch (error) {

    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Unable to login."
    });

  }

});

// =========================
// CURRENT USER
// =========================

app.get(
  "/api/me",
  authenticate,
  (req, res) => {

    const user =
      db.prepare(`
        SELECT
          id,
          name,
          email,
          username,
          balance,
          created_at
        FROM users
        WHERE id = ?
      `).get(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    res.json({
      success: true,
      user
    });

  }
);

// =========================
// CREATE ORDER
// =========================

app.post(
  "/api/orders",
  authenticate,
  (req, res) => {

    try {

      const {
        platform,
        service,
        link,
        quantity
      } = req.body;

      if (
        !platform ||
        !service ||
        !link ||
        !quantity
      ) {
        return res.status(400).json({
          success: false,
          message: "All order fields are required."
        });
      }

      const selected =
        SERVICES[service];

      if (!selected) {
        return res.status(400).json({
          success: false,
          message: "Invalid service."
        });
      }

      if (
        selected.platform !== platform
      ) {
        return res.status(400).json({
          success: false,
          message: "Service does not match platform."
        });
      }

      const qty =
        Number(quantity);

      if (
        !Number.isInteger(qty) ||
        qty < selected.min ||
        qty > selected.max
      ) {
        return res.status(400).json({
          success: false,
          message:
            `Quantity must be between ${selected.min} and ${selected.max}.`
        });
      }

      let target;

      try {

        target =
          new URL(link);

      } catch {

        return res.status(400).json({
          success: false,
          message: "Please provide a valid URL."
        });

      }

      if (
        !["http:", "https:"]
          .includes(target.protocol)
      ) {
        return res.status(400).json({
          success: false,
          message: "Only HTTP and HTTPS links are allowed."
        });
      }

      const amount =
        (qty / 1000) *
        selected.rate;

      const user =
        db.prepare(`
          SELECT id, balance
          FROM users
          WHERE id = ?
        `).get(req.user.id);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found."
        });
      }

      if (Number(user.balance) < amount) {

        return res.status(400).json({
          success: false,
          message:
            `Insufficient balance. You need KSh ${amount.toFixed(2)}.`
        });

      }

      /*
        The transaction makes sure the balance deduction
        and order creation happen together.
      */

      const createOrder =
        db.transaction(() => {

          db.prepare(`
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
          `).run(
            amount,
            req.user.id
          );

          const result =
            db.prepare(`
              INSERT INTO orders
              (
                user_id,
                platform,
                service,
                link,
                quantity,
                rate,
                amount,
                status
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              req.user.id,
              platform,
              service,
              link,
              qty,
              selected.rate,
              amount,
              "pending"
            );

          return result.lastInsertRowid;

        });

      const orderId =
        createOrder();

      res.status(201).json({
        success: true,
        message: "Order submitted successfully.",
        order: {
          id: orderId,
          platform,
          service: selected.name,
          quantity: qty,
          rate: selected.rate,
          amount,
          status: "pending"
        }
      });

    } catch (error) {

      console.error(
        "ORDER ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Unable to create order."
      });

    }

  }
);

// =========================
// USER ORDERS
// =========================

app.get(
  "/api/orders",
  authenticate,
  (req, res) => {

    try {

      const orders =
        db.prepare(`
          SELECT
            id,
            platform,
            service,
            link,
            quantity,
            rate,
            amount,
            status,
            created_at
          FROM orders
          WHERE user_id = ?
          ORDER BY id DESC
        `).all(req.user.id);

      res.json({
        success: true,
        orders
      });

    } catch (error) {

      console.error(
        "ORDERS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Unable to load orders."
      });

    }

  }
);

// =========================
// HOME
// =========================

app.get("/", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );

});

// =========================
// API 404
// =========================

app.use("/api", (req, res) => {

  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });

});

// =========================
// SERVER
// =========================

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `ADEZ TECH running on port ${PORT}`
    );

  }
);
