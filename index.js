import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";

const app = express();
const PORT = process.env.PORT || 3000;

// Change this in production by adding JWT_SECRET
// to your Replit/hosting environment variables.
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_ADEZ_SECRET";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------------
// DATABASE
// -------------------------

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
  )
`);

// -------------------------
// MIDDLEWARE
// -------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(
  path.join(__dirname, "public")
));

// -------------------------
// HEALTH CHECK
// -------------------------

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "ADEZ TECH server is running"
  });
});

// -------------------------
// REGISTER
// -------------------------

app.post("/api/register", async (req, res) => {

  try {

    const {
      name,
      email,
      username,
      password
    } = req.body;

    if (!name || !email || !username || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanUsername = String(username).trim().toLowerCase();

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

    const emailExists = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(cleanEmail);

    if (emailExists) {
      return res.status(409).json({
        success: false,
        message: "Email is already registered."
      });
    }

    const usernameExists = db.prepare(
      "SELECT id FROM users WHERE username = ?"
    ).get(cleanUsername);

    if (usernameExists) {
      return res.status(409).json({
        success: false,
        message: "Username is already taken."
      });
    }

    const hashedPassword =
      await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users
      (name, email, username, password)
      VALUES (?, ?, ?, ?)
    `).run(
      cleanName,
      cleanEmail,
      cleanUsername,
      hashedPassword
    );

    return res.status(201).json({
      success: true,
      message: "Account created successfully.",
      userId: result.lastInsertRowid
    });

  } catch (error) {

    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create account."
    });
  }
});

// -------------------------
// LOGIN
// -------------------------

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
      String(login).trim().toLowerCase();

    const user = db.prepare(`
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

    const passwordCorrect =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: "Invalid username/email or password."
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    return res.json({
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

    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to login."
    });
  }
});

// -------------------------
// AUTHENTICATION MIDDLEWARE
// -------------------------

function authenticate(req, res, next) {

  const header =
    req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {

    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  const token =
    header.substring(7);

  try {

    const decoded =
      jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch {

    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }
}

// -------------------------
// CURRENT USER
// -------------------------

app.get(
  "/api/me",
  authenticate,
  (req, res) => {

    const user = db.prepare(`
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

// -------------------------
// HOME PAGE
// -------------------------

app.get("/", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// -------------------------
// API 404
// -------------------------

app.use("/api", (req, res) => {

  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

// -------------------------
// START SERVER
// -------------------------

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `ADEZ TECH running on port ${PORT}`
    );

  }
);
