/**
 * OSINT Risk Suite — Express Application
 * Entry point: mounts all middleware, routes, and error handlers.
 *
 * Usage:
 *   node app.js        (or npm run dev via nodemon)
 *
 * Expects these environment variables (see .env.example):
 *   PORT, MONGO_URI, HIBP_API_KEY, SHODAN_API_KEY,
 *   JWT_SECRET, CLIENT_URL
 */

require("dotenv").config();

const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const morgan       = require("morgan");
const mongoose     = require("mongoose");

const osintRoutes  = require("./routes/osint");
const authRoutes   = require("./routes/auth");
const protect      = require("./middleware/auth");

// ─── App setup ────────────────────────────────────────────────────────────────

const app  = express();
const PORT = process.env.PORT || 5000;

// ─── Security middleware ──────────────────────────────────────────────────────

app.use(helmet());

app.use(
  cors({
    origin:      process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
    methods:     ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  })
);

// ─── Rate limiting ────────────────────────────────────────────────────────────

// General API limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max:      100,
  message:  { success: false, error: "Too many requests. Please try again in 15 minutes." },
});

// Stricter limiter for heavy OSINT scans
const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max:      20,
  message:  { success: false, error: "Scan limit reached. Maximum 20 full scans per hour." },
});

app.use("/api/", generalLimiter);
app.use("/api/osint/scan/full", scanLimiter);

// ─── Body parsing ─────────────────────────────────────────────────────────────

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

// ─── Request logging ──────────────────────────────────────────────────────────

if (process.env.NODE_ENV !== "test") {
  app.use(morgan("dev"));
}

// ─── Health check ─────────────────────────────────────────────────────────────

app.get("/api/health", (_req, res) => {
  res.json({
    status:    "ok",
    service:   "OSINT Risk Suite API",
    version:   "1.0.0",
    dbStatus:  mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    timestamp: new Date().toISOString(),
  });
});

// ─── Auth routes ──────────────────────────────────────────────────────────────

app.use("/api/auth", authRoutes);

// ─── OSINT routes (protected) ─────────────────────────────────────────────────

app.use("/api/osint", protect, osintRoutes);

// ─── 404 handler ─────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ success: false, error: "Route not found." });
});

// ─── Global error handler ─────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("[Error]", err.message);

  // Multer file size error
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ success: false, error: "File too large. Maximum size is 20 MB." });
  }

  // Multer file type error
  if (err.message?.includes("Only JPEG")) {
    return res.status(415).json({ success: false, error: err.message });
  }

  return res.status(500).json({
    success: false,
    error:   process.env.NODE_ENV === "production" ? "Internal server error." : err.message,
  });
});

// ─── Database + server startup ────────────────────────────────────────────────

async function start() {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log("✅  MongoDB connected");

    app.listen(PORT, () => {
      console.log(`🚀  OSINT Risk Suite API running on http://localhost:${PORT}`);
      console.log(`    Health: http://localhost:${PORT}/api/health`);
    });
  } catch (err) {
    console.error("❌  Failed to connect to MongoDB:", err.message);
    process.exit(1);
  }
}

start();

module.exports = app;  // for testing
