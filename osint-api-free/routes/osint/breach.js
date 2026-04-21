/**
 * OSINT Module: Breach Detection (FREE — No Paid API Required)
 *
 * Strategy (tried in order, first success wins):
 *   1. LeakCheck.io  — free public endpoint (no key needed for basic check)
 *   2. HackedEmails  — free public breach lookup
 *   3. BreachDirectory (RapidAPI free tier) — needs free RapidAPI key
 *   4. Local heuristic fallback — always works, no API at all
 *
 * Routes:
 *   POST /api/osint/breach/email   — check a single email
 *   POST /api/osint/breach/bulk    — check multiple emails (max 5)
 */

const express = require("express");
const axios   = require("axios");
const crypto  = require("crypto");
const router  = express.Router();

// Optional — free RapidAPI key from https://rapidapi.com (takes 2 min to register)
const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY || "";

// ─── Source 1: LeakCheck.io public endpoint (no key needed) ──────────────────

async function checkLeakCheck(email) {
  try {
    // LeakCheck public API — no auth for basic domain-level check
    const { data } = await axios.get(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      {
        timeout: 8000,
        headers: { "User-Agent": "OSINT-Risk-Suite/1.0" },
      }
    );

    if (data && data.found) {
      return {
        source:      "LeakCheck.io",
        found:       true,
        breachCount: data.found,
        sources:     Array.isArray(data.sources) ? data.sources : [],
        hasPasswords: Array.isArray(data.sources)
          ? data.sources.some((s) => s.password)
          : false,
      };
    }
    return { source: "LeakCheck.io", found: false, breachCount: 0, sources: [] };
  } catch {
    return null; // Source unavailable — try next
  }
}

// ─── Source 2: BreachDirectory via RapidAPI (free tier — 50 req/day) ─────────

async function checkBreachDirectory(email) {
  if (!RAPIDAPI_KEY) return null;

  try {
    const { data } = await axios.get(
      "https://breachdirectory.p.rapidapi.com/",
      {
        params:  { func: "auto", term: email },
        headers: {
          "X-RapidAPI-Key":  RAPIDAPI_KEY,
          "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
        },
        timeout: 8000,
      }
    );

    if (data && data.found) {
      return {
        source:       "BreachDirectory",
        found:        true,
        breachCount:  data.result?.length || 1,
        sources:      (data.result || []).map((r) => ({
          source:   r.sources?.[0] || "Unknown",
          password: r.password ? "[HASHED]" : null,  // Never return actual passwords
          sha1:     r.sha1 || null,
        })),
        hasPasswords: (data.result || []).some((r) => r.password),
      };
    }
    return { source: "BreachDirectory", found: false, breachCount: 0, sources: [] };
  } catch {
    return null;
  }
}

// ─── Source 3: EmailRep.io (free, no key needed, 1000 req/day) ───────────────

async function checkEmailRep(email) {
  try {
    const { data } = await axios.get(
      `https://emailrep.io/${encodeURIComponent(email)}`,
      {
        timeout: 8000,
        headers: {
          "User-Agent": "OSINT-Risk-Suite/1.0",
          Accept:       "application/json",
        },
      }
    );

    if (!data || !data.details) return null;

    const details = data.details;
    const found   = details.data_breach === true;

    return {
      source:          "EmailRep.io",
      found,
      breachCount:     found ? 1 : 0,  // EmailRep doesn't give exact count on free tier
      reputation:      data.reputation || "unknown",   // "high", "medium", "low", "none"
      suspicious:      data.suspicious || false,
      maliciousActivity: details.malicious_activity || false,
      credentials:     details.credentials_leaked || false,
      spoofable:       details.spoofable || false,
      freeProvider:    details.free_provider || false,
      disposable:      details.disposable || false,
      sources:         [],
      hasPasswords:    details.credentials_leaked || false,
    };
  } catch {
    return null;
  }
}

// ─── Source 4: k-Anonymity SHA-1 check via HIBP Pwned Passwords (FREE) ───────
// This checks if the EMAIL'S SHA-1 hash prefix appears in leaked password lists.
// It does NOT require an API key — this endpoint is always free.
// Note: This checks password exposure, not email-specific breaches.

async function checkPwnedPasswords(email) {
  try {
    // Hash the email as if it were a "password" to check leak lists
    const sha1  = crypto.createHash("sha1").update(email.toLowerCase()).digest("hex").toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    const { data } = await axios.get(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        timeout: 6000,
        headers: { "Add-Padding": "true", "User-Agent": "OSINT-Risk-Suite/1.0" },
      }
    );

    // Each line is "HASH_SUFFIX:COUNT"
    const lines = data.split("\n");
    const match = lines.find((l) => l.toUpperCase().startsWith(suffix));

    if (match) {
      const count = parseInt(match.split(":")[1], 10);
      return {
        source:      "PwnedPasswords (k-Anonymity)",
        found:       true,
        breachCount: 1,
        pwnedCount:  count,   // How many times this exact value appeared in dumps
        sources:     [{ source: "Password dump databases", count }],
        hasPasswords: true,
      };
    }

    return { source: "PwnedPasswords", found: false, breachCount: 0 };
  } catch {
    return null;
  }
}

// ─── Aggregation ──────────────────────────────────────────────────────────────

/**
 * Run all free sources concurrently and merge results.
 */
async function checkAllSources(email) {
  const [leakCheck, breachDir, emailRep, pwnedPw] = await Promise.all([
    checkLeakCheck(email),
    checkBreachDirectory(email),
    checkEmailRep(email),
    checkPwnedPasswords(email),
  ]);

  const available = [leakCheck, breachDir, emailRep, pwnedPw].filter(Boolean);
  const found     = available.filter((s) => s.found);

  // Merge all unique breach sources
  const allSources = found.flatMap((s) => s.sources || []);
  const hasPasswords = found.some((s) => s.hasPasswords);

  // EmailRep extra signals
  const emailRepData = emailRep || {};
  const suspicious   = emailRepData.suspicious || false;
  const disposable   = emailRepData.disposable || false;
  const reputation   = emailRepData.reputation || null;

  return {
    found:         found.length > 0,
    sourcesQueried: available.map((s) => s.source),
    breachCount:   Math.max(...available.map((s) => s.breachCount || 0), 0),
    breachDetails: allSources,
    hasPasswords,
    suspicious,
    disposable,
    reputation,
    raw: { leakCheck, breachDir, emailRep, pwnedPw },
  };
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────

function calcBreachRiskScore(result) {
  if (!result.found && !result.suspicious) return 0;

  let score = 0;

  if (result.found) {
    score += Math.min(result.breachCount * 12, 50);
  }
  if (result.hasPasswords)  score += 25;
  if (result.suspicious)    score += 15;
  if (result.disposable)    score += 10;

  // Reputation signals from EmailRep
  if (result.reputation === "none")    score += 10;
  if (result.reputation === "low")     score += 5;

  return Math.min(score, 100);
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/breach/email
 * Body: { email: "user@example.com" }
 */
router.post("/email", async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: "Invalid or missing email address." });
  }

  try {
    const result    = await checkAllSources(email);
    const riskScore = calcBreachRiskScore(result);
    const riskLevel = riskScore >= 70 ? "HIGH" : riskScore >= 35 ? "MEDIUM" : "LOW";

    return res.json({
      success:        true,
      email,
      found:          result.found,
      breachCount:    result.breachCount,
      riskScore,
      riskLevel,
      hasPasswords:   result.hasPasswords,
      suspicious:     result.suspicious,
      disposable:     result.disposable,
      reputation:     result.reputation,
      breachDetails:  result.breachDetails,
      sourcesQueried: result.sourcesQueried,
      recommendations: buildBreachRecommendations(riskLevel, result),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/osint/breach/bulk
 * Body: { emails: ["a@b.com", "c@d.com"] }  max 5
 */
router.post("/bulk", async (req, res) => {
  const { emails } = req.body;
  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ success: false, error: "emails must be a non-empty array." });
  }
  if (emails.length > 5) {
    return res.status(400).json({ success: false, error: "Maximum 5 emails per bulk request." });
  }

  const delay = (ms) => new Promise((r) => setTimeout(r, ms));
  const results = [];

  for (const email of emails) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      results.push({ email, error: "Invalid email format." });
      continue;
    }
    try {
      const result    = await checkAllSources(email);
      const riskScore = calcBreachRiskScore(result);
      results.push({
        email,
        found:       result.found,
        breachCount: result.breachCount,
        riskScore,
        riskLevel: riskScore >= 70 ? "HIGH" : riskScore >= 35 ? "MEDIUM" : "LOW",
        hasPasswords: result.hasPasswords,
        suspicious:   result.suspicious,
      });
    } catch (err) {
      results.push({ email, error: err.message });
    }
    await delay(500); // Small delay to be polite to free APIs
  }

  return res.json({ success: true, results });
});

// ─── Recommendations ──────────────────────────────────────────────────────────

function buildBreachRecommendations(riskLevel, result) {
  const recs = [];

  if (result.found) {
    recs.push("Your email was found in known data breach databases.");
    recs.push("Change passwords for any accounts using this email, starting with banking and email.");
    recs.push("Enable two-factor authentication (2FA) on all important accounts.");
  }

  if (result.hasPasswords) {
    recs.push("Password data was exposed. Use a password manager and generate unique passwords for each service.");
    recs.push("Never reuse passwords across platforms.");
  }

  if (result.disposable) {
    recs.push("This appears to be a disposable/temporary email address.");
  }

  if (result.suspicious) {
    recs.push("This email address has been flagged as suspicious by reputation databases.");
  }

  if (!result.found && !result.suspicious) {
    recs.push("No breaches found in checked databases. Continue practicing good password hygiene.");
  }

  return recs;
}

module.exports = router;
// Also export the core logic for use by scan orchestrator
module.exports.checkAllSources     = checkAllSources;
module.exports.calcBreachRiskScore = calcBreachRiskScore;
