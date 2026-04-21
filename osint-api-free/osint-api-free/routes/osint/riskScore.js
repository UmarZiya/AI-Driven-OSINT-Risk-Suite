/**
 * OSINT Module: Risk Score Calculator
 * Computes the final Digital Risk Score by aggregating sub-scores
 * from all OSINT modules with weighted importance.
 *
 * Routes:
 *   POST /api/osint/risk-score/calculate   — compute from pre-gathered sub-scores
 */

const express = require("express");
const router  = express.Router();

// ─── Weights (must sum to 1.0) ────────────────────────────────────────────────

const WEIGHTS = {
  breach:   0.30,   // Data breach history is the highest-impact signal
  network:  0.25,   // Open ports / exposed services
  threat:   0.20,   // NLP threat content signals
  domain:   0.10,   // Domain age, DNSSEC, DNS records
  social:   0.10,   // Social media footprint size
  exif:     0.05,   // Image metadata exposure
};

// ─── Risk classification thresholds ──────────────────────────────────────────

const RISK_THRESHOLDS = {
  CRITICAL: 80,
  HIGH:     60,
  MEDIUM:   35,
  LOW:      0,
};

function classifyRisk(score) {
  if (score >= RISK_THRESHOLDS.CRITICAL) return "CRITICAL";
  if (score >= RISK_THRESHOLDS.HIGH)     return "HIGH";
  if (score >= RISK_THRESHOLDS.MEDIUM)   return "MEDIUM";
  return "LOW";
}

// ─── route ────────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/risk-score/calculate
 *
 * Body:
 * {
 *   target: { email?, domain?, username?, ip? },
 *   subScores: {
 *     breach?:  number (0-100),
 *     network?: number (0-100),
 *     threat?:  number (0-100),
 *     domain?:  number (0-100),
 *     social?:  number (0-100),
 *     exif?:    number (0-100),
 *   }
 * }
 *
 * Any missing sub-score is treated as 0 (not penalised for incomplete scans).
 * The final score is weighted-average of provided scores, re-normalised
 * to maintain the 0-100 range even when not all modules ran.
 */
router.post("/calculate", (req, res) => {
  const { target = {}, subScores = {} } = req.body;

  if (typeof subScores !== "object" || subScores === null) {
    return res.status(400).json({ success: false, error: "subScores must be an object." });
  }

  // Validate & clamp individual scores
  const validated = {};
  for (const [module, weight] of Object.entries(WEIGHTS)) {
    const raw = subScores[module];
    if (raw !== undefined && raw !== null) {
      const clamped = Math.max(0, Math.min(100, Number(raw)));
      validated[module] = { score: clamped, weight };
    }
  }

  if (Object.keys(validated).length === 0) {
    return res.status(400).json({ success: false, error: "At least one sub-score is required." });
  }

  // Weighted average using only provided scores
  // Re-normalise weights so provided scores still produce a 0-100 result
  const totalWeight = Object.values(validated).reduce((sum, v) => sum + v.weight, 0);
  const weightedSum  = Object.values(validated).reduce((sum, v) => sum + v.score * v.weight, 0);
  const finalScore   = Math.round(weightedSum / totalWeight);

  const riskLevel    = classifyRisk(finalScore);
  const breakdown    = Object.fromEntries(
    Object.entries(validated).map(([module, v]) => [
      module,
      {
        score:           v.score,
        weight:          v.weight,
        weightedContrib: Math.round(v.score * v.weight),
        level:           classifyRisk(v.score),
      },
    ])
  );

  const response = {
    success: true,
    target,
    finalScore,
    riskLevel,
    breakdown,
    modulesRun:    Object.keys(validated),
    modulesMissed: Object.keys(WEIGHTS).filter((m) => !(m in validated)),
    recommendations: buildFinalRecommendations(riskLevel, breakdown),
    badge: buildRiskBadge(riskLevel, finalScore),
    scoredAt: new Date().toISOString(),
  };

  return res.json(response);
});

// ─── helpers ──────────────────────────────────────────────────────────────────

function buildFinalRecommendations(riskLevel, breakdown) {
  const recs = [];

  if (riskLevel === "CRITICAL") {
    recs.push("🚨 CRITICAL RISK: Immediate action required. Notify your security team.");
  } else if (riskLevel === "HIGH") {
    recs.push("⚠️  HIGH RISK: Address the identified vulnerabilities as soon as possible.");
  }

  // Surface the highest-contributing modules
  const sorted = Object.entries(breakdown).sort((a, b) => b[1].score - a[1].score);
  const topRisk = sorted.filter(([, v]) => v.score >= 60).map(([m]) => m);

  if (topRisk.length > 0) {
    recs.push(`Highest-risk areas: ${topRisk.join(", ")}. Prioritise these first.`);
  }

  if (breakdown.breach?.score >= 60) {
    recs.push("Change all passwords for breached accounts and enable 2FA.");
  }
  if (breakdown.network?.score >= 60) {
    recs.push("Audit and close all unnecessary open ports. Patch discovered CVEs.");
  }
  if (breakdown.social?.score >= 60) {
    recs.push("Review and deactivate unused social media accounts.");
  }
  if (breakdown.exif?.score >= 40) {
    recs.push("Strip metadata from images before sharing them publicly.");
  }

  if (riskLevel === "LOW") {
    recs.push("Low overall risk. Continue monitoring regularly and practice good digital hygiene.");
  }

  return recs;
}

function buildRiskBadge(riskLevel, score) {
  const colors = {
    CRITICAL: "#FF0000",
    HIGH:     "#FF6600",
    MEDIUM:   "#FFB800",
    LOW:      "#00CC44",
  };
  return {
    label:       riskLevel,
    score,
    color:       colors[riskLevel],
    description: {
      CRITICAL: "Severe exposure — immediate action needed.",
      HIGH:     "Significant vulnerabilities found.",
      MEDIUM:   "Moderate risks detected — review recommended.",
      LOW:      "Minimal risk detected.",
    }[riskLevel],
  };
}

module.exports = router;
