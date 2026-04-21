/**
 * MongoDB Model: ScanResult
 * Stores the full output of each OSINT scan for history/retrieval.
 */

const mongoose = require("mongoose");

const ScanResultSchema = new mongoose.Schema(
  {
    target: {
      email:    { type: String, default: null },
      domain:   { type: String, default: null },
      username: { type: String, default: null },
      ip:       { type: String, default: null },
    },
    scanType: {
      type:    String,
      enum:    ["FULL", "BREACH", "DOMAIN", "NETWORK", "SOCIAL", "EXIF", "THREAT"],
      default: "FULL",
    },
    finalScore: { type: Number, min: 0, max: 100, default: 0 },
    riskLevel:  { type: String, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "LOW" },

    // Sub-scores from each module (0-100 each)
    subScores: {
      breach:  { type: Number, default: null },
      network: { type: Number, default: null },
      threat:  { type: Number, default: null },
      domain:  { type: Number, default: null },
      social:  { type: Number, default: null },
      exif:    { type: Number, default: null },
    },

    // Full results payload from each module
    results: { type: mongoose.Schema.Types.Mixed, default: {} },

    // Module-level errors (non-fatal)
    errors: { type: mongoose.Schema.Types.Mixed, default: {} },

    // Weighted breakdown
    breakdown: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  {
    timestamps: true,   // adds createdAt, updatedAt
  }
);

// Index for efficient history queries
ScanResultSchema.index({ createdAt: -1 });
ScanResultSchema.index({ "target.email": 1 });
ScanResultSchema.index({ "target.domain": 1 });
ScanResultSchema.index({ riskLevel: 1 });

module.exports = mongoose.model("ScanResult", ScanResultSchema);
