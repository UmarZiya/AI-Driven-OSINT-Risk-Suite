/**
 * OSINT Risk Suite — Main API Router
 * Mounts all OSINT sub-routes under /api/osint
 */

const express = require("express");
const router = express.Router();

const breachRouter      = require("./osint/breach");
const domainRouter      = require("./osint/domain");
const networkRouter     = require("./osint/network");
const socialRouter      = require("./osint/social");
const exifRouter        = require("./osint/exif");
const threatRouter      = require("./osint/threat");
const riskScoreRouter   = require("./osint/riskScore");
const scanRouter        = require("./osint/scan");

router.use("/breach",     breachRouter);
router.use("/domain",     domainRouter);
router.use("/network",    networkRouter);
router.use("/social",     socialRouter);
router.use("/exif",       exifRouter);
router.use("/threat",     threatRouter);
router.use("/risk-score", riskScoreRouter);
router.use("/scan",       scanRouter);      // Full scan orchestrator

module.exports = router;
