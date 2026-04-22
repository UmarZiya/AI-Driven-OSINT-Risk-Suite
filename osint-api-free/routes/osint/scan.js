/**
 * OSINT Module: Full Scan Orchestrator
 * Runs all applicable OSINT modules for a given target and returns
 * a consolidated report with the final risk score.
 *
 * This is the main endpoint the frontend "New Scan" form calls.
 *
 * Routes:
 *   POST /api/osint/scan/full   — run complete OSINT scan
 *   GET  /api/osint/scan/:id    — retrieve a saved scan by ID
 */

const express   = require("express");
const axios     = require("axios");
const dns       = require("dns").promises;
const router    = express.Router();

// ─── Internal module imports ──────────────────────────────────────────────────
// We call our own sub-modules directly (function calls, not HTTP) for efficiency.

const { queryAllBreachSources, calcBreachRiskScore }       = require("../../services/breachService");
const { performWhois, enumerateDNS, calcDomainRiskScore } = require("../../services/domainService");
const { shodanHostLookup, scanPorts, calcNetworkRiskScore }          = require("../../services/networkService");
const { checkAllPlatforms, calcSocialRiskScore }          = require("../../services/socialService");
const { analyzeText, calcThreatRiskScore }                = require("../../services/threatService");
const { calcFinalRiskScore }                              = require("../../services/riskScoreService");

// Scan result model (for saving to MongoDB)
const ScanResult = require("../../models/ScanResult");

// ─── route ────────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/scan/full
 *
 * Body:
 * {
 *   email?:    string,
 *   domain?:   string,
 *   username?: string,
 *   ip?:       string,
 * }
 *
 * At least ONE field must be provided.
 */
router.post("/full", async (req, res) => {
  const { email, domain, username, ip } = req.body;

  if (!email && !domain && !username && !ip) {
    return res.status(400).json({
      success: false,
      error: "At least one target field (email, domain, username, ip) is required.",
    });
  }

  const target    = { email, domain, username, ip };
  const subScores = {};
  const results   = {};
  const errors    = {};

  // ── 1. Breach check (requires email) ─────────────────────────────────────
  if (email) {
    try {
      const breaches      = await queryAllBreachSources(email);
      const breachScore   = calcBreachRiskScore(breaches);
      subScores.breach    = breachScore;
      results.breach      = {
        email,
        breachCount:  breaches.breachCount || 0,
        hasPasswords: breaches.hasPasswords || false,
        suspicious:   breaches.suspicious   || false,
        disposable:   breaches.disposable   || false,
        reputation:   breaches.reputation   || null,
        riskScore:    breachScore,
        riskLevel:    breachScore >= 70 ? "HIGH" : breachScore >= 35 ? "MEDIUM" : "LOW",
        breaches:     breaches.breachDetails || [],
      };
    } catch (err) {
      errors.breach = err.message;
    }
  }

  // ── 2. Domain analysis (requires domain) ─────────────────────────────────
  if (domain) {
    try {
      const [whoisData, dnsRecords] = await Promise.allSettled([
        performWhois(domain),
        enumerateDNS(domain),
      ]);

      const whois      = whoisData.status  === "fulfilled" ? whoisData.value  : null;
      const dnsRecs    = dnsRecords.status === "fulfilled" ? dnsRecords.value : {};
      const domScore   = calcDomainRiskScore(whois, dnsRecs);

      subScores.domain = domScore;
      results.domain   = {
        domain,
        riskScore:  domScore,
        riskLevel:  domScore >= 60 ? "HIGH" : domScore >= 30 ? "MEDIUM" : "LOW",
        whois,
        dns:        dnsRecs,
      };
    } catch (err) {
      errors.domain = err.message;
    }
  }

  // ── 3. Network exposure (domain → IP, or direct IP) ───────────────────────
  const networkTarget = ip || domain;
  if (networkTarget) {
    try {
      let resolvedIP = ip;

      if (!resolvedIP && domain) {
        const ips = await dns.resolve4(domain).catch(() => []);
        resolvedIP = ips[0] || null;
      }

      if (resolvedIP) {
        const [shodanData, scannedPorts] = await Promise.all([
          shodanHostLookup(resolvedIP),
          scanPorts(resolvedIP),
        ]);
        const openPorts = shodanData?.ports || scannedPorts || [];
        const vulns     = shodanData?.vulns ? Object.keys(shodanData.vulns) : [];
        const netScore  = calcNetworkRiskScore(openPorts, vulns);
        subScores.network = netScore;
        results.network   = {
          ip:        resolvedIP,
          indexed:   !!shodanData,
          riskScore: netScore,
          riskLevel: netScore >= 60 ? "HIGH" : netScore >= 30 ? "MEDIUM" : "LOW",
          openPorts,
          vulnCount: vulns.length,
          country:   shodanData?.country_name || null,
          org:       shodanData?.org          || null,
        };
      }
    } catch (err) {
      errors.network = err.message;
    }
  }

  // ── 4. Social media footprint (requires username) ─────────────────────────
  if (username) {
    try {
      const found         = await checkAllPlatforms(username);
      const socialScore   = calcSocialRiskScore(found);
      subScores.social    = socialScore;
      results.social      = {
        username,
        foundCount:  found.length,
        riskScore:   socialScore,
        riskLevel:   socialScore >= 60 ? "HIGH" : socialScore >= 30 ? "MEDIUM" : "LOW",
        platforms:   found,
      };
    } catch (err) {
      errors.social = err.message;
    }
  }

  // ── 5. NLP threat detection on domain WHOIS / social bios ────────────────
  //       (runs on any free-text we collected; lightweight always-on step)
  const textToAnalyze = [
    results.domain?.whois?.registrantOrg,
    results.domain?.whois?.registrantCountry,
    email,
    username,
  ]
    .filter(Boolean)
    .join(" ");

  if (textToAnalyze.trim().length > 5) {
    try {
      const findings      = analyzeText(textToAnalyze);
      const threatScore   = calcThreatRiskScore(findings);
      subScores.threat    = threatScore;
      results.threat      = {
        analysedText: textToAnalyze.substring(0, 200),
        findingsCount: findings.length,
        riskScore:     threatScore,
        riskLevel:     threatScore >= 60 ? "HIGH" : threatScore >= 30 ? "MEDIUM" : "LOW",
        findings,
      };
    } catch (err) {
      errors.threat = err.message;
    }
  }

  // ── 6. Compute final risk score ───────────────────────────────────────────
  const { finalScore, riskLevel, breakdown, recommendations, badge } =
    calcFinalRiskScore(subScores, target);

  // ── 7. Persist scan result to MongoDB ─────────────────────────────────────
  let savedScanId = null;
  try {
    const saved = await ScanResult.create({
      target,
      subScores,
      results,
      finalScore,
      riskLevel,
      breakdown,
      scanErrors: errors,
      scanType: "FULL",
    });
    savedScanId = saved._id;
  } catch (dbErr) {
    // Non-fatal: if DB save fails, still return the result to the client
    errors.db = `Failed to persist scan: ${dbErr.message}`;
  }

  return res.status(200).json({
    success: true,
    scanId:  savedScanId,
    target,
    finalScore,
    riskLevel,
    badge,
    breakdown,
    results,
    errors,
    recommendations,
    scanType:  "FULL",
    completedAt: new Date().toISOString(),
  });
});

/**
 * GET /api/osint/scan/:id
 * Retrieve a previously saved scan result by MongoDB ObjectId.
 */
router.get("/:id", async (req, res) => {
  try {
    const scan = await ScanResult.findById(req.params.id).lean();
    if (!scan) {
      return res.status(404).json({ success: false, error: "Scan not found." });
    }
    return res.json({ success: true, scan });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/osint/scan
 * List recent scans (last 50, newest first).
 */
router.get("/", async (req, res) => {
  try {
    const scans = await ScanResult.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .select("target finalScore riskLevel scanType createdAt")
      .lean();
    return res.json({ success: true, count: scans.length, scans });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
