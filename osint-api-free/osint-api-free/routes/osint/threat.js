/**
 * OSINT Module: NLP-Based Threat Detection
 * Analyses free-form text (scraped bios, posts, forum content) for threat signals.
 * Uses pattern matching + keyword classification. No external ML service required.
 * (Can be upgraded to a hosted model if desired.)
 *
 * Routes:
 *   POST /api/osint/threat/analyze-text   — analyse plain text content
 *   POST /api/osint/threat/analyze-url    — fetch a URL's content and analyse it
 */

const express = require("express");
const axios   = require("axios");
const router  = express.Router();

// ─── Threat signal dictionaries ───────────────────────────────────────────────

const THREAT_PATTERNS = {
  credentials: {
    risk:     "HIGH",
    label:    "Credential Exposure",
    patterns: [
      /password\s*[:=]\s*\S+/gi,
      /passwd\s*[:=]\s*\S+/gi,
      /api[_\s-]?key\s*[:=]\s*[A-Za-z0-9_\-]{10,}/gi,
      /secret\s*[:=]\s*\S+/gi,
      /token\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}/gi,
      /private[_\s-]?key/gi,
    ],
  },
  hacking: {
    risk:     "HIGH",
    label:    "Hacking / Exploitation Language",
    patterns: [
      /\b(exploit|payload|reverse shell|shell code|shellcode|privilege escalation|privesc|0day|zero.?day)\b/gi,
      /\b(sql injection|sqli|xss|csrf|ssrf|lfi|rfi|path traversal|buffer overflow)\b/gi,
      /\b(metasploit|msfvenom|cobalt strike|mimikatz|empire framework|bloodhound|crackmapexec)\b/gi,
      /\b(hash crack|hashcat|john the ripper|hydra brute|brute.?force)\b/gi,
    ],
  },
  darkweb: {
    risk:     "HIGH",
    label:    "Dark Web / Illicit Market References",
    patterns: [
      /\.onion/gi,
      /\b(tor browser|tor network|dark.?web|dark.?net|hidden service)\b/gi,
      /\b(buy (drugs|carding|fullz|dumps|cc|cvv)|sell (accounts|credentials|credit cards))\b/gi,
    ],
  },
  personalInfo: {
    risk:     "MEDIUM",
    label:    "Personal Information Exposure",
    patterns: [
      /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g,                 // US phone number
      /\b[A-Z]{5}\d{4}[A-Z]{1}\b/g,                         // Indian PAN card pattern
      /\b\d{12}\b/g,                                          // Aadhaar-length number
      /\b(home address|my address|i live at|residing at)\b/gi,
      /\b(date of birth|dob|born on)\s*:?\s*\d/gi,
      /\b(ssn|social security)\s*[:=\s]\s*\d{3}-?\d{2}-?\d{4}\b/gi,
    ],
  },
  malware: {
    risk:     "HIGH",
    label:    "Malware / Ransomware References",
    patterns: [
      /\b(ransomware|keylogger|trojan|rootkit|botnet|c2 server|command and control|rat\b|remote access trojan)\b/gi,
      /\b(dropper|loader|stealer|infostealer|credential harvester)\b/gi,
      /\b(encrypt your files|decrypt|bitcoin ransom|pay in crypto)\b/gi,
    ],
  },
  phishing: {
    risk:     "MEDIUM",
    label:    "Phishing / Social Engineering",
    patterns: [
      /\b(phish|spear phish|whaling|vishing|smishing|pretexting)\b/gi,
      /\b(click here to verify|update your (password|account|details)|suspended account|verify your identity)\b/gi,
      /\b(impersonat|fake (login|page|website)|clone (site|page))\b/gi,
    ],
  },
  dataLeaks: {
    risk:     "HIGH",
    label:    "Data Leak / Database Dump References",
    patterns: [
      /\b(database dump|db dump|leaked data|data breach|credential dump|combolist|combo list)\b/gi,
      /\b(pastebin\.com|paste\.ee|hastebin)\/.{5,}/gi,
      /\b(download (users|emails|passwords|fullz|dumps))\b/gi,
    ],
  },
  networkRecon: {
    risk:     "MEDIUM",
    label:    "Network Reconnaissance Language",
    patterns: [
      /\b(nmap|masscan|shodan|censys|port scan|network scan|recon)\b/gi,
      /\b(vulnerability scan|vuln scan|nikto|dirb|gobuster|ffuf|wfuzz)\b/gi,
      /\b(footprint(ing)?|osint|open source intelligence)\b/gi,
    ],
  },
};

// ─── helpers ──────────────────────────────────────────────────────────────────

/**
 * Run all threat patterns against a text string.
 * Returns an array of findings.
 */
function analyzeText(text) {
  if (!text || typeof text !== "string") return [];

  const findings = [];

  for (const [category, { risk, label, patterns }] of Object.entries(THREAT_PATTERNS)) {
    const matches = [];

    for (const regex of patterns) {
      let m;
      regex.lastIndex = 0;
      while ((m = regex.exec(text)) !== null) {
        // Avoid duplicate matches
        if (!matches.includes(m[0])) {
          matches.push(m[0].substring(0, 80)); // truncate very long matches
        }
      }
    }

    if (matches.length > 0) {
      findings.push({
        category,
        label,
        risk,
        matchCount: matches.length,
        samples:    matches.slice(0, 5), // return up to 5 sample matches
      });
    }
  }

  return findings;
}

/**
 * Calculate NLP threat risk sub-score (0–100).
 */
function calcThreatRiskScore(findings) {
  if (!findings.length) return 0;
  let score = 0;
  for (const f of findings) {
    const weight = f.risk === "HIGH" ? 20 : 10;
    score += Math.min(f.matchCount * weight, 30); // cap per category
  }
  return Math.min(score, 100);
}

/**
 * Categorise the overall threat level of the content.
 */
function classifyContent(findings) {
  const highCount = findings.filter((f) => f.risk === "HIGH").length;
  if (highCount >= 3) return "MALICIOUS";
  if (highCount >= 1) return "SUSPICIOUS";
  if (findings.length > 0) return "MODERATE";
  return "CLEAN";
}

// ─── routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/threat/analyze-text
 * Body: { text: "...", context: "bio|post|forum" (optional) }
 */
router.post("/analyze-text", async (req, res) => {
  const { text, context = "general" } = req.body;

  if (!text || typeof text !== "string") {
    return res.status(400).json({ success: false, error: "text field is required." });
  }
  if (text.length > 50000) {
    return res.status(400).json({ success: false, error: "text must be under 50,000 characters." });
  }

  const findings     = analyzeText(text);
  const riskScore    = calcThreatRiskScore(findings);
  const riskLevel    = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";
  const contentClass = classifyContent(findings);

  return res.json({
    success:      true,
    context,
    textLength:   text.length,
    contentClass,
    riskScore,
    riskLevel,
    findingsCount: findings.length,
    findings,
    recommendations: buildThreatRecommendations(contentClass, findings),
  });
});

/**
 * POST /api/osint/threat/analyze-url
 * Body: { url: "https://..." }
 * Fetches the URL's text content and runs threat analysis.
 */
router.post("/analyze-url", async (req, res) => {
  const { url } = req.body;
  if (!url || !/^https?:\/\/.+/.test(url)) {
    return res.status(400).json({ success: false, error: "Valid http(s) URL required." });
  }

  // Block private/internal IPs and localhost
  const blocked = /localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\./i;
  if (blocked.test(url)) {
    return res.status(403).json({ success: false, error: "Fetching private/internal URLs is not allowed." });
  }

  try {
    const { data, headers } = await axios.get(url, {
      timeout:        10000,
      maxRedirects:   3,
      responseType:   "text",
      headers:        { "User-Agent": "OSINT-Risk-Suite/1.0 (threat-scanner)" },
    });

    const contentType = headers["content-type"] || "";
    if (!/text|html|json/.test(contentType)) {
      return res.status(415).json({ success: false, error: "Only text/HTML/JSON content is analysable." });
    }

    const text         = typeof data === "string" ? data.substring(0, 50000) : JSON.stringify(data).substring(0, 50000);
    const findings     = analyzeText(text);
    const riskScore    = calcThreatRiskScore(findings);
    const riskLevel    = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";
    const contentClass = classifyContent(findings);

    return res.json({
      success: true,
      url,
      contentType,
      textLength:      text.length,
      contentClass,
      riskScore,
      riskLevel,
      findingsCount:   findings.length,
      findings,
      recommendations: buildThreatRecommendations(contentClass, findings),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: `URL fetch failed: ${err.message}` });
  }
});

// ─── recommendations ──────────────────────────────────────────────────────────

function buildThreatRecommendations(contentClass, findings) {
  const recs = [];

  if (contentClass === "MALICIOUS") {
    recs.push("Content exhibits strong malicious indicators. Report to your security team immediately.");
    recs.push("Do not interact with any links, downloads, or instructions in this content.");
  } else if (contentClass === "SUSPICIOUS") {
    recs.push("Suspicious threat signals detected. Treat this content with caution.");
  }

  const hasCredentials = findings.find((f) => f.category === "credentials");
  if (hasCredentials) {
    recs.push("Credentials or API keys appear to be exposed. Rotate them immediately.");
  }

  const hasPersonalInfo = findings.find((f) => f.category === "personalInfo");
  if (hasPersonalInfo) {
    recs.push("Personal information detected. Review and redact before further sharing.");
  }

  if (contentClass === "CLEAN") {
    recs.push("No threat signals detected in this content.");
  }

  return recs;
}

module.exports = router;
