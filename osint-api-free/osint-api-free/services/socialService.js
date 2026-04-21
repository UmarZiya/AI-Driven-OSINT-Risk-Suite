/**
 * Service: Social Media Footprint
 */
const axios = require("axios");

const PLATFORMS = [
  { name: "GitHub",      url: (u) => `https://github.com/${u}`,               category: "developer"  },
  { name: "Twitter/X",   url: (u) => `https://twitter.com/${u}`,              category: "social"     },
  { name: "Instagram",   url: (u) => `https://www.instagram.com/${u}/`,       category: "social"     },
  { name: "Reddit",      url: (u) => `https://www.reddit.com/user/${u}/about.json`, category: "social" },
  { name: "GitLab",      url: (u) => `https://gitlab.com/${u}`,               category: "developer"  },
  { name: "Dev.to",      url: (u) => `https://dev.to/${u}`,                   category: "developer"  },
  { name: "Medium",      url: (u) => `https://medium.com/@${u}`,              category: "blogging"   },
  { name: "Pastebin",    url: (u) => `https://pastebin.com/u/${u}`,           category: "misc"       },
  { name: "Twitch",      url: (u) => `https://www.twitch.tv/${u}`,            category: "streaming"  },
  { name: "TikTok",      url: (u) => `https://www.tiktok.com/@${u}`,         category: "social"     },
  { name: "Keybase",     url: (u) => `https://keybase.io/${u}`,              category: "identity"   },
  { name: "HackerNews",  url: (u) => `https://hacker-news.firebaseio.com/v0/user/${u}.json`, category: "developer" },
];

const HEADERS = { "User-Agent": "Mozilla/5.0 OSINT-Risk-Suite/1.0" };

async function checkAllPlatforms(username) {
  const clean = username.trim().toLowerCase();
  const checks = await Promise.allSettled(
    PLATFORMS.map(async (p) => {
      try {
        const r = await axios.get(p.url(clean), { headers: HEADERS, timeout: 7000, maxRedirects: 3, validateStatus: () => true });
        const found = r.status === 200;
        return { platform: p.name, category: p.category, found, url: p.url(clean) };
      } catch {
        return { platform: p.name, category: p.category, found: false, url: p.url(clean) };
      }
    })
  );
  return checks
    .filter((r) => r.status === "fulfilled" && r.value.found)
    .map((r) => r.value);
}

function calcSocialRiskScore(found) {
  if (!found.length) return 0;
  const score = Math.min(found.length * 5, 50);
  const highRisk = found.filter((p) => p.category === "misc").length * 10;
  return Math.min(score + highRisk, 100);
}

module.exports = { checkAllPlatforms, calcSocialRiskScore };


// ─────────────────────────────────────────────────────────────────────────────
/**
 * Service: NLP Threat Detection
 */

const THREAT_PATTERNS = {
  credentials: { risk: "HIGH",   patterns: [/password\s*[:=]\s*\S+/gi, /api[_\s-]?key\s*[:=]/gi, /token\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}/gi] },
  hacking:     { risk: "HIGH",   patterns: [/\b(exploit|payload|reverse shell|privilege escalation|0day)\b/gi, /\b(sql injection|xss|buffer overflow)\b/gi] },
  darkweb:     { risk: "HIGH",   patterns: [/\.onion/gi, /\b(dark.?web|hidden service)\b/gi] },
  malware:     { risk: "HIGH",   patterns: [/\b(ransomware|keylogger|trojan|botnet|c2 server)\b/gi] },
  phishing:    { risk: "MEDIUM", patterns: [/\b(phish|spear phish|smishing)\b/gi] },
  dataLeaks:   { risk: "HIGH",   patterns: [/\b(database dump|credential dump|combolist)\b/gi] },
  personalInfo:{ risk: "MEDIUM", patterns: [/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, /\b(home address|i live at)\b/gi] },
};

function analyzeText(text) {
  if (!text || typeof text !== "string") return [];
  const findings = [];
  for (const [category, { risk, patterns }] of Object.entries(THREAT_PATTERNS)) {
    const matches = [];
    for (const regex of patterns) {
      regex.lastIndex = 0;
      let m;
      while ((m = regex.exec(text)) !== null) {
        if (!matches.includes(m[0])) matches.push(m[0].substring(0, 80));
      }
    }
    if (matches.length) findings.push({ category, risk, matchCount: matches.length, samples: matches.slice(0, 3) });
  }
  return findings;
}

function calcThreatRiskScore(findings) {
  let score = 0;
  for (const f of findings) {
    score += Math.min(f.matchCount * (f.risk === "HIGH" ? 20 : 10), 30);
  }
  return Math.min(score, 100);
}

module.exports = { ...module.exports, analyzeText, calcThreatRiskScore };


// ─────────────────────────────────────────────────────────────────────────────
/**
 * Service: Final Risk Score Calculator
 */

const WEIGHTS = { breach: 0.30, network: 0.25, threat: 0.20, domain: 0.10, social: 0.10, exif: 0.05 };

function calcFinalRiskScore(subScores, target = {}) {
  const provided = Object.entries(WEIGHTS)
    .filter(([m]) => subScores[m] !== undefined)
    .map(([m, w]) => ({ module: m, score: Math.min(100, Math.max(0, Number(subScores[m]))), weight: w }));

  if (!provided.length) return { finalScore: 0, riskLevel: "LOW", breakdown: {}, recommendations: [], badge: {} };

  const totalW = provided.reduce((s, v) => s + v.weight, 0);
  const finalScore = Math.round(provided.reduce((s, v) => s + v.score * v.weight, 0) / totalW);

  const riskLevel = finalScore >= 80 ? "CRITICAL" : finalScore >= 60 ? "HIGH" : finalScore >= 35 ? "MEDIUM" : "LOW";

  const breakdown = Object.fromEntries(provided.map(({ module, score, weight }) => [module, { score, weight, level: score >= 60 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW" }]));

  const colors = { CRITICAL: "#FF0000", HIGH: "#FF6600", MEDIUM: "#FFB800", LOW: "#00CC44" };
  const badge = { label: riskLevel, score: finalScore, color: colors[riskLevel] };

  const recommendations = [];
  if (riskLevel === "CRITICAL" || riskLevel === "HIGH") recommendations.push("Immediate action required — review all flagged areas.");
  if (subScores.breach >= 60) recommendations.push("Change all breached passwords and enable 2FA.");
  if (subScores.network >= 60) recommendations.push("Close high-risk open ports and patch CVEs.");
  if (subScores.social >= 60) recommendations.push("Reduce social media exposure and deactivate unused accounts.");

  return { finalScore, riskLevel, breakdown, recommendations, badge };
}

module.exports = { ...module.exports, calcFinalRiskScore };
