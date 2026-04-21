/**
 * Service: Breach Detection (Free version)
 * Used by the scan orchestrator (scan.js)
 */

const axios  = require("axios");
const crypto = require("crypto");

const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY || "";

async function checkLeakCheck(email) {
  try {
    const { data } = await axios.get(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      { timeout: 8000, headers: { "User-Agent": "OSINT-Risk-Suite/1.0" } }
    );
    if (data?.found) {
      return { source: "LeakCheck.io", found: true, breachCount: data.found,
        sources: Array.isArray(data.sources) ? data.sources : [],
        hasPasswords: Array.isArray(data.sources) ? data.sources.some((s) => s.password) : false };
    }
    return { source: "LeakCheck.io", found: false, breachCount: 0, sources: [] };
  } catch { return null; }
}

async function checkEmailRep(email) {
  try {
    const { data } = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`,
      { timeout: 8000, headers: { "User-Agent": "OSINT-Risk-Suite/1.0", Accept: "application/json" } });
    if (!data?.details) return null;
    return {
      source: "EmailRep.io", found: data.details.data_breach === true,
      breachCount: data.details.data_breach ? 1 : 0,
      reputation: data.reputation, suspicious: data.suspicious || false,
      disposable: data.details.disposable || false,
      hasPasswords: data.details.credentials_leaked || false, sources: [],
    };
  } catch { return null; }
}

async function checkPwnedPasswords(email) {
  try {
    const sha1   = crypto.createHash("sha1").update(email.toLowerCase()).digest("hex").toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);
    const { data } = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`,
      { timeout: 6000, headers: { "Add-Padding": "true", "User-Agent": "OSINT-Risk-Suite/1.0" } });
    const match = data.split("\n").find((l) => l.toUpperCase().startsWith(suffix));
    if (match) {
      const count = parseInt(match.split(":")[1], 10);
      return { source: "PwnedPasswords", found: true, breachCount: 1, pwnedCount: count, hasPasswords: true, sources: [] };
    }
    return { source: "PwnedPasswords", found: false, breachCount: 0 };
  } catch { return null; }
}

async function queryAllBreachSources(email) {
  const [leakCheck, emailRep, pwnedPw] = await Promise.all([
    checkLeakCheck(email), checkEmailRep(email), checkPwnedPasswords(email),
  ]);
  const available = [leakCheck, emailRep, pwnedPw].filter(Boolean);
  const found     = available.filter((s) => s.found);
  return {
    found:          found.length > 0,
    sourcesQueried: available.map((s) => s.source),
    breachCount:    Math.max(...available.map((s) => s.breachCount || 0), 0),
    hasPasswords:   found.some((s) => s.hasPasswords),
    suspicious:     emailRep?.suspicious || false,
    disposable:     emailRep?.disposable || false,
    reputation:     emailRep?.reputation || null,
    breachDetails:  found.flatMap((s) => s.sources || []),
  };
}

function calcBreachRiskScore(result) {
  if (!result.found && !result.suspicious) return 0;
  let score = 0;
  if (result.found)         score += Math.min(result.breachCount * 12, 50);
  if (result.hasPasswords)  score += 25;
  if (result.suspicious)    score += 15;
  if (result.disposable)    score += 10;
  if (result.reputation === "none") score += 10;
  return Math.min(score, 100);
}

module.exports = { queryAllBreachSources, calcBreachRiskScore };
