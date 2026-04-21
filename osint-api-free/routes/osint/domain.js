/**
 * OSINT Module: Domain Analysis
 * Performs WHOIS lookup + DNS record enumeration for a given domain.
 *
 * Routes:
 *   POST /api/osint/domain/whois   — WHOIS lookup
 *   POST /api/osint/domain/dns     — DNS record enumeration
 *   POST /api/osint/domain/full    — WHOIS + DNS combined
 */

const express = require("express");
const dns     = require("dns").promises;
const whois   = require("whois-json");           // npm i whois-json
const router  = express.Router();

// ─── helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve multiple DNS record types for a domain.
 * Returns only the types that were successfully resolved.
 */
async function enumerateDNS(domain) {
  const recordTypes = [
    { type: "A",     resolver: () => dns.resolve4(domain)        },
    { type: "AAAA",  resolver: () => dns.resolve6(domain)        },
    { type: "MX",    resolver: () => dns.resolveMx(domain)       },
    { type: "NS",    resolver: () => dns.resolveNs(domain)       },
    { type: "TXT",   resolver: () => dns.resolveTxt(domain)      },
    { type: "SOA",   resolver: () => dns.resolveSoa(domain)      },
    { type: "CNAME", resolver: () => dns.resolveCname(domain)    },
  ];

  const records = {};

  await Promise.allSettled(
    recordTypes.map(async ({ type, resolver }) => {
      try {
        const result = await resolver();
        records[type] = result;
      } catch {
        // Record type not available — silently skip
      }
    })
  );

  return records;
}

/**
 * Perform WHOIS query and normalise the result.
 */
async function performWhois(domain) {
  try {
    const raw = await whois(domain);
    return {
      registrar:       raw.registrar       || raw.Registrar       || null,
      registeredOn:    raw.creationDate    || raw.createdDate      || null,
      expiresOn:       raw.expirationDate  || raw.registrarRegistrationExpirationDate || null,
      updatedOn:       raw.updatedDate     || raw.lastUpdated      || null,
      registrantOrg:   raw.registrantOrganization || raw["Registrant Organization"] || null,
      registrantCountry: raw.registrantCountry || raw["Registrant Country"] || null,
      nameServers:     raw.nameServer ? (Array.isArray(raw.nameServer) ? raw.nameServer : [raw.nameServer]) : [],
      status:          raw.domainStatus ? (Array.isArray(raw.domainStatus) ? raw.domainStatus : [raw.domainStatus]) : [],
      dnssec:          raw.dNSSEC || raw.dnssec || "Unknown",
      raw,
    };
  } catch (err) {
    throw new Error(`WHOIS lookup failed: ${err.message}`);
  }
}

/**
 * Calculate domain risk sub-score (0–100).
 * Considers: domain age, DNSSEC, suspicious indicators.
 */
function calcDomainRiskScore(whoisData, dnsRecords) {
  let score = 0;

  // New domain = higher risk
  if (whoisData?.registeredOn) {
    const ageMs  = Date.now() - new Date(whoisData.registeredOn).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    if (ageDays < 30)   score += 40;
    else if (ageDays < 180) score += 20;
    else if (ageDays < 365) score += 10;
  }

  // No DNSSEC = slightly higher risk
  if (whoisData?.dnssec && /unsigned|unsigned delegation/i.test(whoisData.dnssec)) {
    score += 10;
  }

  // Missing MX record may indicate disposable/proxy domain
  if (!dnsRecords?.MX || dnsRecords.MX.length === 0) {
    score += 10;
  }

  // Suspicious TXT records (e.g., base64-looking strings, lots of TXT entries)
  if (dnsRecords?.TXT && dnsRecords.TXT.length > 10) {
    score += 10;
  }

  // Domain expiring in < 30 days
  if (whoisData?.expiresOn) {
    const expiryMs = new Date(whoisData.expiresOn).getTime() - Date.now();
    if (expiryMs < 30 * 24 * 60 * 60 * 1000) score += 15;
  }

  return Math.min(score, 100);
}

// ─── routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/domain/whois
 * Body: { domain: "example.com" }
 */
router.post("/whois", async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ success: false, error: "domain is required." });

  try {
    const whoisData = await performWhois(domain);
    return res.json({ success: true, domain, whois: whoisData });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/osint/domain/dns
 * Body: { domain: "example.com" }
 */
router.post("/dns", async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ success: false, error: "domain is required." });

  try {
    const records = await enumerateDNS(domain);
    return res.json({ success: true, domain, dns: records });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/osint/domain/full
 * Body: { domain: "example.com" }
 * Returns WHOIS + DNS + risk score combined.
 */
router.post("/full", async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ success: false, error: "domain is required." });

  try {
    const [whoisData, dnsRecords] = await Promise.allSettled([
      performWhois(domain),
      enumerateDNS(domain),
    ]);

    const whois   = whoisData.status  === "fulfilled" ? whoisData.value  : null;
    const dns     = dnsRecords.status === "fulfilled" ? dnsRecords.value : {};
    const whoisErr = whoisData.status  === "rejected"  ? whoisData.reason?.message  : null;

    const riskScore = calcDomainRiskScore(whois, dns);
    const riskLevel = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";

    return res.json({
      success: true,
      domain,
      riskScore,
      riskLevel,
      whois,
      whoisError: whoisErr,
      dns,
      recommendations: buildDomainRecommendations(riskLevel, whois, dns),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ─── recommendations ──────────────────────────────────────────────────────────

function buildDomainRecommendations(riskLevel, whois, dns) {
  const recs = [];

  if (riskLevel === "HIGH") {
    recs.push("Exercise caution — this domain exhibits multiple risk indicators.");
  }

  if (whois?.dnssec && /unsigned/i.test(whois.dnssec)) {
    recs.push("Enable DNSSEC to protect against DNS spoofing attacks.");
  }

  if (!dns?.MX || dns.MX.length === 0) {
    recs.push("No MX records found. Verify this is a legitimate domain before trusting associated emails.");
  }

  if (whois?.expiresOn) {
    const expiryMs = new Date(whois.expiresOn).getTime() - Date.now();
    if (expiryMs < 30 * 24 * 60 * 60 * 1000) {
      recs.push("Domain expiring soon. If you own this domain, renew it promptly.");
    }
  }

  return recs;
}

module.exports = router;
