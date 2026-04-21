/**
 * OSINT Module: Network Exposure Analysis (FREE — No Paid API)
 *
 * Strategy (layered, all free):
 *   1. Shodan Free API  — register at shodan.io, free tier gives host lookups
 *                         (Free account = 100 query credits/month, no credit card)
 *   2. Built-in Port Scanner — uses Node's net module, no API needed at all
 *   3. Censys Free API  — register at censys.io, free tier (250 queries/month)
 *
 * The port scanner runs regardless of API availability.
 * It scans the most commonly exposed/dangerous ports directly.
 *
 * Routes:
 *   POST /api/osint/network/ip      — full lookup for an IP
 *   POST /api/osint/network/domain  — resolve domain → IP → scan
 *   POST /api/osint/network/ports   — direct port scan only (no API key needed)
 */

const express = require("express");
const net     = require("net");
const dns     = require("dns").promises;
const axios   = require("axios");
const router  = express.Router();

// ─── Free API credentials ─────────────────────────────────────────────────────
// Shodan: free account at https://account.shodan.io — no credit card required
// Censys: free account at https://censys.io — no credit card required

const SHODAN_API_KEY  = process.env.SHODAN_API_KEY  || "";   // Free tier key
const CENSYS_API_ID   = process.env.CENSYS_API_ID   || "";   // Free tier
const CENSYS_API_SECRET = process.env.CENSYS_API_SECRET || "";

// ─── Port definitions ─────────────────────────────────────────────────────────

const PORTS_TO_SCAN = {
  // Critical / HIGH risk
  21:    { service: "FTP",        risk: "HIGH",   reason: "Plaintext file transfer — often misconfigured" },
  22:    { service: "SSH",        risk: "MEDIUM", reason: "Common brute-force target if weak passwords" },
  23:    { service: "Telnet",     risk: "HIGH",   reason: "Plaintext protocol — completely insecure" },
  25:    { service: "SMTP",       risk: "MEDIUM", reason: "Mail relay — can be abused if open relay" },
  53:    { service: "DNS",        risk: "LOW",    reason: "DNS service" },
  80:    { service: "HTTP",       risk: "LOW",    reason: "Web server — check for sensitive endpoints" },
  110:   { service: "POP3",       risk: "MEDIUM", reason: "Email — plaintext if not TLS" },
  143:   { service: "IMAP",       risk: "MEDIUM", reason: "Email — plaintext if not TLS" },
  443:   { service: "HTTPS",      risk: "LOW",    reason: "Secure web server" },
  445:   { service: "SMB",        risk: "HIGH",   reason: "File sharing — WannaCry/NotPetya vector" },
  1433:  { service: "MSSQL",      risk: "HIGH",   reason: "SQL Server exposed to internet" },
  1521:  { service: "Oracle DB",  risk: "HIGH",   reason: "Oracle database exposed" },
  2375:  { service: "Docker",     risk: "HIGH",   reason: "Docker daemon — full container escape possible" },
  3306:  { service: "MySQL",      risk: "HIGH",   reason: "Database exposed to internet" },
  3389:  { service: "RDP",        risk: "HIGH",   reason: "Remote Desktop — common ransomware entry point" },
  4444:  { service: "Metasploit", risk: "HIGH",   reason: "Default Metasploit reverse shell port" },
  5432:  { service: "PostgreSQL", risk: "HIGH",   reason: "Database exposed to internet" },
  5900:  { service: "VNC",        risk: "HIGH",   reason: "Remote desktop — often no auth" },
  6379:  { service: "Redis",      risk: "HIGH",   reason: "Usually unauthenticated — critical risk" },
  8080:  { service: "HTTP Alt",   risk: "MEDIUM", reason: "Dev/proxy server — may expose admin panels" },
  8443:  { service: "HTTPS Alt",  risk: "LOW",    reason: "Alternate HTTPS port" },
  8888:  { service: "Jupyter",    risk: "HIGH",   reason: "Jupyter Notebook — often no auth, RCE risk" },
  9200:  { service: "Elasticsearch", risk: "HIGH", reason: "Often unauthenticated, exposes all data" },
  27017: { service: "MongoDB",    risk: "HIGH",   reason: "Database — historically often left open" },
  50070: { service: "Hadoop",     risk: "HIGH",   reason: "Hadoop admin interface exposed" },
};

// ─── Built-in Port Scanner (no API key needed) ────────────────────────────────

/**
 * Attempt a TCP connection to a single host:port.
 * Returns true if port is open (connection accepted), false otherwise.
 * Timeout: 2 seconds per port.
 */
function scanPort(host, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let open = false;

    socket.setTimeout(timeoutMs);

    socket.on("connect", () => {
      open = true;
      socket.destroy();
    });

    socket.on("timeout", () => socket.destroy());
    socket.on("error",   () => socket.destroy());
    socket.on("close",   () => resolve(open));

    socket.connect(port, host);
  });
}

/**
 * Scan multiple ports concurrently (batched to avoid overwhelming the target).
 * Returns array of open port numbers.
 */
async function scanPorts(host, ports, batchSize = 20) {
  const openPorts = [];
  const portList  = Array.isArray(ports) ? ports : Object.keys(ports).map(Number);

  // Process in batches
  for (let i = 0; i < portList.length; i += batchSize) {
    const batch   = portList.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (port) => ({ port, open: await scanPort(host, port) }))
    );
    results.filter((r) => r.open).forEach((r) => openPorts.push(r.port));
  }

  return openPorts;
}

// ─── Shodan Free API ──────────────────────────────────────────────────────────

async function shodanLookup(ip) {
  if (!SHODAN_API_KEY) return null;

  try {
    const { data } = await axios.get(
      `https://api.shodan.io/shodan/host/${ip}`,
      { params: { key: SHODAN_API_KEY }, timeout: 12000 }
    );
    return {
      source:    "Shodan",
      ports:     data.ports     || [],
      hostnames: data.hostnames || [],
      country:   data.country_name || null,
      org:       data.org          || null,
      isp:       data.isp          || null,
      lastSeen:  data.last_update  || null,
      vulns:     data.vulns ? Object.keys(data.vulns) : [],
      services:  (data.data || []).map((s) => ({
        port:    s.port,
        product: s.product || null,
        version: s.version || null,
        banner:  s.data ? s.data.substring(0, 150) : null,
      })),
    };
  } catch (err) {
    if (err.response?.status === 404) return null;
    return null; // Silently fall through to port scanner
  }
}

// ─── Censys Free API ──────────────────────────────────────────────────────────

async function censysLookup(ip) {
  if (!CENSYS_API_ID || !CENSYS_API_SECRET) return null;

  try {
    const { data } = await axios.get(
      `https://search.censys.io/api/v2/hosts/${ip}`,
      {
        auth:    { username: CENSYS_API_ID, password: CENSYS_API_SECRET },
        timeout: 12000,
      }
    );

    const result = data.result || {};
    const services = (result.services || []).map((s) => ({
      port:        s.port,
      protocol:    s.transport_protocol,
      serviceName: s.service_name,
      product:     s.software?.[0]?.product || null,
    }));

    return {
      source:    "Censys",
      ports:     services.map((s) => s.port),
      country:   result.location?.country    || null,
      org:       result.autonomous_system?.name || null,
      lastSeen:  result.last_updated_at      || null,
      services,
    };
  } catch {
    return null;
  }
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────

function classifyPorts(openPorts) {
  const high   = [];
  const medium = [];
  const low    = [];

  for (const port of openPorts) {
    const info = PORTS_TO_SCAN[port];
    if (!info) { low.push({ port, service: "Unknown", risk: "LOW" }); continue; }
    const entry = { port, service: info.service, reason: info.reason };
    if (info.risk === "HIGH")   high.push(entry);
    else if (info.risk === "MEDIUM") medium.push(entry);
    else low.push(entry);
  }

  return { high, medium, low };
}

function calcNetworkRiskScore(openPorts, vulns = []) {
  const classified = classifyPorts(openPorts);
  let score = 0;
  score += classified.high.length   * 20;
  score += classified.medium.length * 8;
  score += classified.low.length    * 2;
  score += vulns.length             * 15;
  return Math.min(score, 100);
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/network/ports
 * Direct port scan — no API key needed at all.
 * Body: { host: "example.com" OR "8.8.8.8" }
 */
router.post("/ports", async (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ success: false, error: "host is required." });

  // Block scanning private/internal ranges
  const privateRanges = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
  if (privateRanges.test(host)) {
    return res.status(403).json({ success: false, error: "Scanning private/internal addresses is not allowed." });
  }

  try {
    const resolvedIP = /^\d+\.\d+\.\d+\.\d+$/.test(host)
      ? host
      : (await dns.resolve4(host).catch(() => [host]))[0];

    const openPorts  = await scanPorts(resolvedIP, Object.keys(PORTS_TO_SCAN).map(Number));
    const classified = classifyPorts(openPorts);
    const riskScore  = calcNetworkRiskScore(openPorts);
    const riskLevel  = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";

    return res.json({
      success: true,
      host,
      resolvedIP,
      scanMethod:  "direct-tcp",
      openPorts,
      portCount:   openPorts.length,
      portRisk:    classified,
      riskScore,
      riskLevel,
      recommendations: buildNetworkRecommendations(classified, []),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/osint/network/ip
 * Full lookup: Shodan (if key available) + built-in port scan
 * Body: { ip: "8.8.8.8" }
 */
router.post("/ip", async (req, res) => {
  const { ip } = req.body;
  if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return res.status(400).json({ success: false, error: "Valid IPv4 address required." });
  }

  const privateRanges = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
  if (privateRanges.test(ip)) {
    return res.status(403).json({ success: false, error: "Scanning private IP ranges is not allowed." });
  }

  try {
    // Run API lookups and port scan concurrently
    const [shodanData, censysData, scannedPorts] = await Promise.all([
      shodanLookup(ip),
      censysLookup(ip),
      scanPorts(ip, Object.keys(PORTS_TO_SCAN).map(Number)),
    ]);

    // Merge all open ports from all sources
    const allPorts = [...new Set([
      ...scannedPorts,
      ...(shodanData?.ports  || []),
      ...(censysData?.ports  || []),
    ])].sort((a, b) => a - b);

    const vulns      = shodanData?.vulns || [];
    const classified = classifyPorts(allPorts);
    const riskScore  = calcNetworkRiskScore(allPorts, vulns);
    const riskLevel  = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";

    // Merge service info from available sources
    const services = shodanData?.services || censysData?.services || [];

    const sourcesUsed = ["direct-port-scan"];
    if (shodanData)  sourcesUsed.push("shodan-free");
    if (censysData)  sourcesUsed.push("censys-free");

    return res.json({
      success: true,
      ip,
      sourcesUsed,
      country:   shodanData?.country || censysData?.country || null,
      org:       shodanData?.org     || censysData?.org     || null,
      hostnames: shodanData?.hostnames || [],
      openPorts: allPorts,
      portCount: allPorts.length,
      portRisk:  classified,
      services,
      vulns,
      riskScore,
      riskLevel,
      recommendations: buildNetworkRecommendations(classified, vulns),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/osint/network/domain
 * Body: { domain: "example.com" }
 */
router.post("/domain", async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ success: false, error: "domain is required." });

  try {
    const ips = await dns.resolve4(domain).catch(() => []);
    if (!ips.length) {
      return res.status(404).json({ success: false, error: `Could not resolve domain: ${domain}` });
    }

    // Scan first resolved IP
    const ip         = ips[0];
    const [shodanData, scannedPorts] = await Promise.all([
      shodanLookup(ip),
      scanPorts(ip, Object.keys(PORTS_TO_SCAN).map(Number)),
    ]);

    const allPorts  = [...new Set([...scannedPorts, ...(shodanData?.ports || [])])].sort((a, b) => a - b);
    const vulns     = shodanData?.vulns || [];
    const riskScore = calcNetworkRiskScore(allPorts, vulns);

    return res.json({
      success: true,
      domain,
      resolvedIPs: ips,
      primaryIP:   ip,
      openPorts:   allPorts,
      portRisk:    classifyPorts(allPorts),
      vulns,
      country:     shodanData?.country || null,
      org:         shodanData?.org     || null,
      riskScore,
      riskLevel:   riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW",
      recommendations: buildNetworkRecommendations(classifyPorts(allPorts), vulns),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Recommendations ──────────────────────────────────────────────────────────

function buildNetworkRecommendations(portRisk, vulns) {
  const recs = [];

  if (portRisk.high.length) {
    recs.push(`Close or firewall these high-risk open ports: ${portRisk.high.map((p) => `${p.port} (${p.service})`).join(", ")}.`);
  }
  if (portRisk.high.find((p) => p.port === 3389))  recs.push("Restrict RDP (3389) behind a VPN or IP whitelist immediately.");
  if (portRisk.high.find((p) => p.port === 6379))  recs.push("Redis (6379) is typically unauthenticated. Bind to localhost only.");
  if (portRisk.high.find((p) => p.port === 27017)) recs.push("MongoDB (27017) exposed. Add authentication and bind to localhost.");
  if (portRisk.high.find((p) => p.port === 9200))  recs.push("Elasticsearch (9200) exposed. Enable security features immediately.");
  if (portRisk.high.find((p) => p.port === 2375))  recs.push("Docker daemon (2375) is publicly exposed — this allows full server takeover. Close immediately.");
  if (vulns.length) recs.push(`${vulns.length} known CVE(s) detected via Shodan. Apply patches immediately.`);
  if (!recs.length) recs.push("No critical exposures detected from this scan.");

  return recs;
}

module.exports = router;
module.exports.shodanLookup        = shodanLookup;
module.exports.scanPorts           = scanPorts;
module.exports.calcNetworkRiskScore = calcNetworkRiskScore;
module.exports.classifyPorts       = classifyPorts;
