/**
 * Service: Network Exposure (Free version — port scanner + optional free Shodan)
 * Used by the scan orchestrator (scan.js)
 */

const net  = require("net");
const axios = require("axios");

const SHODAN_API_KEY = process.env.SHODAN_API_KEY || "";

const HIGH_RISK_PORTS = [21, 23, 445, 3306, 3389, 5432, 6379, 8888, 9200, 27017, 2375];
const ALL_SCAN_PORTS  = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 2375, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017, 50070];

function scanPort(host, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let open = false;
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => { open = true; socket.destroy(); });
    socket.on("timeout", () => socket.destroy());
    socket.on("error",   () => socket.destroy());
    socket.on("close",   () => resolve(open));
    socket.connect(port, host);
  });
}

async function scanPorts(host, ports = ALL_SCAN_PORTS, batchSize = 20) {
  const openPorts = [];
  for (let i = 0; i < ports.length; i += batchSize) {
    const batch   = ports.slice(i, i + batchSize);
    const results = await Promise.all(batch.map(async (port) => ({ port, open: await scanPort(host, port) })));
    results.filter((r) => r.open).forEach((r) => openPorts.push(r.port));
  }
  return openPorts;
}

async function shodanHostLookup(ip) {
  if (!SHODAN_API_KEY) return null;
  try {
    const { data } = await axios.get(`https://api.shodan.io/shodan/host/${ip}`,
      { params: { key: SHODAN_API_KEY }, timeout: 12000 });
    return data;
  } catch (err) {
    if (err.response?.status === 404) return null;
    return null;
  }
}

function calcNetworkRiskScore(openPorts, vulns = []) {
  let score = 0;
  score += openPorts.filter((p) => HIGH_RISK_PORTS.includes(p)).length * 20;
  score += openPorts.filter((p) => !HIGH_RISK_PORTS.includes(p)).length * 3;
  score += vulns.length * 15;
  return Math.min(score, 100);
}

module.exports = { scanPorts, shodanHostLookup, calcNetworkRiskScore };
