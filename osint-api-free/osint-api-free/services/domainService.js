/**
 * Service: Domain Analysis
 */
const dns   = require("dns").promises;
const whois = require("whois-json");

async function performWhois(domain) {
  const raw = await whois(domain);
  return {
    registrar:         raw.registrar      || null,
    registeredOn:      raw.creationDate   || null,
    expiresOn:         raw.expirationDate || null,
    updatedOn:         raw.updatedDate    || null,
    registrantOrg:     raw.registrantOrganization || null,
    registrantCountry: raw.registrantCountry      || null,
    nameServers:       raw.nameServer ? [].concat(raw.nameServer) : [],
    status:            raw.domainStatus  ? [].concat(raw.domainStatus) : [],
    dnssec:            raw.dNSSEC || "Unknown",
  };
}

async function enumerateDNS(domain) {
  const types = [
    { type: "A",   fn: () => dns.resolve4(domain)   },
    { type: "MX",  fn: () => dns.resolveMx(domain)  },
    { type: "NS",  fn: () => dns.resolveNs(domain)  },
    { type: "TXT", fn: () => dns.resolveTxt(domain) },
    { type: "SOA", fn: () => dns.resolveSoa(domain) },
  ];
  const records = {};
  await Promise.allSettled(
    types.map(async ({ type, fn }) => {
      try { records[type] = await fn(); } catch {}
    })
  );
  return records;
}

function calcDomainRiskScore(whoisData, dnsRecords) {
  let score = 0;
  if (whoisData?.registeredOn) {
    const age = (Date.now() - new Date(whoisData.registeredOn)) / 86400000;
    if (age < 30) score += 40;
    else if (age < 180) score += 20;
    else if (age < 365) score += 10;
  }
  if (whoisData?.dnssec && /unsigned/i.test(whoisData.dnssec)) score += 10;
  if (!dnsRecords?.MX?.length) score += 10;
  return Math.min(score, 100);
}

module.exports = { performWhois, enumerateDNS, calcDomainRiskScore };
