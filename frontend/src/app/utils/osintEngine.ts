// OSINT Engine — calls the real osint-api-free backend
import type { ScanTarget, ScanResult } from '../types';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('osint_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

// ── All mock data commented out ───────────────────────────────────────────────
// const MOCK_BREACHES = [ { name: 'LinkedIn Data Leak 2021', ... }, ... ]
// const PLATFORMS = ['Twitter', 'Facebook', 'Instagram', ...]
// const VULNERABILITIES = ['CVE-2021-44228 (Log4Shell)', ...]
// async function scanBreaches(email?) { await delay(800); Math.random()... }
// async function scanWhois(domain) { await delay(600); Math.random()... }
// async function scanShodan(ip) { await delay(1000); Math.random()... }
// async function scanSocialMedia(username) { await delay(700); Math.random()... }
// async function scanExifData() { await delay(500); Math.random()... }
// async function performNLPAnalysis(target) { await delay(900); Math.random()... }
// function calculateRiskScore(data) { ... Math.random() mlConfidence ... }
// function generateRecommendations(score, breaches, shodan) { ... }
// function generateScanId() { return `scan_${Date.now()}_${Math.random()...}` }
// function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)) }
// function shuffleArray(array) { ... }
// ─────────────────────────────────────────────────────────────────────────────

export async function performOSINTScan(target: ScanTarget): Promise<ScanResult> {
  const res = await fetch(`${API_URL}/osint/scan/full`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({
      email:    target.email     || undefined,
      domain:   target.domain    || undefined,
      username: target.username  || undefined,
      ip:       target.ipAddress || undefined,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Scan request failed');
  }

  const data = await res.json();
  return mapApiResponse(data, target);
}

export async function fetchScanHistory() {
  const res = await fetch(`${API_URL}/osint/scan`, { headers: authHeaders() });
  if (!res.ok) return [];
  const data = await res.json();
  return (data.scans || []).map((s: any) => ({
    id:        s._id,
    target:    s.target.email || s.target.domain || s.target.username || s.target.ip || 'Unknown',
    timestamp: s.createdAt,
    riskScore: s.finalScore,
    status:    'completed' as const,
  }));
}

export async function fetchScanById(id: string): Promise<ScanResult | null> {
  const res = await fetch(`${API_URL}/osint/scan/${id}`, { headers: authHeaders() });
  if (!res.ok) return null;
  const data = await res.json();
  if (!data.scan) return null;
  const s = data.scan;
  const target: ScanTarget = {
    email:     s.target.email    || undefined,
    domain:    s.target.domain   || undefined,
    username:  s.target.username || undefined,
    ipAddress: s.target.ip       || undefined,
  };
  return mapApiResponse({
    ...s,
    scanId:          s._id,
    completedAt:     s.createdAt,
    recommendations: s.recommendations || [],
  }, target);
}

function mapApiResponse(data: any, target: ScanTarget): ScanResult {
  const r = data.results || {};

  // ── Breaches ────────────────────────────────────────────────────────────────
  const breaches: ScanResult['breaches'] = [];
  if (r.breach?.breachCount > 0) {
    const sev = r.breach.riskScore >= 70 ? 'high' : r.breach.riskScore >= 35 ? 'medium' : 'low';
    (r.breach.breaches || []).forEach((b: any) => {
      breaches.push({
        name:            b.source || 'Unknown Breach',
        date:            b.date   || new Date().toISOString(),
        dataClasses:     b.dataClasses || [],
        severity:        sev as 'low' | 'medium' | 'high' | 'critical',
        affectedRecords: b.count || 0,
      });
    });
    if (breaches.length === 0) {
      breaches.push({
        name:            `${r.breach.breachCount} breach(es) detected`,
        date:            new Date().toISOString(),
        dataClasses:     r.breach.hasPasswords ? ['Passwords', 'Email addresses'] : ['Email addresses'],
        severity:        sev as 'low' | 'medium' | 'high' | 'critical',
        affectedRecords: r.breach.breachCount,
      });
    }
  }

  // ── WHOIS ───────────────────────────────────────────────────────────────────
  const whois = r.domain?.whois ? {
    domain:       target.domain || '',
    registrar:    r.domain.whois.registrar    || 'Unknown',
    createdDate:  r.domain.whois.registeredOn || '',
    expiryDate:   r.domain.whois.expiresOn    || '',
    nameServers:  r.domain.whois.nameServers  || [],
    exposedEmail: false,
  } : undefined;

  // ── Network ─────────────────────────────────────────────────────────────────
  const shodan = r.network ? {
    ip:              r.network.ip || '',
    openPorts:       r.network.openPorts || [],
    services:        (r.network.openPorts || []).map((p: number) => ({
      port: p, service: portLabel(p), version: '',
    })),
    vulnerabilities: r.network.vulnCount > 0
      ? [`${r.network.vulnCount} vulnerabilit${r.network.vulnCount === 1 ? 'y' : 'ies'} detected`]
      : [],
    country:         r.network.country || '',
    organization:    r.network.org     || '',
  } : undefined;

  // ── Social ──────────────────────────────────────────────────────────────────
  const socialMedia = (r.social?.platforms || []).map((p: any) => ({
    platform:   p.platform,
    username:   target.username || '',
    url:        p.url,
    isPublic:   true,
    lastActive: new Date().toISOString(),
  }));

  // ── NLP Threat ──────────────────────────────────────────────────────────────
  const nlpAnalysis = r.threat ? {
    sentiment:   (r.threat.riskScore >= 60 ? 'threatening' : 'neutral') as
                   'positive' | 'neutral' | 'negative' | 'threatening',
    threatLevel: r.threat.riskScore || 0,
    keywords:    (r.threat.findings || [])
                   .flatMap((f: any) => f.samples || [f.category])
                   .slice(0, 5),
    isDoxxed:    (r.threat.findings || []).some((f: any) => f.category === 'personalInfo'),
    mentions:    r.threat.findingsCount || 0,
  } : undefined;

  // ── Risk score ──────────────────────────────────────────────────────────────
  const bd = data.breakdown || {};
  const riskScore = {
    overall: data.finalScore || 0,
    categories: {
      dataBreaches:    bd.breach?.score  ?? r.breach?.riskScore  ?? 0,
      domainSecurity:  bd.domain?.score  ?? r.domain?.riskScore  ?? 0,
      networkExposure: bd.network?.score ?? r.network?.riskScore ?? 0,
      socialFootprint: bd.social?.score  ?? r.social?.riskScore  ?? 0,
      privacyLeaks:    bd.exif?.score    ?? 0,
    },
    mlConfidence: 0.85,
  };

  return {
    id:              data.scanId || `scan_${Date.now()}`,
    target,
    timestamp:       data.completedAt || new Date().toISOString(),
    status:          'completed',
    breaches,
    whois,
    shodan,
    socialMedia,
    exifData:        [],
    nlpAnalysis,
    riskScore,
    recommendations: data.recommendations || [],
  };
}

function portLabel(port: number): string {
  const map: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL',
    5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB',
  };
  return map[port] || `Port ${port}`;
}
