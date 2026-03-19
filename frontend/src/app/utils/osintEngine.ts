// Mock OSINT Engine with ML Risk Scoring
import type { ScanTarget, ScanResult, BreachData, WhoisData, ShodanData, SocialMediaPresence, ExifData, NLPAnalysis, RiskScore } from '../types';

// Mock breach database
const MOCK_BREACHES: BreachData[] = [
  {
    name: 'LinkedIn Data Leak 2021',
    date: '2021-04-06',
    dataClasses: ['Email addresses', 'Full names', 'Phone numbers', 'Job titles'],
    severity: 'high',
    affectedRecords: 700000000,
  },
  {
    name: 'Adobe Breach 2013',
    date: '2013-10-04',
    dataClasses: ['Email addresses', 'Passwords', 'Password hints'],
    severity: 'critical',
    affectedRecords: 153000000,
  },
  {
    name: 'Dropbox Validation 2012',
    date: '2012-07-01',
    dataClasses: ['Email addresses', 'Passwords'],
    severity: 'high',
    affectedRecords: 68000000,
  },
  {
    name: 'MyFitnessPal',
    date: '2018-02-01',
    dataClasses: ['Email addresses', 'Usernames', 'Passwords'],
    severity: 'medium',
    affectedRecords: 144000000,
  },
];

const PLATFORMS = ['Twitter', 'Facebook', 'Instagram', 'LinkedIn', 'GitHub', 'Reddit', 'TikTok', 'Discord'];

const VULNERABILITIES = [
  'CVE-2021-44228 (Log4Shell)',
  'CVE-2022-22965 (Spring4Shell)',
  'CVE-2021-26855 (ProxyLogon)',
  'CVE-2020-1472 (Zerologon)',
  'CVE-2019-0708 (BlueKeep)',
];

// Simulate async OSINT data collection
export async function performOSINTScan(target: ScanTarget): Promise<ScanResult> {
  const scanId = generateScanId();
  
  // Simulate network delay for realism
  await delay(2000);

  const breaches = await scanBreaches(target.email);
  const whois = target.domain ? await scanWhois(target.domain) : undefined;
  const shodan = target.ipAddress ? await scanShodan(target.ipAddress) : undefined;
  const socialMedia = target.username ? await scanSocialMedia(target.username) : [];
  const exifData = await scanExifData();
  const nlpAnalysis = await performNLPAnalysis(target);
  
  // ML-based risk scoring
  const riskScore = calculateRiskScore({
    breaches,
    whois,
    shodan,
    socialMedia,
    exifData,
    nlpAnalysis,
  });

  const recommendations = generateRecommendations(riskScore, breaches, shodan);

  return {
    id: scanId,
    target,
    timestamp: new Date().toISOString(),
    status: 'completed',
    breaches,
    whois,
    shodan,
    socialMedia,
    exifData,
    nlpAnalysis,
    riskScore,
    recommendations,
  };
}

async function scanBreaches(email?: string): Promise<BreachData[]> {
  await delay(800);
  if (!email) return [];
  
  // Simulate finding 2-4 breaches
  const numBreaches = Math.floor(Math.random() * 3) + 2;
  return MOCK_BREACHES.slice(0, numBreaches);
}

async function scanWhois(domain: string): Promise<WhoisData> {
  await delay(600);
  
  const createdDate = new Date(Date.now() - Math.random() * 10 * 365 * 24 * 60 * 60 * 1000);
  const expiryDate = new Date(Date.now() + Math.random() * 2 * 365 * 24 * 60 * 60 * 1000);
  
  return {
    domain,
    registrar: ['Namecheap', 'GoDaddy', 'Google Domains', 'Cloudflare'][Math.floor(Math.random() * 4)],
    createdDate: createdDate.toISOString().split('T')[0],
    expiryDate: expiryDate.toISOString().split('T')[0],
    nameServers: ['ns1.example.com', 'ns2.example.com'],
    exposedEmail: Math.random() > 0.5,
  };
}

async function scanShodan(ip: string): Promise<ShodanData> {
  await delay(1000);
  
  const openPorts = [22, 80, 443, 8080, 3306].filter(() => Math.random() > 0.6);
  const services = openPorts.map(port => ({
    port,
    service: port === 22 ? 'SSH' : port === 80 ? 'HTTP' : port === 443 ? 'HTTPS' : port === 8080 ? 'HTTP-Proxy' : 'MySQL',
    version: `${Math.floor(Math.random() * 3 + 1)}.${Math.floor(Math.random() * 10)}`,
  }));
  
  const numVulns = Math.floor(Math.random() * 3);
  const vulnerabilities = VULNERABILITIES.slice(0, numVulns);
  
  return {
    ip,
    openPorts,
    services,
    vulnerabilities,
    country: ['United States', 'Germany', 'Singapore', 'United Kingdom'][Math.floor(Math.random() * 4)],
    organization: ['AWS', 'Google Cloud', 'DigitalOcean', 'Linode'][Math.floor(Math.random() * 4)],
  };
}

async function scanSocialMedia(username: string): Promise<SocialMediaPresence[]> {
  await delay(700);
  
  const numPlatforms = Math.floor(Math.random() * 5) + 3;
  const selectedPlatforms = shuffleArray([...PLATFORMS]).slice(0, numPlatforms);
  
  return selectedPlatforms.map(platform => ({
    platform,
    username,
    url: `https://${platform.toLowerCase()}.com/${username}`,
    isPublic: Math.random() > 0.3,
    lastActive: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
  }));
}

async function scanExifData(): Promise<ExifData[]> {
  await delay(500);
  
  const numImages = Math.floor(Math.random() * 4) + 1;
  return Array.from({ length: numImages }, (_, i) => ({
    fileName: `image_${i + 1}.jpg`,
    gpsLocation: Math.random() > 0.6 ? {
      lat: 37.7749 + (Math.random() - 0.5) * 10,
      lng: -122.4194 + (Math.random() - 0.5) * 10,
    } : undefined,
    deviceModel: Math.random() > 0.5 ? ['iPhone 13 Pro', 'Canon EOS R5', 'Samsung Galaxy S21'][Math.floor(Math.random() * 3)] : undefined,
    timestamp: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
    risk: Math.random() > 0.7 ? 'high' : Math.random() > 0.5 ? 'medium' : 'low',
  }));
}

async function performNLPAnalysis(target: ScanTarget): Promise<NLPAnalysis> {
  await delay(900);
  
  const sentiments: ('positive' | 'neutral' | 'negative' | 'threatening')[] = ['positive', 'neutral', 'negative', 'threatening'];
  const sentiment = sentiments[Math.floor(Math.random() * 4)];
  
  return {
    sentiment,
    threatLevel: sentiment === 'threatening' ? Math.random() * 40 + 60 : Math.random() * 60,
    keywords: ['exposed', 'leaked', 'vulnerable', 'security', 'breach'].filter(() => Math.random() > 0.6),
    isDoxxed: Math.random() > 0.85,
    mentions: Math.floor(Math.random() * 100),
  };
}

// ML-inspired risk scoring using weighted features
function calculateRiskScore(data: {
  breaches: BreachData[];
  whois?: WhoisData;
  shodan?: ShodanData;
  socialMedia: SocialMediaPresence[];
  exifData: ExifData[];
  nlpAnalysis?: NLPAnalysis;
}): RiskScore {
  const { breaches, whois, shodan, socialMedia, exifData, nlpAnalysis } = data;
  
  // Data Breaches Score (0-100)
  let dataBreachScore = 0;
  if (breaches.length > 0) {
    const severityWeights = { low: 10, medium: 25, high: 40, critical: 60 };
    const avgSeverity = breaches.reduce((sum, b) => sum + severityWeights[b.severity], 0) / breaches.length;
    const recencyFactor = breaches.some(b => new Date(b.date) > new Date('2020-01-01')) ? 1.3 : 1.0;
    dataBreachScore = Math.min(100, avgSeverity * recencyFactor * (1 + breaches.length * 0.1));
  }
  
  // Domain Security Score (0-100)
  let domainScore = 0;
  if (whois) {
    domainScore += whois.exposedEmail ? 30 : 0;
    const domainAge = (Date.now() - new Date(whois.createdDate).getTime()) / (365 * 24 * 60 * 60 * 1000);
    domainScore += domainAge < 1 ? 25 : 0; // New domains are suspicious
  }
  
  // Network Exposure Score (0-100)
  let networkScore = 0;
  if (shodan) {
    networkScore += shodan.openPorts.length * 10;
    networkScore += shodan.vulnerabilities.length * 25;
    networkScore = Math.min(100, networkScore);
  }
  
  // Social Footprint Score (0-100)
  const publicProfiles = socialMedia.filter(s => s.isPublic).length;
  const socialScore = Math.min(100, publicProfiles * 15);
  
  // Privacy Leaks Score (0-100)
  const highRiskExif = exifData.filter(e => e.risk === 'high').length;
  const medRiskExif = exifData.filter(e => e.risk === 'medium').length;
  const privacyScore = Math.min(100, highRiskExif * 30 + medRiskExif * 15);
  
  // Weighted overall score (Random Forest-inspired)
  const weights = {
    dataBreaches: 0.35,
    domainSecurity: 0.15,
    networkExposure: 0.25,
    socialFootprint: 0.10,
    privacyLeaks: 0.15,
  };
  
  let overall = 
    dataBreachScore * weights.dataBreaches +
    domainScore * weights.domainSecurity +
    networkScore * weights.networkExposure +
    socialScore * weights.socialFootprint +
    privacyScore * weights.privacyLeaks;
  
  // NLP threat adjustment
  if (nlpAnalysis && nlpAnalysis.isDoxxed) {
    overall = Math.min(100, overall * 1.4);
  }
  
  return {
    overall: Math.round(overall),
    categories: {
      dataBreaches: Math.round(dataBreachScore),
      domainSecurity: Math.round(domainScore),
      networkExposure: Math.round(networkScore),
      socialFootprint: Math.round(socialScore),
      privacyLeaks: Math.round(privacyScore),
    },
    mlConfidence: 0.82 + Math.random() * 0.15, // Simulated ML confidence
  };
}

function generateRecommendations(score: RiskScore, breaches: BreachData[], shodan?: ShodanData): string[] {
  const recs: string[] = [];
  
  if (score.categories.dataBreaches > 40) {
    recs.push('Change passwords for all accounts found in data breaches immediately');
    recs.push('Enable two-factor authentication (2FA) on all critical accounts');
  }
  
  if (breaches.length > 0) {
    recs.push('Monitor credit reports for suspicious activity');
    recs.push('Consider using a password manager to generate unique passwords');
  }
  
  if (score.categories.networkExposure > 50) {
    recs.push('Close unnecessary open ports on your network infrastructure');
    recs.push('Update all services to latest versions to patch known vulnerabilities');
  }
  
  if (shodan && shodan.vulnerabilities.length > 0) {
    recs.push('Apply security patches for identified CVEs immediately');
    recs.push('Implement a Web Application Firewall (WAF)');
  }
  
  if (score.categories.socialFootprint > 40) {
    recs.push('Review privacy settings on all social media accounts');
    recs.push('Limit personal information shared publicly online');
  }
  
  if (score.categories.privacyLeaks > 30) {
    recs.push('Remove GPS metadata from photos before sharing online');
    recs.push('Use tools like ExifTool to strip metadata from images');
  }
  
  if (score.overall > 70) {
    recs.push('Consider engaging a cybersecurity professional for a comprehensive audit');
  }
  
  return recs;
}

// Utility functions
function generateScanId(): string {
  return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function shuffleArray<T>(array: T[]): T[] {
  const newArray = [...array];
  for (let i = newArray.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
  }
  return newArray;
}
