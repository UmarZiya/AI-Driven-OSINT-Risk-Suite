// Type definitions for the OSINT Risk Suite

export interface ScanTarget {
  email?: string;
  domain?: string;
  username?: string;
  ipAddress?: string;
}

export interface BreachData {
  name: string;
  date: string;
  dataClasses: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  affectedRecords: number;
}

export interface WhoisData {
  domain: string;
  registrar: string;
  createdDate: string;
  expiryDate: string;
  nameServers: string[];
  exposedEmail: boolean;
}

export interface ShodanData {
  ip: string;
  openPorts: number[];
  services: { port: number; service: string; version: string }[];
  vulnerabilities: string[];
  country: string;
  organization: string;
}

export interface SocialMediaPresence {
  platform: string;
  username: string;
  url: string;
  isPublic: boolean;
  lastActive: string;
}

export interface ExifData {
  fileName: string;
  gpsLocation?: { lat: number; lng: number };
  deviceModel?: string;
  timestamp?: string;
  risk: 'low' | 'medium' | 'high';
}

export interface NLPAnalysis {
  sentiment: 'positive' | 'neutral' | 'negative' | 'threatening';
  threatLevel: number; // 0-100
  keywords: string[];
  isDoxxed: boolean;
  mentions: number;
}

export interface RiskScore {
  overall: number; // 0-100
  categories: {
    dataBreaches: number;
    domainSecurity: number;
    networkExposure: number;
    socialFootprint: number;
    privacyLeaks: number;
  };
  mlConfidence: number;
}

export interface ScanResult {
  id: string;
  target: ScanTarget;
  timestamp: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  breaches: BreachData[];
  whois?: WhoisData;
  shodan?: ShodanData;
  socialMedia: SocialMediaPresence[];
  exifData: ExifData[];
  nlpAnalysis?: NLPAnalysis;
  riskScore: RiskScore;
  recommendations: string[];
}

export interface ScanHistoryItem {
  id: string;
  target: string;
  timestamp: string;
  riskScore: number;
  status: 'completed' | 'failed';
}
