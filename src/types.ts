export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskLevel = 'Safe' | 'Low Risk' | 'Suspicious' | 'Malicious';

export interface Threat {
  id: string;
  severity: RiskSeverity;
  category: string;
  title: string;
  description: string;
}

export interface SecurityChecklistItem {
  passed: boolean;
  label: string;
}

export interface SecurityChecklist {
  https: SecurityChecklistItem;
  dns: SecurityChecklistItem;
  sslCert: SecurityChecklistItem;
  homographFree: SecurityChecklistItem;
  structure: SecurityChecklistItem;
  reputation: SecurityChecklistItem;
}

export interface DnsDetails {
  resolved: boolean;
  ipAddresses: string[];
  mailServers: string[];
  nameServers: string[];
}

export interface SslDetails {
  hasSSL: boolean;
  valid: boolean;
  authorized?: boolean;
  isExpired?: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string | null;
  validTo?: string | null;
  daysRemaining?: number | null;
  error?: string;
}

export interface ScanResult {
  url: string;
  normalizedUrl: string;
  defangedUrl: string;
  riskScore: number;
  riskLevel: RiskLevel;
  riskColor: string;
  hostname: string;
  rootDomain: string;
  subdomain: string | null;
  tld: string;
  protocol: string;
  pathname: string;
  entropy: {
    host: number;
    path: number;
  };
  checklist: SecurityChecklist;
  threatsFound: Threat[];
  dns: DnsDetails;
  ssl: SslDetails;
  targetedBrand: string | null;
  recommendations: string[];
  scannedAt: string;
  error?: string;
}

export interface BatchSummary {
  total: number;
  safeCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  avgScore: number;
}

export interface BatchResult {
  summary: BatchSummary;
  results: ScanResult[];
}

export interface DemoPreset {
  category: string;
  label: string;
  url: string;
  expectedScore: string;
}
