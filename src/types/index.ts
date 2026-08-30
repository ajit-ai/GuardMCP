export interface CveResult {
  id: string;
  summary: string;
  description: string;
  cvssScore?: number;
  cvssVector?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  publishedDate: string;
  lastModified: string;
  references: string[];
  affectedProducts: string[];
  cweIds: string[];
  source: "NVD" | "OSV" | "GitHub";
}

export interface PackageVulnerability {
  id: string;
  packageName: string;
  ecosystem: string;
  affectedVersions: string;
  fixedVersion?: string;
  severity: string;
  summary: string;
  details: string;
  cveIds: string[];
  publishedAt: string;
  references: string[];
}

export interface PackageScanResult {
  packageName: string;
  version: string;
  ecosystem: string;
  vulnerabilities: PackageVulnerability[];
  isVulnerable: boolean;
  latestVersion?: string;
  advisoryUrl?: string;
}

export interface AuditResult {
  totalDependencies: number;
  vulnerableDependencies: number;
  vulnerabilities: Array<{
    packageName: string;
    version: string;
    vulns: PackageVulnerability[];
  }>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface CacheEntry<T> {
  data: T;
  expiresAt: number;
  key: string;
}

export interface AuditLogEntry {
  timestamp: string;
  tool: string;
  params: Record<string, unknown>;
  durationMs: number;
  cacheHit: boolean;
  success: boolean;
  error?: string;
  clientInfo?: string;
}
