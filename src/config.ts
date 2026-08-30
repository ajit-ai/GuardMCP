export const config = {
  nvd: {
    apiKey: process.env.NVD_API_KEY || "",
    baseUrl: "https://services.nvd.nist.gov/rest/json/cves/2.0",
    // NVD rate limits: 5/30s without key, 50/30s with key
    rateLimit: process.env.NVD_API_KEY ? 50 : 5,
    rateWindowMs: 30_000,
  },
  osv: {
    baseUrl: "https://api.osv.dev/v1/query",
    batchUrl: "https://api.osv.dev/v1/querybatch",
  },
  npm: {
    baseUrl: "https://registry.npmjs.org",
  },
  github: {
    token: process.env.GITHUB_TOKEN || "",
    baseUrl: "https://api.github.com/advisories",
  },
  cache: {
    // Diagram 2: cache is critical for NVD rate limits
    cveTtlMs: parseInt(process.env.CVE_CACHE_TTL || "3600000", 10), // 1 hour
    packageTtlMs: parseInt(process.env.PACKAGE_CACHE_TTL || "86400000", 10), // 24 hours
    maxSize: 1000,
  },
  audit: {
    enabled: process.env.AUDIT_LOG_ENABLED !== "false",
    path: process.env.AUDIT_LOG_PATH || "./logs/audit.log",
  },
  redisUrl: process.env.REDIS_URL || "",
  logLevel: process.env.LOG_LEVEL || "info",
};
