import { config } from "../config.js";
import { cveCache, cacheKeys } from "../utils/cache.js";
import { RateLimiter } from "../utils/rate-limiter.js";
import type { CveResult } from "../types/index.js";

const limiter = new RateLimiter(config.nvd.rateLimit, config.nvd.rateWindowMs);

interface NvdResponse {
  resultsPerPage: number;
  totalResults: number;
  vulnerabilities?: Array<{
    cve: {
      id: string;
      descriptions: Array<{ lang: string; value: string }>;
      metrics?: {
        cvssMetricV31?: Array<{ cvssData: { baseScore: number; vectorString: string } }>;
        cvssMetricV30?: Array<{ cvssData: { baseScore: number; vectorString: string } }>;
        cvssMetricV2?: Array<{ cvssData: { baseScore: number; vectorString: string } }>;
      };
      published: string;
      lastModified: string;
      references: Array<{ url: string }>;
      weaknesses?: Array<{ description: Array<{ value: string }> }>;
      configurations?: unknown;
    };
  }>;
}

function severityFromScore(score?: number): CveResult["severity"] {
  if (score === undefined) return "UNKNOWN";
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}

type NvdVuln = NonNullable<NonNullable<NvdResponse["vulnerabilities"]>[number]>;

function parseNvdToCve(raw: NvdVuln): CveResult {
  const cve = raw.cve;
  const desc = cve.descriptions.find((d: { lang: string }) => d.lang === "en")?.value || cve.descriptions[0]?.value || "";
  const cvss =
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV2?.[0]?.cvssData;

  return {
    id: cve.id,
    summary: desc.slice(0, 200),
    description: desc,
    cvssScore: cvss?.baseScore,
    cvssVector: cvss?.vectorString,
    severity: severityFromScore(cvss?.baseScore),
    publishedDate: cve.published,
    lastModified: cve.lastModified,
    references: cve.references.map((r: { url: string }) => r.url),
    affectedProducts: [],
    cweIds: cve.weaknesses?.flatMap((w: { description: Array<{ value: string }> }) => w.description.map((d) => d.value)) || [],
    source: "NVD",
  };
}

export async function fetchCveFromNvd(cveId: string): Promise<{ data: CveResult | null; cacheHit: boolean }> {
  const key = cacheKeys.cve(cveId);
  const cached = cveCache.get(key) as CveResult | null | undefined;
  if (cached !== undefined) {
    return { data: cached, cacheHit: true };
  }

  await limiter.acquire();

  const url = `${config.nvd.baseUrl}?cveId=${encodeURIComponent(cveId)}`;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (config.nvd.apiKey) headers["apiKey"] = config.nvd.apiKey;

  // Retry on 429 with exponential backoff
  const maxRetries = 3;
  let attempt = 0;
  while (true) {
    try {
      const res = await fetch(url, { headers });
      if (res.status === 429) {
        if (attempt >= maxRetries) throw new Error(`NVD rate limit exceeded after ${maxRetries} retries (429)`);
        const retryAfter = parseInt(res.headers.get("Retry-After") || "30", 10);
        const backoff = Math.min(retryAfter * 1000 || 30000, 30000) + attempt * 5000;
        console.error(`[nvd] 429 rate limited, retrying in ${backoff}ms (attempt ${attempt + 1}/${maxRetries})`);
        await new Promise((r) => setTimeout(r, backoff));
        attempt++;
        await limiter.acquire();
        continue;
      }
      if (!res.ok) {
        if (res.status === 404) {
          cveCache.set(key, null);
          return { data: null, cacheHit: false };
        }
        throw new Error(`NVD API error ${res.status}: ${await res.text()}`);
      }
      const json = (await res.json()) as NvdResponse;
      const vuln = json.vulnerabilities?.[0];
      const result = vuln ? parseNvdToCve(vuln) : null;
      cveCache.set(key, result);
      return { data: result, cacheHit: false };
    } catch (err) {
      // Network errors: retry once
      if (err instanceof TypeError && attempt < 1) {
        attempt++;
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }
      throw err;
    }
  }
}

export async function searchNvdByKeyword(
  keyword: string,
  limit = 10
): Promise<{ data: CveResult[]; cacheHit: boolean }> {
  const key = cacheKeys.search(keyword);
  const cached = cveCache.get(key) as CveResult[] | undefined;
  if (cached) return { data: cached, cacheHit: true };

  await limiter.acquire();

  const url = `${config.nvd.baseUrl}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (config.nvd.apiKey) headers["apiKey"] = config.nvd.apiKey;

  const maxRetries = 3;
  let attempt = 0;
  while (true) {
    try {
      const res = await fetch(url, { headers });
      if (res.status === 429) {
        if (attempt >= maxRetries) throw new Error(`NVD search rate limit exceeded after ${maxRetries} retries`);
        const retryAfter = parseInt(res.headers.get("Retry-After") || "30", 10);
        const backoff = Math.min(retryAfter * 1000 || 30000, 30000) + attempt * 5000;
        console.error(`[nvd] 429 on search, retrying in ${backoff}ms`);
        await new Promise((r) => setTimeout(r, backoff));
        attempt++;
        await limiter.acquire();
        continue;
      }
      if (!res.ok) throw new Error(`NVD search error ${res.status}: ${await res.text()}`);
      const json = (await res.json()) as NvdResponse;
      const results = (json.vulnerabilities || []).map(parseNvdToCve);
      cveCache.set(key, results);
      return { data: results, cacheHit: false };
    } catch (err) {
      if (err instanceof TypeError && attempt < 1) {
        attempt++;
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }
      throw err;
    }
  }
}
