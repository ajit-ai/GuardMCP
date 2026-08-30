import { config } from "../config.js";
import { cveCache, cacheKeys } from "../utils/cache.js";

interface GhAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  cvss?: { score: number; vector_string: string };
  published_at: string;
  updated_at: string;
  references: string[];
  cwe_ids: string[];
}

export async function fetchGitHubAdvisory(
  cveId: string
): Promise<{ data: GhAdvisory | null; cacheHit: boolean }> {
  const key = cacheKeys.github(cveId);
  const cached = cveCache.get(key) as GhAdvisory | null | undefined;
  if (cached !== undefined) return { data: cached, cacheHit: true };

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (config.github.token) headers.Authorization = `Bearer ${config.github.token}`;

  // GitHub Advisory by CVE: search advisories
  const url = `${config.github.baseUrl}?cve_id=${encodeURIComponent(cveId)}`;
  const res = await fetch(url, { headers });

  if (!res.ok) {
    if (res.status === 404 || res.status === 403) {
      cveCache.set(key, null);
      return { data: null, cacheHit: false };
    }
    throw new Error(`GitHub Advisory error ${res.status}: ${await res.text()}`);
  }

  const json = (await res.json()) as GhAdvisory[];
  const advisory = Array.isArray(json) ? json[0] || null : (json as unknown as GhAdvisory);
  cveCache.set(key, advisory);
  return { data: advisory, cacheHit: false };
}

export async function searchGitHubAdvisories(
  keyword: string,
  ecosystem?: string
): Promise<GhAdvisory[]> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (config.github.token) headers.Authorization = `Bearer ${config.github.token}`;

  // GitHub search advisory API uses `q` param via search/advisories? Not stable, fallback to list filter
  let url = `${config.github.baseUrl}?per_page=20`;
  if (ecosystem) url += `&ecosystem=${encodeURIComponent(ecosystem)}`;

  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GitHub Advisory search error ${res.status}`);

  const data = (await res.json()) as GhAdvisory[];
  if (!keyword) return data;
  const kw = keyword.toLowerCase();
  return data.filter(
    (a) => a.summary.toLowerCase().includes(kw) || a.description.toLowerCase().includes(kw)
  );
}
