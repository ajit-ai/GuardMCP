import { config } from "../config.js";
import { packageCache, cacheKeys } from "../utils/cache.js";
import type { PackageVulnerability } from "../types/index.js";

interface OsvQueryResponse {
  vulns?: Array<{
    id: string;
    summary: string;
    details: string;
    aliases?: string[];
    published: string;
    modified: string;
    severity?: Array<{ type: string; score: string }>;
    affected?: Array<{
      package: { name: string; ecosystem: string };
      ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
      versions?: string[];
    }>;
    references?: Array<{ type: string; url: string }>;
  }>;
}

function mapOsvToVuln(v: NonNullable<OsvQueryResponse["vulns"]>[number]): PackageVulnerability {
  const aff = v.affected?.[0];
  const fixed = aff?.ranges?.[0]?.events.find((e) => e.fixed)?.fixed;
  // Extract severity string from CVSS or fallback
  const sev = v.severity?.[0]?.score || "UNKNOWN";
  return {
    id: v.id,
    packageName: aff?.package.name || "unknown",
    ecosystem: aff?.package.ecosystem || "unknown",
    affectedVersions: aff?.versions?.join(", ") || aff?.ranges?.map((r) => JSON.stringify(r.events)).join("; ") || "unknown",
    fixedVersion: fixed,
    severity: sev,
    summary: v.summary || v.details?.slice(0, 200) || v.id,
    details: v.details || v.summary || "",
    cveIds: v.aliases?.filter((a) => a.startsWith("CVE-")) || [],
    publishedAt: v.published,
    references: v.references?.map((r) => r.url) || [],
  };
}

export async function queryOsv(
  packageName: string,
  version: string,
  ecosystem: string
): Promise<{ data: PackageVulnerability[]; cacheHit: boolean }> {
  const key = cacheKeys.package(ecosystem, packageName, version);
  const cached = packageCache.get(key) as PackageVulnerability[] | undefined;
  if (cached) return { data: cached, cacheHit: true };

  const body = JSON.stringify({
    package: { name: packageName, ecosystem },
    version,
  });

  const res = await fetch(config.osv.baseUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  if (!res.ok) throw new Error(`OSV API error ${res.status}: ${await res.text()}`);

  const json = (await res.json()) as OsvQueryResponse;
  const vulns = (json.vulns || []).map(mapOsvToVuln);
  packageCache.set(key, vulns);
  return { data: vulns, cacheHit: false };
}

export async function queryOsvBatch(
  packages: Array<{ name: string; version: string; ecosystem: string }>
): Promise<Map<string, PackageVulnerability[]>> {
  // Batch leverages OSV querybatch endpoint
  const uncached: typeof packages = [];
  const results = new Map<string, PackageVulnerability[]>();

  for (const p of packages) {
    const key = cacheKeys.package(p.ecosystem, p.name, p.version);
    const cached = packageCache.get(key) as PackageVulnerability[] | undefined;
    if (cached) {
      results.set(`${p.ecosystem}:${p.name}@${p.version}`, cached);
    } else {
      uncached.push(p);
    }
  }

  if (uncached.length === 0) return results;

  const body = JSON.stringify({
    queries: uncached.map((p) => ({
      package: { name: p.name, ecosystem: p.ecosystem },
      version: p.version,
    })),
  });

  const res = await fetch(config.osv.batchUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  if (!res.ok) throw new Error(`OSV batch error ${res.status}: ${await res.text()}`);

  const json = (await res.json()) as { results: OsvQueryResponse[] };
  json.results.forEach((r, i) => {
    const pkg = uncached[i];
    const key = cacheKeys.package(pkg.ecosystem, pkg.name, pkg.version);
    const vulns = (r.vulns || []).map(mapOsvToVuln);
    packageCache.set(key, vulns);
    results.set(`${pkg.ecosystem}:${pkg.name}@${pkg.version}`, vulns);
  });

  return results;
}
