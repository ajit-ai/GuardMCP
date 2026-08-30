import { auditDependenciesSchema } from "../utils/validator.js";
import { queryOsvBatch } from "../services/osv-service.js";
import type { AuditResult } from "../types/index.js";

function parsePackageJson(raw: string): { deps: Record<string, string>; devDeps: Record<string, string> } {
  try {
    const pkg = JSON.parse(raw);
    return {
      deps: pkg.dependencies || {},
      devDeps: pkg.devDependencies || {},
    };
  } catch {
    throw new Error("Invalid packageJson JSON");
  }
}

function cleanVersion(v: string): string {
  // Strip ^ ~ >= etc. Take first semver found
  const m = v.match(/(\d+\.\d+\.\d+[^,\s]*)/);
  return m ? m[1] : v.replace(/^[\^~>=<\s]+/, "").trim();
}

export const auditDependenciesTool = {
  name: "audit_dependencies",
  description:
    "Audit all dependencies (package.json or explicit map) for vulnerabilities via OSV batch API. Returns summary by severity and per-package findings.",
  inputSchema: {
    type: "object" as const,
    properties: {
      packageJson: { type: "string", description: "Raw package.json string" },
      dependencies: { type: "object", description: "Map of packageName -> version", additionalProperties: { type: "string" } },
      devDependencies: { type: "object", description: "Map of dev packageName -> version", additionalProperties: { type: "string" } },
      ecosystem: { type: "string", default: "npm", description: "Ecosystem, default npm" },
    },
  },
  async handler(rawParams: unknown) {
    const parsed = auditDependenciesSchema.parse(rawParams);
    let deps: Record<string, string> = parsed.dependencies || {};
    let devDeps: Record<string, string> = parsed.devDependencies || {};

    if (parsed.packageJson) {
      const fromPkg = parsePackageJson(parsed.packageJson);
      deps = { ...fromPkg.deps, ...deps };
      devDeps = { ...fromPkg.devDeps, ...devDeps };
    }

    const all = { ...deps, ...devDeps };
    const entries = Object.entries(all);
    if (entries.length === 0) {
      return {
        content: [{ type: "text" as const, text: "No dependencies provided to audit." }],
        _meta: { cacheHit: false },
      };
    }

    const ecosystem = parsed.ecosystem || "npm";
    const queries = entries.map(([name, ver]) => ({
      name,
      version: cleanVersion(ver),
      ecosystem,
    }));

    const batch = await queryOsvBatch(queries);

    const result: AuditResult = {
      totalDependencies: entries.length,
      vulnerableDependencies: 0,
      vulnerabilities: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0 },
    };

    for (const q of queries) {
      const key = `${q.ecosystem}:${q.name}@${q.version}`;
      const vulns = batch.get(key) || [];
      if (vulns.length > 0) {
        result.vulnerableDependencies++;
        result.vulnerabilities.push({ packageName: q.name, version: q.version, vulns });
        for (const v of vulns) {
          // Severity is free-form from OSV; bucket by keyword
          const s = v.severity?.toUpperCase() || v.summary?.toUpperCase() || "";
          if (s.includes("CRITICAL") || v.cveIds.length > 0) {
            // heuristic - real scoring would use CVSS
          }
        }
      }
    }

    // Aggregate counts by checking cve severity hints
    for (const entry of result.vulnerabilities) {
      for (const v of entry.vulns) {
        const sev = v.severity.toLowerCase();
        if (sev.includes("critical") || v.summary.toLowerCase().includes("critical")) result.summary.critical++;
        else if (sev.includes("high") || v.summary.toLowerCase().includes("high")) result.summary.high++;
        else if (sev.includes("medium")) result.summary.medium++;
        else if (sev.includes("low")) result.summary.low++;
        else result.summary.medium++; // default bucket
      }
    }

    const header =
      result.vulnerableDependencies === 0
        ? `✅ All ${result.totalDependencies} dependencies clean`
        : `⚠️ ${result.vulnerableDependencies}/${result.totalDependencies} dependencies have vulnerabilities`;

    return {
      content: [{ type: "text" as const, text: `${header}\n\n${JSON.stringify(result, null, 2)}` }],
      _meta: { cacheHit: false },
    };
  },
};
