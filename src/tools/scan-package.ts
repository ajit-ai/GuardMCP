import { scanPackageSchema } from "../utils/validator.js";
import { queryOsv } from "../services/osv-service.js";
import { getLatestVersion } from "../services/npm-service.js";
import type { PackageScanResult } from "../types/index.js";

export const scanPackageTool = {
  name: "scan_package",
  description:
    "Scan a single package version for known vulnerabilities via OSV.dev. Supports npm, PyPI, Go, Maven, crates.io. Uses 24h package cache.",
  inputSchema: {
    type: "object" as const,
    properties: {
      packageName: { type: "string", description: "Package name e.g. lodash, requests" },
      version: { type: "string", description: "Exact version e.g. 4.17.20" },
      ecosystem: { type: "string", description: "Ecosystem id (npm, PyPI, Go, Maven, crates.io)", default: "npm" },
    },
    required: ["packageName", "version"],
  },
  async handler(rawParams: unknown) {
    const { packageName, version, ecosystem } = scanPackageSchema.parse(rawParams);

    // Normalize ecosystem for OSV (PyPI capitalisation)
    const osvEcosystem = ecosystem === "npm" ? "npm" : ecosystem;

    const { data: vulns, cacheHit } = await queryOsv(packageName, version, osvEcosystem);

    let latestVersion: string | undefined;
    if (osvEcosystem === "npm") {
      latestVersion = await getLatestVersion(packageName);
    }

    const result: PackageScanResult = {
      packageName,
      version,
      ecosystem: osvEcosystem,
      vulnerabilities: vulns,
      isVulnerable: vulns.length > 0,
      latestVersion,
    };

    const summary = vulns.length === 0
      ? `✅ No known vulnerabilities for ${packageName}@${version} (${osvEcosystem})`
      : `⚠️ Found ${vulns.length} vulnerabilit${vulns.length === 1 ? "y" : "ies"} for ${packageName}@${version}`;

    return {
      content: [{ type: "text" as const, text: `${summary}\n\n${JSON.stringify(result, null, 2)}` }],
      _meta: { cacheHit },
    };
  },
};
