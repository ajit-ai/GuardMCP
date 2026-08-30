import { searchVulnerabilitiesSchema } from "../utils/validator.js";
import { searchNvdByKeyword } from "../services/nvd-service.js";
import { searchGitHubAdvisories } from "../services/github-service.js";

export const searchVulnerabilitiesTool = {
  name: "search_vulnerabilities",
  description:
    "Search vulnerabilities by keyword across NVD and GitHub Advisory. Filter by ecosystem and severity. Useful for threat hunting and dependency research.",
  inputSchema: {
    type: "object" as const,
    properties: {
      keyword: { type: "string", description: "Search term e.g. log4j, openssl" },
      ecosystem: { type: "string", description: "Filter by ecosystem e.g. npm, Maven, PyPI" },
      severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
      limit: { type: "number", description: "Max results (1-50, default 10)" },
    },
    required: ["keyword"],
  },
  async handler(rawParams: unknown) {
    const { keyword, ecosystem, severity, limit } = searchVulnerabilitiesSchema.parse(rawParams);

    // Parallel fan-out to NVD + GitHub per Architecture diagram external data sources
    const [nvd, gh] = await Promise.all([
      searchNvdByKeyword(keyword, limit).catch((e) => ({ data: [] as unknown[], cacheHit: false, error: String(e) })),
      searchGitHubAdvisories(keyword, ecosystem).catch(() => [] as unknown[]),
    ]);

    let nvdResults = (nvd as { data: { severity: string }[] }).data || [];
    let ghResults: unknown[] = Array.isArray(gh) ? gh : [];

    // Severity filter
    if (severity) {
      nvdResults = nvdResults.filter((r) => r.severity === severity) as typeof nvdResults;
      ghResults = (ghResults as Array<{ severity: string }>).filter(
        (r) => r.severity?.toUpperCase() === severity
      );
    }

    if (limit) {
      nvdResults = nvdResults.slice(0, limit);
      ghResults = ghResults.slice(0, limit);
    }

    const payload = {
      keyword,
      ecosystem: ecosystem || "all",
      nvd: { count: nvdResults.length, results: nvdResults },
      github: { count: ghResults.length, results: ghResults },
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
      _meta: { cacheHit: (nvd as { cacheHit?: boolean }).cacheHit || false },
    };
  },
};
