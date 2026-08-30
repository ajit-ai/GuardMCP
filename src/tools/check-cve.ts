import { checkCveSchema } from "../utils/validator.js";
import { fetchCveFromNvd } from "../services/nvd-service.js";
import { fetchGitHubAdvisory } from "../services/github-service.js";

export const checkCveTool = {
  name: "check_cve",
  description:
    "Lookup a CVE by ID via NVD and GitHub Advisory. Returns CVSS score, severity, description, references and CWE. Uses 1h cache.",
  inputSchema: {
    type: "object" as const,
    properties: {
      cveId: { type: "string", description: "CVE ID e.g. CVE-2024-1234" },
    },
    required: ["cveId"],
  },
  async handler(rawParams: unknown) {
    const { cveId } = checkCveSchema.parse(rawParams);

    // Request lifecycle: NVD primary, GitHub enrichment
    const nvd = await fetchCveFromNvd(cveId);
    const gh = await fetchGitHubAdvisory(cveId).catch(() => ({ data: null, cacheHit: false }));

    if (!nvd.data && !gh.data) {
      return {
        content: [{ type: "text" as const, text: `No data found for ${cveId}. CVE may not exist or not yet published.` }],
        _meta: { cacheHit: nvd.cacheHit },
      };
    }

    const payload: Record<string, unknown> = {};
    if (nvd.data) payload.nvd = nvd.data;
    if (gh.data) payload.github = gh.data;

    const cacheHit = nvd.cacheHit; // primary signal

    return {
      content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
      _meta: { cacheHit },
    };
  },
};
