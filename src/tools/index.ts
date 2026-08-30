export { checkCveTool } from "./check-cve.js";
export { scanPackageTool } from "./scan-package.js";
export { auditDependenciesTool } from "./audit-dependencies.js";
export { searchVulnerabilitiesTool } from "./search-vulnerabilities.js";

import { checkCveTool } from "./check-cve.js";
import { scanPackageTool } from "./scan-package.js";
import { auditDependenciesTool } from "./audit-dependencies.js";
import { searchVulnerabilitiesTool } from "./search-vulnerabilities.js";

export const allTools = [
  checkCveTool,
  scanPackageTool,
  auditDependenciesTool,
  searchVulnerabilitiesTool,
] as const;

export type ToolName = (typeof allTools)[number]["name"];
