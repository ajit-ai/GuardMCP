import { z } from "zod";

export const CveIdSchema = z
  .string()
  .regex(/^CVE-\d{4}-\d{4,}$/i, "Invalid CVE ID format. Expected CVE-YYYY-NNNNN");

export const checkCveSchema = z.object({
  cveId: CveIdSchema,
});

export const scanPackageSchema = z.object({
  packageName: z.string().min(1, "packageName is required"),
  version: z.string().min(1, "version is required"),
  ecosystem: z
    .string()
    .default("npm")
    .describe("Ecosystem: npm, PyPI, Go, Maven, crates.io, etc."),
});

export const auditDependenciesSchema = z.object({
  // Accept either packageJson string or dependencies map
  packageJson: z.string().optional().describe("Raw package.json content"),
  dependencies: z.record(z.string()).optional(),
  devDependencies: z.record(z.string()).optional(),
  ecosystem: z.string().default("npm"),
});

export const searchVulnerabilitiesSchema = z.object({
  keyword: z.string().min(1, "keyword is required"),
  ecosystem: z.string().optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional(),
  limit: z.number().int().min(1).max(50).default(10),
});

export function validate<T>(schema: z.ZodSchema<T>, data: unknown): T {
  return schema.parse(data);
}
