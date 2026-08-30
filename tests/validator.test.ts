import { describe, it, expect } from "vitest";
import { checkCveSchema, scanPackageSchema } from "../src/utils/validator.js";

describe("validator", () => {
  it("validates CVE id", () => {
    expect(() => checkCveSchema.parse({ cveId: "CVE-2024-1234" })).not.toThrow();
    expect(() => checkCveSchema.parse({ cveId: "bad" })).toThrow();
  });

  it("validates scan_package", () => {
    const r = scanPackageSchema.parse({ packageName: "lodash", version: "4.17.20", ecosystem: "npm" });
    expect(r.packageName).toBe("lodash");
  });
});
