import { describe, it, expect } from "vitest";
import { TTLCache, cacheKeys } from "../src/utils/cache.js";

describe("TTLCache", () => {
  it("stores and retrieves", () => {
    const c = new TTLCache<string>(1000);
    c.set("k", "v");
    expect(c.get("k")).toBe("v");
  });

  it("expires after TTL", async () => {
    const c = new TTLCache<string>(10);
    c.set("k", "v");
    await new Promise((r) => setTimeout(r, 20));
    expect(c.get("k")).toBeUndefined();
  });

  it("cache keys helpers", () => {
    expect(cacheKeys.cve("cve-2024-1234")).toBe("cve:CVE-2024-1234");
    expect(cacheKeys.package("npm", "lodash", "4.17.21")).toBe("pkg:npm:lodash@4.17.21");
  });
});
