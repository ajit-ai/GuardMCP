import { config } from "../config.js";
import { packageCache, cacheKeys } from "../utils/cache.js";

interface NpmPackument {
  name: string;
  "dist-tags": { latest: string };
  versions: Record<string, unknown>;
  time?: Record<string, string>;
}

export async function fetchNpmInfo(packageName: string): Promise<{ data: NpmPackument; cacheHit: boolean }> {
  const key = cacheKeys.npm(packageName);
  const cached = packageCache.get(key) as NpmPackument | undefined;
  if (cached) return { data: cached, cacheHit: true };

  const url = `${config.npm.baseUrl}/${encodeURIComponent(packageName)}`;
  let res: Response;
  try {
    res = await fetch(url, { headers: { Accept: "application/json" } });
  } catch (err) {
    throw new Error(`npm registry network error for ${packageName}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!res.ok) {
    if (res.status === 404) throw new Error(`npm package not found: ${packageName}`);
    if (res.status === 429) throw new Error(`npm registry rate limited (429) for ${packageName}`);
    throw new Error(`npm registry error ${res.status} for ${packageName}: ${await res.text()}`);
  }

  const json = (await res.json()) as NpmPackument;
  packageCache.set(key, json);
  return { data: json, cacheHit: false };
}

export async function getLatestVersion(packageName: string): Promise<string | undefined> {
  try {
    const { data } = await fetchNpmInfo(packageName);
    return data["dist-tags"]?.latest;
  } catch {
    return undefined;
  }
}
