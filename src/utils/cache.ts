import { config } from "../config.js";
import type { CacheEntry } from "../types/index.js";

/**
 * In-memory TTL cache — Diagram 2's most important performance feature.
 * Without it, every request hits NVD and exhausts 5 req/30s limit.
 *
 * TTLs: 1 hour for CVEs, 24 hours for packages (configurable).
 */
export class TTLCache<T> {
  private store = new Map<string, CacheEntry<T>>();
  private ttlMs: number;
  private maxSize: number;

  constructor(ttlMs: number, maxSize = 1000) {
    this.ttlMs = ttlMs;
    this.maxSize = maxSize;
    // Periodic cleanup every 5 min
    setInterval(() => this.evictExpired(), 5 * 60 * 1000).unref();
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.data;
  }

  set(key: string, data: T, ttlMs?: number): void {
    if (this.store.size >= this.maxSize) {
      // Evict oldest
      const firstKey = this.store.keys().next().value;
      if (firstKey) this.store.delete(firstKey);
    }
    this.store.set(key, {
      key,
      data,
      expiresAt: Date.now() + (ttlMs ?? this.ttlMs),
    });
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  size(): number {
    return this.store.size;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [k, v] of this.store) {
      if (now > v.expiresAt) this.store.delete(k);
    }
  }
}

// Singleton caches per Diagram 2
export const cveCache = new TTLCache<unknown>(config.cache.cveTtlMs, config.cache.maxSize);
export const packageCache = new TTLCache<unknown>(config.cache.packageTtlMs, config.cache.maxSize);

// Cache key helpers
export const cacheKeys = {
  cve: (id: string) => `cve:${id.toUpperCase()}`,
  package: (ecosystem: string, name: string, version: string) =>
    `pkg:${ecosystem}:${name}@${version}`,
  npm: (name: string) => `npm:${name}`,
  github: (id: string) => `gh:${id}`,
  search: (keyword: string, ecosystem?: string) =>
    `search:${keyword}:${ecosystem || "all"}`,
};
