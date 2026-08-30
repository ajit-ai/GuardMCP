import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { config } from "../config.js";
import type { AuditLogEntry } from "../types/index.js";

/**
 * Enterprise audit logger — Diagram 1 core engine module.
 * Every tool invocation is logged with timestamp, params, duration, cacheHit.
 * Enterprises need to know what agents queried and when.
 * Roadmap gap in current MCP servers that GitHub explicitly calls out.
 */
export class AuditLogger {
  private enabled: boolean;
  private path: string;

  constructor(enabled = config.audit.enabled, path = config.audit.path) {
    this.enabled = enabled;
    this.path = path;
  }

  async log(entry: AuditLogEntry): Promise<void> {
    if (!this.enabled) return;

    const line = JSON.stringify(entry) + "\n";

    // Also emit to stderr for MCP stdio visibility (stdout is reserved for protocol)
    if (config.logLevel === "debug") {
      console.error(`[audit] ${line.trim()}`);
    }

    try {
      await mkdir(dirname(this.path), { recursive: true });
      await appendFile(this.path, line, "utf-8");
    } catch (err) {
      // Never fail the request due to audit log failure
      console.error(`[audit] Failed to write log: ${err}`);
    }
  }

  createEntry(
    tool: string,
    params: Record<string, unknown>,
    durationMs: number,
    opts: { cacheHit: boolean; success: boolean; error?: string }
  ): AuditLogEntry {
    return {
      timestamp: new Date().toISOString(),
      tool,
      params: this.sanitizeParams(params),
      durationMs,
      cacheHit: opts.cacheHit,
      success: opts.success,
      error: opts.error,
    };
  }

  private sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
    // Redact sensitive fields
    const redacted = { ...params };
    for (const key of ["apiKey", "token", "password"]) {
      if (key in redacted) redacted[key] = "***";
    }
    return redacted;
  }
}

export const auditLogger = new AuditLogger();
