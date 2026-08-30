# GuardMCP — Security-First MCP Server for AI Agents

> **Design Architect Specification v1.0.0** | Vulnerability intelligence for Claude Code, VS Code, Cursor via NVD, OSV.dev, npm Registry & GitHub Advisory

GuardMCP is an enterprise-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that gives AI agents real-time security context — CVE lookup, package scanning, dependency auditing and threat hunting — without leaking secrets or burning NVD rate limits.

---

## Table of Contents
- [1. Executive Summary](#1-executive-summary)
- [2. System Architecture — Three Layers](#2-system-architecture--three-layers-diagram-1)
- [3. Request Lifecycle — Cache-First Flow](#3-request-lifecycle--cache-first-flow-diagram-2)
- [4. Folder Structure & Build Map](#4-folder-structure--build-map-diagram-3)
- [5. Component Specification](#5-component-specification)
- [6. Tool Contract (MCP Tools)](#6-tool-contract-mcp-tools)
- [7. External Data Sources](#7-external-data-sources)
- [8. Core Engine](#8-core-engine)
- [9. Configuration & Environment](#9-configuration--environment)
- [10. Quick Start](#10-quick-start)
- [11. MCP Client Integration](#11-mcp-client-integration)
- [12. Security & Compliance](#12-security--compliance)
- [13. Testing & Verification](#13-testing--verification)
- [14. Roadmap](#14-roadmap)

---

## 1. Executive Summary

| Attribute | Value |
|-----------|-------|
| **Problem** | AI coding agents blindly `npm install` vulnerable packages; no MCP server offers unified CVE + package + advisory intelligence with audit trails |
| **Solution** | Single stdio MCP server federating 4 sources, with TTL caching, rate-limiting and JSONL audit logging |
| **Users** | Individual devs, platform teams, enterprise security — same binary, env-gated features |
| **Protocol** | MCP `stdio` (stdout = JSON-RPC, stderr = logs) via `@modelcontextprotocol/sdk` |
| **Language/Runtime** | TypeScript 5.7 / Node ≥18 (native `fetch`) |

---

## 2. System Architecture — Three Layers (Diagram 1)

```
 ┌─────────────────────────────────────────────────────────────────┐
 │ LAYER 1 — AI Agent Clients (Top)                                │
 │  Claude Code  ·  VS Code (Copilot)  ·  Cursor                   │
 │  Role: Tool consumer. Discovers & calls tools via MCP JSON-RPC. │
 │  Transport: stdio (primary) / HTTP+SSE (future)                 │
 └──────────────────────────┬──────────────────────────────────────┘
                            │ MCP stdio (JSON-RPC 2.0)
                            │  list_tools / call_tool
 ┌──────────────────────────▼──────────────────────────────────────┐
 │ LAYER 2 — GuardMCP Server (Middle) — Core of this spec          │
 │                                                                 │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ MCP Server (`src/server.ts:20`, `src/index.ts:1`)       │   │
 │  │  createServer() → ListTools + CallTool handlers         │   │
 │  │  Request lifecycle orchestration + error boundary       │   │
 │  └──────────────────────┬──────────────────────────────────┘   │
 │                         │                                      │
 │  ┌──────────────────────▼──────────────────────────────────┐   │
 │  │ Tool Dispatcher (`src/tools/index.ts:9`) — 4 tools      │   │
 │  │  1. check_cve              → NVD + GitHub               │   │
 │  │  2. scan_package           → OSV + npm                  │   │
 │  │  3. audit_dependencies     → OSV Batch                  │   │
 │  │  4. search_vulnerabilities → NVD + GitHub (parallel)    │   │
 │  └──────────────────────┬──────────────────────────────────┘   │
 │                         │                                      │
 │  ┌──────────────────────▼──────────────────────────────────┐   │
 │  │ Core Engine                                              │   │
 │  │  cache.ts:10        TTLCache (1h CVE / 24h pkg)         │   │
 │  │  validator.ts:1     zod schemas (input guard)           │   │
 │  │  audit-log.ts:10    JSONL audit trail (enterprise)      │   │
 │  │  rate-limiter.ts:1  Token-bucket 5/30s (NVD)            │   │
 │  │  config.ts:1        Env-centralized config               │   │
 │  └─────────────────────────────────────────────────────────┘   │
 └──────────────────────────┬──────────────────────────────────────┘
                            │ HTTPS + API keys (optional)
 ┌──────────────────────────▼──────────────────────────────────────┐
 │ LAYER 3 — External Data Sources (Bottom)                        │
 │  NVD API  services.nvd.nist.gov/rest/json/cves/2.0   (CVE)      │
 │  OSV.dev  api.osv.dev/v1/query + querybatch           (packages)│
 │  npm Registry registry.npmjs.org                       (metadata)│
 │  GitHub Advisory api.github.com/advisories             (GHSA)   │
 └─────────────────────────────────────────────────────────────────┘
```

**Design decisions:**
- **stdio over HTTP** — zero network config for local agents; stdout reserved for protocol, all logs to stderr (`src/server.ts:86`).
- **Federation, not aggregation-only** — NVD is source of truth for CVEs, OSV for package ranges, GitHub for GHSA enrichment; each tool picks optimal source(s).
- **Stateless server + stateful cache** — cache lives in-process (Map + TTL); safe to restart, no external Redis required for v1.

---

## 3. Request Lifecycle — Cache-First Flow (Diagram 2)

Every `call_tool` follows the same pipeline. Cache is the *most important performance feature*.

```
 Agent call_tool(name, args)
        │
        ▼
 ┌─────────────┐
 │ 1. Validate │  zod parse — src/utils/validator.ts:10
 │  (fail fast)│  → 400-style error, audit.log(success=false)
 └──────┬──────┘
        ▼
 ┌─────────────┐
 │ 2. Cache    │  TTLCache.get() — src/utils/cache.ts:15
 │   Check     │  key = cve:CVE-XXXX / pkg:eco:name@ver / npm:name / gh:id
 └──────┬──────┘
        │ HIT ──────────────┐
        │                   ▼
        │              ┌──────────┐  return instantly, skip network
        │              │  Format  │  _meta.cacheHit=true
        │              └────┬─────┘
        │                   │
        │ MISS              │
        ▼                   │
 ┌─────────────┐            │
 │ 3. Dispatcher│  tool.handler() — src/tools/*.ts │
 │  RateLimit  │  NVD: RateLimiter.acquire() 5/30s  │
 │  (if NVD)   │  src/utils/rate-limiter.ts:8       │
 └──────┬──────┘            │
        ▼                   │
 ┌─────────────┐            │
 │ 4. External │  fetch() → NVD/OSV/npm/GitHub │
 │    API      │  src/services/*.ts             │
 └──────┬──────┘            │
        ▼                   │
 ┌─────────────┐            │
 │ 5. Format   │  JSON stringify + summary line │
 │   Result    │  {content:[{type:"text",text}]} │
 └──────┬──────┘            │
        ▼                   ▼
 ┌─────────────────────────────────┐
 │ 6. Audit Log │ JSONL append — src/utils/audit-log.ts:18
 │  {timestamp,tool,params,durationMs,cacheHit,success,error}
 │  path: logs/audit.log (AUDIT_LOG_PATH)
 └──────────────┬──────────────────┘
                ▼
           Return to Agent
```

**Cache TTLs — tuned to source volatility vs rate limits:**

| Cache | Key Pattern | Default TTL | Env | Rationale |
|-------|-------------|-------------|-----|-----------|
| CVE | `cve:CVE-2024-1234` | 3,600,000 ms (1 h) | `CVE_CACHE_TTL` | CVE descriptions/CVSS rarely change hourly |
| Package | `pkg:npm:lodash@4.17.21` | 86,400,000 ms (24 h) | `PACKAGE_CACHE_TTL` | OSV data stable per version |
| npm meta | `npm:lodash` | 86,400,000 ms | — | dist-tags change infrequently |
| Search | `search:log4j` | 3,600,000 ms | — | Keyword search is expensive on NVD |

NVD limits: **5 req/30s without key, 50 req/30s with `NVD_API_KEY`** — cache + limiter prevents 429s (`src/config.ts:6`, `src/utils/rate-limiter.ts:12`).

---

## 4. Folder Structure & Build Map (Diagram 3)

```
GuardMCP/
├── src/
│   ├── index.ts              # Entry — shebang + startServer() (stdio)
│   ├── server.ts             # createServer(), ListTools/CallTool, lifecycle, audit
│   ├── config.ts             # Centralized env config (NVD/OSV/npm/GitHub/cache/audit)
│   ├── types/index.ts        # CveResult, PackageVulnerability, AuditResult, CacheEntry
│   ├── tools/                # 4 MCP tools (dispatcher layer)
│   │   ├── index.ts          # allTools registry
│   │   ├── check-cve.ts      # CVE lookup (NVD primary + GitHub enrich)
│   │   ├── scan-package.ts   # Single package scan (OSV + npm latest)
│   │   ├── audit-dependencies.ts # Batch audit (OSV querybatch, semver clean)
│   │   └── search-vulnerabilities.ts # Keyword search (NVD + GitHub parallel)
│   ├── services/             # External data adapters (HTTPS layer)
│   │   ├── nvd-service.ts    # fetchCveFromNvd, searchNvdByKeyword, parseNvdToCve
│   │   ├── osv-service.ts    # queryOsv, queryOsvBatch (querybatch endpoint)
│   │   ├── npm-service.ts    # fetchNpmInfo, getLatestVersion
│   │   └── github-service.ts # fetchGitHubAdvisory, searchGitHubAdvisories
│   └── utils/                # Core engine
│       ├── cache.ts          # TTLCache<T> + cveCache/packageCache singletons + cacheKeys
│       ├── validator.ts      # Zod schemas: CveIdSchema, checkCveSchema, etc.
│       ├── audit-log.ts      # AuditLogger (JSONL, sanitized, mkdir -p, never throws)
│       └── rate-limiter.ts   # Token-bucket RateLimiter (refill window, queue)
├── tests/
│   ├── cache.test.ts         # TTL + expiry + key helpers
│   └── validator.test.ts     # CVE id + scan_package validation
├── dist/                     # tsc output (build artifact, not committed conceptually)
├── package.json              # @modelcontextprotocol/sdk, zod, tsx, vitest
├── tsconfig.json             # ES2022, NodeNext, strict, outDir dist
├── .env.example              # NVD_API_KEY, GITHUB_TOKEN, TTL overrides
├── .gitignore                # node_modules, dist, logs, .env
└── README.md                 # This file — architect spec
```

**Build order** (paste into Claude Code: `start with step 1`):
1. `package.json` + `tsconfig.json` + `.env.example` + `src/config.ts`
2. `src/types/index.ts` + `src/utils/cache.ts` + `rate-limiter.ts` + `audit-log.ts` + `validator.ts`
3. `src/services/nvd-service.ts` + `osv-service.ts` + `npm-service.ts` + `github-service.ts`
4. `src/tools/*.ts` + `src/tools/index.ts`
5. `src/server.ts` + `src/index.ts`
6. `tests/*` + `README.md` + `npm run build` + `npm test`

---

## 5. Component Specification

### 5.1 MCP Server (`src/server.ts:20`)
- `createServer(): Server` — constructs `Server({name:"GuardMCP", version:"1.0.0"}, {capabilities:{tools:{}}})`.
- `ListTools` handler returns `allTools.map(t => ({name, description, inputSchema}))`.
- `CallTool` handler implements lifecycle: find tool → `await tool.handler(args)` → extract `_meta.cacheHit` → `auditLogger.log(createEntry(...))` → strip `_meta` → return. Errors are caught, logged (`success:false`) and returned as `{isError:true}` never thrown to transport.
- `startServer()` — `StdioServerTransport` + `server.connect()`, logs to `stderr`.

### 5.2 Types (`src/types/index.ts:1`)
`CveResult`, `PackageVulnerability`, `PackageScanResult`, `AuditResult`, `CacheEntry<T>`, `AuditLogEntry`. All inter-module contracts flow through these.

---

## 6. Tool Contract (MCP Tools)

| # | Name | Input Schema | Handler | Sources | Cache |
|---|------|--------------|---------|---------|-------|
| 1 | `check_cve` | `cveId: string (CVE-YYYY-NNNNN regex)` — `src/utils/validator.ts:6` | `src/tools/check-cve.ts:7` — NVD primary, GitHub enrich, 404 → null cached | NVD + GitHub | `cve:<ID>` 1h |
| 2 | `scan_package` | `packageName, version, ecosystem="npm"` — `src/utils/validator.ts:10` | `src/tools/scan-package.ts:7` — OSV query + npm `latest` enrichment | OSV + npm | `pkg:<eco>:<name>@<ver>` 24h |
| 3 | `audit_dependencies` | `packageJson? (raw JSON string), dependencies?, devDependencies?, ecosystem="npm"` — `src/utils/validator.ts:16` | `src/tools/audit-dependencies.ts:9` — parses `package.json`, cleans `^~>= ` semver, `queryOsvBatch` | OSV batch | per-package 24h |
| 4 | `search_vulnerabilities` | `keyword, ecosystem?, severity? (CRITICAL|HIGH|MEDIUM|LOW), limit=10 (1-50)` — `src/utils/validator.ts:22` | `src/tools/search-vulnerabilities.ts:6` — parallel `searchNvdByKeyword` + `searchGitHubAdvisories`, severity filter | NVD + GitHub | `search:<kw>:<eco>` 1h |

**Output shape** (MCP `CallToolResult`): `{ content: [{type:"text", text: "<summary>\n\n<JSON>"}] }`. Summary line is human-readable (`✅`/`⚠️`), JSON is machine-parseable.

---

## 7. External Data Sources

| Source | Base URL | Auth | Adapter | Notes |
|--------|----------|------|---------|-------|
| **NVD** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | `apiKey` header if `NVD_API_KEY` | `src/services/nvd-service.ts:62` | `?cveId=` + `?keywordSearch=`; CVSS v3.1→3.0→2 fallback; `severityFromScore` buckets |
| **OSV.dev** | `https://api.osv.dev/v1/query` + `querybatch` | none | `src/services/osv-service.ts:25` | Batch avoids N× HTTP; `mapOsvToVuln` extracts fixedVersion from `ranges.events` |
| **npm** | `https://registry.npmjs.org` | none | `src/services/npm-service.ts:7` | `dist-tags.latest` for “is update available” hint |
| **GitHub** | `https://api.github.com/advisories` | `Bearer GITHUB_TOKEN` (optional) | `src/services/github-service.ts:11` | `?cve_id=`, `X-GitHub-Api-Version: 2022-11-28` |

All services check `*Cache.get()` first (cache-hit path), then `limiter.acquire()` (NVD only), then `fetch()`.

---

## 8. Core Engine

### 8.1 Cache (`src/utils/cache.ts:10`)
- `TTLCache<T>` — `Map<string, CacheEntry>` with `evictExpired()` every 5 min (`unref()`). `maxSize=1000`, LRU-ish (evicts `keys().next()` when full).
- Singletons: `cveCache` (1h), `packageCache` (24h). `cacheKeys` helpers ensure consistent key format.

### 8.2 Validator (`src/utils/validator.ts:1`)
Zod schemas exported for both MCP `inputSchema` (JSON Schema) and runtime `parse()`. CVE regex: `/^CVE-\d{4}-\d{4,}$/i`.

### 8.3 Audit Logger (`src/utils/audit-log.ts:10`)
- Enterprise gap filler — GitHub MCP roadmap calls out missing audit trails.
- `log(entry)` → `mkdir -p dirname(path)` → `appendFile(JSON.stringify(entry)+"\n")`. Swallows write errors (never fails request). Sanitizes `apiKey|token|password → "***"`.
- Entry: `{timestamp ISO, tool, params (sanitized), durationMs, cacheHit, success, error?}`.
- Enabled by `AUDIT_LOG_ENABLED !== "false"`, path `AUDIT_LOG_PATH=./logs/audit.log`. In `debug` mode also echoes to `stderr`.

### 8.4 Rate Limiter (`src/utils/rate-limiter.ts:8`)
Token-bucket: `tokens = maxTokens`, `acquire()` decrements or queues Promise; `setTimeout(windowMs)` refills to `maxTokens` and drains queue. `unref()` so process can exit.

### 8.5 Config (`src/config.ts:1`)
Single source of truth. All env vars read once at import with defaults. No `dotenv` — caller (MCP client `env`) injects.

---

## 9. Configuration & Environment

Copy `.env.example` → `.env` (or set via MCP client `env`):

```ini
# NVD — https://nvd.nist.gov/developers/request-an-api-key
# 5/30s without, 50/30s with
NVD_API_KEY=

# GitHub Advisory — higher rate limit with PAT
GITHUB_TOKEN=

# TTL overrides (ms)
#CVE_CACHE_TTL=3600000
#PACKAGE_CACHE_TTL=86400000

# Audit log
#AUDIT_LOG_PATH=./logs/audit.log
#AUDIT_LOG_ENABLED=true

#LOG_LEVEL=info  # debug → audit echo to stderr
```

---

## 10. Quick Start

```bash
npm install
npm run build      # tsc → dist/
npm start          # node dist/index.js (stdio)
npm test           # vitest run
npm run dev        # tsx src/index.ts (watch)
```

---

## 11. MCP Client Integration

**Claude Code** (`.mcp.json` or `claude.json`):
```json
{
  "mcpServers": {
    "guardmcp": {
      "command": "node",
      "args": ["F:/Codes/Git/Quantsmind-Products/GuardMCP/dist/index.js"],
      "env": { "NVD_API_KEY": "your-key", "GITHUB_TOKEN": "ghp_xxx" }
    }
  }
}
```

**VS Code** (`settings.json` → `mcp.servers`) and **Cursor** (`~/.cursor/mcp.json`) — same shape.

Test via MCP Inspector:
```bash
npx @modelcontextprotocol/inspector node dist/index.js
# → list_tools, then call check_cve {cveId:"CVE-2021-44228"}
```

---

## 12. Security & Compliance

- No secrets logged — `audit-log.ts:45` redacts token-like keys.
- No network egress beyond the 4 allow-listed hosts.
- Read-only tools — no file writes except `logs/audit.log`.
- Cache is in-memory only; no persistence of vulnerability data beyond TTL.
- `validator.ts` rejects malformed CVE IDs and empty package names before any fetch.

---

## 13. Testing & Verification

```bash
npm test
# ✓ tests/cache.test.ts (store/retrieve, expiry, key helpers)
# ✓ tests/validator.test.ts (CVE regex, scan_package)
```

Manual verification:
```bash
node --input-type=module -e "
import {createServer} from './dist/server.js';
import {allTools} from './dist/tools/index.js';
console.log(allTools.map(t=>t.name));
"
# → check_cve, scan_package, audit_dependencies, search_vulnerabilities
```

---

## 14. Roadmap

- [ ] HTTP+SSE transport for remote agents
- [ ] Redis-backed cache for multi-instance deployments
- [ ] SARIF output for CI integration
- [ ] `purl` support + SBOM (`cyclonedx.json`) ingestion
- [ ] Policy engine (block `CRITICAL` on `audit_dependencies`)

---

## License
MIT — see `LICENSE`.

> **Maintainer:** Ajit Kumar (`ajitjava2@gmail.com`) · **Repo:** `ajit-ai/GuardMCP` · **Version:** 1.0.0
