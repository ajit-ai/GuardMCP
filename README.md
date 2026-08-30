# GuardMCP

> Security-first MCP server — vulnerability scanning for AI agents via NVD, OSV, npm and GitHub Advisory.

### Architecture — 3 Layers (Diagram 1)
```
┌─────────────────────────────────┐
│  AI Agent Clients (Top Layer)   │  Claude Code, VS Code, Cursor
│         -- MCP stdio/HTTP -->    │
├─────────────────────────────────┤
│  GuardMCP Server (Middle)       │  4 tools + core engine
│  Tools: check_cve, scan_package, audit_dependencies, search_vulnerabilities
│  Engine: cache, validator, audit-log, rate-limiter
│         -- HTTPS -->             │
├─────────────────────────────────┤
│  External Data (Bottom Layer)   │  NVD, OSV.dev, npm Registry, GitHub Advisory
└─────────────────────────────────┘
```

### Request Lifecycle (Diagram 2)
```
Agent -> validate -> cache check ->[HIT]-> return instantly
                      |
                    [MISS]
                      v
                  tool dispatcher -> external API -> format result -> audit log
```
Cache is the critical performance feature: **1h for CVEs, 24h for packages** to respect NVD's `5 req/30s` (no key) / `50 req/30s` (with key). Set `NVD_API_KEY` to bypass strict limit.

### Tools

| Tool | Description | Source |
|------|-------------|--------|
| `check_cve` | Lookup CVE by ID (CVSS, severity, CWE, refs) | NVD + GitHub |
| `scan_package` | Scan `name@version` in ecosystem | OSV + npm |
| `audit_dependencies` | Batch audit `package.json` or dependency map | OSV batch |
| `search_vulnerabilities` | Keyword search across NVD + GitHub | NVD + GitHub |

### Quick Start

```bash
npm install
npm run build
npm start
```

Env: copy `.env.example` to `.env` and set `NVD_API_KEY` / `GITHUB_TOKEN`.

### MCP Client Config

**Claude Code** (`claude.json` / `.mcp.json`):
```json
{
  "mcpServers": {
    "guardmcp": { "command": "node", "args": ["F:/Codes/Git/Quantsmind-Products/GuardMCP/dist/index.js"], "env": { "NVD_API_KEY": "..." } }
  }
}
```

VS Code / Cursor: same `mcpServers` in settings.

### Project Structure (Diagram 3)
```
src/
  index.ts              # entry, stdio transport
  server.ts             # server + request lifecycle
  config.ts             # env & TTLs
  types/index.ts
  tools/
    check-cve.ts
    scan-package.ts
    audit-dependencies.ts
    search-vulnerabilities.ts
    index.ts
  services/
    nvd-service.ts
    osv-service.ts
    npm-service.ts
    github-service.ts
  utils/
    cache.ts            # TTLCache (1h / 24h)
    validator.ts        # zod schemas
    audit-log.ts        # enterprise audit log
    rate-limiter.ts     # NVD 5/30s limiter
tests/
  cache.test.ts
  validator.test.ts
```

### Audit Logging
Every tool call is appended as JSONL to `logs/audit.log` (`AUDIT_LOG_PATH`). Contains timestamp, tool, params (sanitized), duration, cacheHit, success. This fills the enterprise gap called out in GitHub's MCP roadmap.

### Cache TTLs
- `CVE_CACHE_TTL=3600000` (1h) — CVE details change slowly
- `PACKAGE_CACHE_TTL=86400000` (24h) — package vulns stable

### License
MIT
