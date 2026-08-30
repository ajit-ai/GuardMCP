# guard-mcp

> Security intelligence MCP server for AI agents

[![npm version](https://img.shields.io/npm/v/guard-mcp?style=flat-square&color=blue)](https://www.npmjs.com/package/guard-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/ajit-ai/GuardMCP?style=flat-square)](https://github.com/ajit-ai/GuardMCP/stargazers)

## Why this exists

AI coding agents blindly `npm install` vulnerable packages with no security context. GuardMCP gives Claude Code, Cursor and any MCP client real-time CVE, package and advisory intelligence with caching and audit trails — so agents make secure choices.

## Quick Install

**No install — run directly:**
```bash
npx guard-mcp
```

**Or add to Claude Code permanently:**
```bash
claude mcp add guard-mcp npx guard-mcp
# with API keys:
claude mcp add guard-mcp --env NVD_API_KEY=your_key -- npx guard-mcp
```

**From source:**
```bash
git clone https://github.com/ajit-ai/GuardMCP.git
cd GuardMCP
npm install && npm run build && npm start
```

<details>
<summary>MCP client config (VS Code / Cursor)</summary>

```json
{
  "mcpServers": {
    "guard-mcp": {
      "command": "npx",
      "args": ["guard-mcp"],
      "env": { "NVD_API_KEY": "..." }
    }
  }
}
```

Or with local build:
```json
{
  "mcpServers": {
    "guard-mcp": {
      "command": "node",
      "args": ["/absolute/path/GuardMCP/dist/index.js"],
      "env": { "NVD_API_KEY": "..." }
    }
  }
}
```
</details>

## Tool Reference

| Tool | What it does | Example Input | Example Output |
|------|--------------|---------------|----------------|
| `check_cve` | Lookup CVE by ID via NVD + GitHub Advisory. Returns CVSS, severity, CWE, refs. | `{"cveId": "CVE-2021-44228"}` | `{"nvd":{"id":"CVE-2021-44228","cvssScore":10,"severity":"CRITICAL","description":"Log4Shell..."},"github":{"ghsa_id":"GHSA-jfh8-c2jp-5v3q"}}` |
| `scan_package` | Scan single package version via OSV + npm. | `{"packageName":"lodash","version":"4.17.20","ecosystem":"npm"}` | `{"packageName":"lodash","version":"4.17.20","isVulnerable":true,"vulnerabilities":[{"id":"GHSA-...","fixedVersion":"4.17.21"}],"latestVersion":"4.17.21"}` |
| `audit_dependencies` | Batch audit `package.json` or dep map via OSV querybatch. | `{"dependencies":{"lodash":"4.17.20","axios":"0.21.1"}}`  or `{"packageJson":"{...}"}` | `{"totalDependencies":2,"vulnerableDependencies":2,"summary":{"critical":1,"high":1},"vulnerabilities":[...]}` |
| `search_vulnerabilities` | Keyword search across NVD + GitHub (threat hunting). | `{"keyword":"log4j","limit":5}`  or `{"keyword":"openssl","severity":"CRITICAL"}` | `{"keyword":"log4j","nvd":{"count":5,"results":[...]},"github":{"count":3,"results":[...]}}` |

All tools follow **validate → cache check (1h CVE / 24h pkg) → dispatcher → external API → format → audit log**. Cache hits return in <10ms and avoid NVD's `5 req/30s` limit.

## Configuration

| Env Var | Required | Default | Description |
|---------|----------|---------|-------------|
| `NVD_API_KEY` | No | — | Get free at https://nvd.nist.gov/developers/request-an-api-key. Without: 5 req/30s, with: 50 req/30s. |
| `REDIS_URL` | No | — | Redis URL for distributed cache (e.g. `redis://localhost:6379`). If unset, in-memory TTL cache is used. Future release will enable shared caching across instances. |
| `LOG_LEVEL` | No | `info` | `debug` echoes audit entries to stderr; `info` silent except startup. |
| `GITHUB_TOKEN` | No | — | Increases GitHub Advisory rate limit (`ghp_xxx`). |
| `CVE_CACHE_TTL` | No | `3600000` (1h) | CVE cache TTL in ms. |
| `PACKAGE_CACHE_TTL` | No | `86400000` (24h) | Package vuln cache TTL in ms. |
| `AUDIT_LOG_PATH` | No | `./logs/audit.log` | JSONL audit trail path. |
| `AUDIT_LOG_ENABLED` | No | `true` | Set `false` to disable audit logging. |

```bash
# .env example
NVD_API_KEY=your_nvd_key
GITHUB_TOKEN=ghp_xxx
REDIS_URL=redis://localhost:6379
LOG_LEVEL=info
```

> **Security:** Audit logs sanitize `apiKey/token/password → "***"` and never block requests on write failure (`src/utils/audit-log.ts:18`).

## Architecture

Three layers (`src/server.ts:20`, `src/tools/index.ts:9`):

```
AI Clients (Claude/Cursor/VS Code) --MCP stdio--> GuardMCP (4 tools + cache/validator/audit/rate-limiter) --HTTPS--> NVD / OSV / npm / GitHub
```

**Request lifecycle:** `validate (zod)` → `cache check` → `[HIT] return` / `[MISS] → rate-limit → fetch → format → audit log`

**Folder map:**
```
src/{index.ts,server.ts,config.ts,types/,tools/{check-cve,scan-package,audit-dependencies,search-vulnerabilities},services/{nvd,osv,npm,github},utils/{cache,validator,audit-log,rate-limiter}}
tests/{cache.test.ts,validator.test.ts}
```

**Executables:** Cross-platform binaries via `npm run build:all` (`@yao-pkg/pkg` + Node SEA):
- `guardmcp-win-x64.exe` + MSI (`installer/wix/guardmcp.wxs`)
- `guardmcp-linux-x64`
- `guardmcp-macos-x64` / `guardmcp-macos-arm64`
- BSD: build natively `npm run build:all` on FreeBSD host or use `node dist/index.js`

## Verification

```bash
npm install
npm run build        # tsc, no errors
npx vitest run       # 5 passed
node dist/index.js   # → [GuardMCP] Server running on stdio
# Inspector:
npx @modelcontextprotocol/inspector node dist/index.js
# Raw:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/index.js
```

## Sponsor this project

If GuardMCP secures your AI workflow, consider sponsoring — your support funds NVD API costs, cache infrastructure and new ecosystems (PyPI, Go, Maven).

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-pink?style=for-the-badge&logo=github)](https://github.com/sponsors/ajit-ai)

*Placeholder: https://github.com/sponsors/ajit-ai — replace with your Sponsors URL after enabling GitHub Sponsors.*

## License

MIT — see [LICENSE](LICENSE). Maintainer: Ajit Kumar (`ajitjava2@gmail.com`) · [ajit-ai/GuardMCP](https://github.com/ajit-ai/GuardMCP)
