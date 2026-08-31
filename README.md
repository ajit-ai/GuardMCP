# GuardMCP

> **Trusted execution and security control layer for AI agents and MCP tools.** `AI Agent → GuardMCP → Security Decision → MCP Tool`

[![CI](https://github.com/ajit-ai/GuardMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/ajit-ai/GuardMCP/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GuardMCP controls, evaluates and observes every protected MCP tool execution. **No protected tool execution without a Guard Decision.**

## Architecture

```
AI AGENT
  → GUARDMCP GATEWAY → GUARD CONTEXT → IDENTITY+DELEGATION → POLICY → RISK → BUDGET → SECURITY INTELLIGENCE → DECISION ENGINE → MCP EXECUTION → POST-EXECUTION CONTROL → AUDIT+OBSERVABILITY
```

Dependency direction: `Application → Adapters → Services → Domain` (domain has no deps on FastAPI/PostgreSQL/Redis/MCP transport/OpenTelemetry).

## Project Mission

Primary responsibilities (implemented incrementally G0–G15):

```
1. Request Context Construction  2. Identity Propagation  3. Delegation Validation  4. Agent Identity
5. Policy Evaluation  6. Risk Evaluation  7. Adaptive Budgeting  8. Security Intelligence
9. Execution Decision  10. MCP Interception  11. Post-Execution Inspection  12. Structured Errors  13. Audit Events  14. Observability
```

## Repository Structure

```
guardmcp/
├── packages/guardmcp-core/ … guardmcp-proxy/  (11 modular packages)
├── apps/{gateway,control-plane}
├── examples/{basic,policy,mcp-proxy,security}
├── docs/{architecture,adr,protocols,security,development}
├── tests/{unit,integration,security,e2e}
├── scripts/  └── .github/workflows/
```

See `docs/architecture/OVERVIEW.md` and `docs/adr/`.

## Quick Start (G0-G8)

```bash
# install
pip install uv
uv pip install --system -e ".[dev]"
uv pip install --system -e ./packages/guardmcp-core

# or
make install

# validate
make format
make lint
make typecheck
make test
make ci   # full gate
```

Requires Python 3.11+.

## Implementation Phases

`G0` Repository Foundation → `G1` Core Domain → `G2` Errors → `G3` Policy → `G4` Risk → `G5` Budget → `G6` Decision → `G7` Audit → `G8` MCP Proxy → `G9` Post-Execution → `G10` Security Intelligence → `G11` Observability → `G12` Persistence → `G13` Hardening → `G14` DX → `G15` Release

Current: **G8 complete** — `GuardMCPProxy` (intercept→context→policy→risk→budget→decision→router→audit), 4 decision outcomes tested, `examples/mcp-proxy/basic.py` runnable, 83 tests, mypy strict. Awaiting `Proceed to G9`.

## Documentation

- `docs/architecture/OVERVIEW.md` - system overview
- `docs/adr/ADR-001-python-runtime.md` - Python baseline
- `docs/development/GETTING_STARTED.md` - dev guide

## License

MIT - see `LICENSE`. Maintainer: Ajit Kumar (`ajitjava2@gmail.com`)
