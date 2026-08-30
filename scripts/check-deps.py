"""Architecture dependency guard — G0.

Ensures domain packages do not import forbidden infrastructure.

Forbidden imports for domain packages:
  fastapi, sqlalchemy, psycopg, redis, opentelemetry, mcp
"""

from __future__ import annotations

import pathlib
import re
import sys

FORBIDDEN = re.compile(
    r"^\s*(import|from)\s+(fastapi|sqlalchemy|psycopg|redis|opentelemetry|mcp)\b"
)

DOMAIN_PACKAGES = [
    "packages/guardmcp-core/src",
    "packages/guardmcp-context/src",
    "packages/guardmcp-errors/src",
    "packages/guardmcp-policy/src",
    "packages/guardmcp-risk/src",
    "packages/guardmcp-budget/src",
    "packages/guardmcp-decision/src",
    "packages/guardmcp-audit/src",
]


def main() -> int:
    violations: list[str] = []
    for pkg in DOMAIN_PACKAGES:
        for py in pathlib.Path(pkg).rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                if FORBIDDEN.search(line):
                    violations.append(f"{py}:{i}: {line.strip()}")
    if violations:
        print("Architecture violations — domain imports forbidden infra:", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("deps check: OK — no forbidden domain imports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
