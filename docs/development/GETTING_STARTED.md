# Getting Started (G0)

## Prereqs

- Python 3.11+
- `uv` (recommended) or `pip`

```bash
python --version  # >=3.11
uv --version
```

## Install

```bash
uv pip install --system -e ".[dev]"
uv pip install --system -e ./packages/guardmcp-core
# add other packages as they become implemented
```

Or:

```bash
make install
```

## Validate

```bash
make format
make lint
make typecheck
make test
make ci
```

## Project Layout

- `packages/` - domain packages (see `docs/architecture/OVERVIEW.md`)
- `tests/{unit,integration,security,e2e}` - test categories
- `scripts/check-deps.py` - architecture guard
- `.github/workflows/ci.yml` - CI gate

## Next

Await instruction `Proceed to G1` to implement GuardContext and core domain models.
