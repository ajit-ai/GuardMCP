"""G0: verify workspace installs and core package imports."""

from __future__ import annotations


def test_guardmcp_core_imports() -> None:
    import guardmcp_core

    assert guardmcp_core.__version__ == "0.1.0"


def test_all_placeholders_import() -> None:
    import guardmcp_audit
    import guardmcp_budget
    import guardmcp_context
    import guardmcp_decision
    import guardmcp_errors
    import guardmcp_policy
    import guardmcp_risk

    for mod in [
        guardmcp_context,
        guardmcp_errors,
        guardmcp_policy,
        guardmcp_risk,
        guardmcp_budget,
        guardmcp_decision,
        guardmcp_audit,
    ]:
        assert hasattr(mod, "__version__")
