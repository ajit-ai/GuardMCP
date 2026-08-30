"""G0 placeholder test — validates test harness, not domain logic."""

from __future__ import annotations


def test_placeholder_passes() -> None:
    assert True


def test_python_version() -> None:
    import sys

    assert sys.version_info >= (3, 11)
