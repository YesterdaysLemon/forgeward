from __future__ import annotations

import runpy

import pytest

import forgeward.cli as cli_module


def test_python_module_entrypoint_invokes_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked: list[bool] = []
    monkeypatch.setattr(cli_module, "app", lambda: invoked.append(True))

    runpy.run_module("forgeward.__main__", run_name="__main__")

    assert invoked == [True]
