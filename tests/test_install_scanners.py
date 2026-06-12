"""Tests for scripts/install_scanners.py — the registry-driven CI installer."""

import shutil

import install_scanners as inst


def test_plan_is_registry_driven(monkeypatch):
    # With nothing installed, every adapter that declares a ci_install is planned.
    monkeypatch.setattr(shutil, "which", lambda name: None)
    pip_pkgs, others = inst.plan()
    # pip-installable scanners are batched.
    assert {"bandit", "checkov", "semgrep", "pip-audit"} <= set(pip_pkgs)
    # binary-installer scanners run individually, each with a non-pip command.
    names = {n for n, _ in others}
    assert {"trivy", "grype", "trufflehog"} <= names
    for n, cmd in others:
        assert cmd and not cmd.startswith("pip install")


def test_plan_skips_already_installed(monkeypatch):
    # Pretend everything is on PATH → nothing to install.
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    pip_pkgs, others = inst.plan()
    assert pip_pkgs == [] and others == []


def test_print_mode_runs_and_exits_zero():
    assert inst.main(["--print"]) == 0
