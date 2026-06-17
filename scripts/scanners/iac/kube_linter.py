"""kube-linter adapter — IaC (Kubernetes). https://github.com/stackrox/kube-linter

StackRox's Kubernetes-manifest linter (Apache-2.0, single Go binary). Adds workload-
security depth (runAsNonRoot, readOnlyRootFilesystem, dropped capabilities, resource
limits) that Checkov/KICS cover broadly but kube-linter specialises in. Marked
heavy=True (deep-scan only) since Checkov+KICS already provide baseline K8s coverage;
consolidation collapses any overlap by (rule_key, file, line).

Gated on the presence of YAML manifests; returns None when the binary is absent.

stdlib only.
"""

from __future__ import annotations

from typing import Optional

import external_tools as ext
from external_tools import _which
from scanners.registry import ScanContext, ToolAdapter, register, run_json

_INSTALL = ("brew install kube-linter   (or: "
            "https://docs.kubelinter.io/#/configuring-kubelinter?id=installing-kubelinter)")


def parse(data) -> list:
    return ext.parse_sarif(data, tool="kube-linter")


def run(ctx: ScanContext) -> Optional[list]:
    if not _which("kube-linter"):
        return None
    return run_json(ctx, ["kube-linter", "lint", str(ctx.root), "--format", "sarif"],
                    parse, gate=("*.yaml", "*.yml"))


register(ToolAdapter(
    name="kube-linter", scan_type="iac", binary="kube-linter",
    run=run, install=_INSTALL, heavy=True,
    ci_install="curl -sSfLO https://github.com/stackrox/kube-linter/releases/latest/"
               "download/kube-linter-linux && install kube-linter-linux /usr/local/bin/kube-linter"))
