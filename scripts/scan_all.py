#!/usr/bin/env python3
"""
Unified local security scan.

Runs every layer of the pipeline against a repo and prints one compact table
per scan type (Secrets, SCA + malicious packages, SAST, DAST, AI workflow blast
radius). Each layer uses its open-source scanner when installed (gitleaks,
semgrep, trivy, osv-scanner, ZAP) and a built-in Python fallback otherwise, so
the command always produces a result — and tells you how to install the real
tools for deeper coverage.

Initial output is intentionally compact: severity + finding title only. Drill
into any layer with `--detail <type>`, the interactive prompt, or the clickable
HTML report (`--html`). A ready-to-paste fix prompt is generated per scan type.

Usage:
    python scripts/scan_all.py [ROOT] [options]

stdlib only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import external_tools as ext  # noqa: E402
import check_packages  # noqa: E402
import run_pipeline as rp  # noqa: E402
import blast_radius as br  # noqa: E402
import policy as policy_mod  # noqa: E402
from scanners import registry  # noqa: E402
from scanners.secrets import config_secrets as secrets_in_config, prompt_privacy  # noqa: E402

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Order + the compact-view labels. The canonical ordering and the AI fix-prompt
# wording live once in scanners/registry.py (SCAN_TYPES); these labels are the
# upper-cased display strings for the terminal table.
TABLE_ORDER = list(registry.SCAN_TYPE_KEYS)
LABELS = {
    "secrets": "SECRETS",
    "packages": "DEPENDENCY TRUST  (supply chain)",
    "sca": "DEPENDENCIES  (SCA / CVEs)",
    "sast": "STATIC ANALYSIS  (SAST)",
    "iac": "INFRASTRUCTURE AS CODE  (IaC)",
    "ci_cd": "CI / CD  (GitHub Actions)",
    "ai_posture": "AI WORKFLOW BLAST RADIUS",
    "dast": "DYNAMIC ANALYSIS  (DAST)",
}
SOURCE_EXTS = (".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
MAX_FILE_BYTES = 1_500_000  # skip giant/minified files in the built-in scanners


@dataclass
class ScanFinding:
    scan_type: str
    severity: str
    title: str
    detail: str = ""
    file: str = ""
    line: int = 0
    fix: str = ""
    tool: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Layer:
    scan_type: str
    engine: str                       # which scanner ran (e.g. "semgrep" or "built-in")
    findings: list = field(default_factory=list)
    note: str = ""                    # e.g. "install semgrep for deeper coverage"


# ─────────────────────────────────────────────────────────────────────────────
# Built-in fallbacks (no external tool required)
# ─────────────────────────────────────────────────────────────────────────────

# Our own rule-definition files embed example/pattern strings that look like
# insecure code (e.g. the Semgrep pattern "app.run(..., debug=True, ...)"). The
# regex fallback must not flag its own catalog — these files carry this marker.
_SCANNER_SOURCE_MARKER = "secure-ai-pipeline:rule-source"


def _is_scanner_source(p: Path) -> bool:
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            return _SCANNER_SOURCE_MARKER in fh.read(2048)
    except OSError:
        return False


def _walk_sources(root: Path):
    for p in root.rglob("*"):
        if check_packages._skip(p) or not p.is_file():
            continue
        if p.suffix not in SOURCE_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if _is_scanner_source(p):
            continue
        yield p


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def builtin_secrets(root: Path) -> list:
    from scanners.base import SECRET_VALUE_PATTERNS
    out: list = []
    # Config / .env / MCP secrets and prompt-embedded secrets.
    for f in secrets_in_config.scan(root):
        out.append(ScanFinding("secrets", f.severity, f.title, f.detail,
                               f.file, f.line, f.fix, "built-in"))
    for f in prompt_privacy.scan(root):
        if f.rule_id == "prompt-secret":
            out.append(ScanFinding("secrets", f.severity, f.title, f.detail,
                                   f.file, f.line, f.fix, "built-in"))
    # High-confidence provider tokens in source. We deliberately do NOT use the
    # generic "40+ char string" heuristic here — it floods real codebases with
    # false positives (base64 data, hashes, test fixtures). gitleaks does
    # entropy + allowlisting properly; install it for that.
    for p in _walk_sources(root):
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "#", "*")) or rp._SUPPRESS_RE.search(line):
                continue
            for pat, label in SECRET_VALUE_PATTERNS:
                if pat.search(line):
                    out.append(ScanFinding(
                        "secrets", "CRITICAL", f"Hardcoded {label}",
                        f"A {label} appears to be hardcoded in source.",
                        _rel(p, root), i,
                        "Remove it; load from the environment / a secrets manager and rotate it.",
                        "built-in"))
                    break
    return out


def builtin_sast(root: Path) -> list:
    # The built-in regex rules are Python-oriented but run on JS/TS too (the
    # language-agnostic ones still fire); semgrep is the real cross-language SAST.
    out: list = []
    for p in _walk_sources(root):
        for f in rp.stage1_sast(p):
            out.append(ScanFinding("sast", ext._norm_sev(f.severity),
                                   f.message.split(".")[0], f.message,
                                   _rel(p, root), f.line, f.message, "built-in"))
    return out


def builtin_packages(root: Path, offline: bool) -> list:
    """Supply-chain integrity: hallucinated / non-existent / registry-unreachable
    imports (anti-slopsquatting). The unique check no external tool does."""
    out: list = []
    if not offline:
        for f in br.package_findings(root):
            out.append(ScanFinding("packages", f.severity, f.title, f.detail,
                                   f.file, f.line, f.fix, "built-in (anti-slopsquatting)"))
    return out


def builtin_sca(root: Path, offline: bool) -> list:
    # Curated CVEs for pinned requirements.txt deps (offline-safe). Real CVE
    # breadth comes from trivy/osv/grype/pip-audit when installed.
    out: list = []
    import re
    for req in root.rglob("requirements*.txt"):
        if check_packages._skip(req):
            continue
        for f in rp.stage1_sca(req):
            # Drop the path-missing note and the "verify on PyPI" note: the latter
            # has no real CVE/fix (so the '(fix: …)' extraction below would mislabel
            # it "Upgrade to a patched release") and is the packages layer's job.
            if f.rule_id in ("requirements-not-found", "unknown-package-in-requirements"):
                continue
            m = re.search(r"\(fix:\s*([^)]+)\)", f.message)
            fixtext = f"Upgrade to {m.group(1).strip()}." if m else \
                "Upgrade to a patched release (see the advisory)."
            out.append(ScanFinding("sca", ext._norm_sev(f.severity), f.message.split(" (fix")[0],
                                   f.message, _rel(req, root), f.line, fixtext,
                                   "built-in (curated CVEs)"))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────

def _from_ext(scan_type: str, rows: list) -> list:
    return [ScanFinding(scan_type, ext._norm_sev(r["severity"]), r["title"],
                        r.get("detail", ""), r.get("file", ""), int(r.get("line") or 0),
                        r.get("fix", ""), r.get("tool", "")) for r in rows]


# Per-scan-type built-in fallback policy. Each entry: (fn(ctx) -> list[ScanFinding],
# always). always=True runs the built-in even when an external tool ran (slopsquatting
# + curated CVEs + the AI blast radius cover ground no OSS tool does); always=False
# uses the built-in only when no external scanner for that type is installed. Every
# fn takes the ScanContext so the policy is uniform (no root/offline-vs-ctx split).
BUILTIN_FALLBACK = {
    "secrets":    (lambda ctx: builtin_secrets(ctx.root), False),
    "packages":   (lambda ctx: builtin_packages(ctx.root, ctx.offline), True),
    "sca":        (lambda ctx: builtin_sca(ctx.root, ctx.offline), True),
    "sast":       (lambda ctx: builtin_sast(ctx.root), False),
    "ai_posture": (lambda ctx: builtin_ai_posture(ctx), True),
}


def _progress(msg: str) -> None:
    """Stream scan progress to stderr so a long CI step never looks frozen.
    stdout carries the table / --json path, so progress stays on stderr."""
    print(msg, file=sys.stderr, flush=True)


def _run_adapter(adapter, ctx) -> tuple:
    """Run one tool, timed, swallowing any error (a broken tool is skipped, not
    fatal). Returns (rows|None, elapsed_seconds)."""
    t0 = time.monotonic()
    try:
        rows = adapter.run(ctx)
    except Exception:
        rows = None
    return rows, time.monotonic() - t0


def _assemble_layer(scan_type: str, ext_results: list, ctx: "registry.ScanContext") -> Layer:
    """Consolidate one type's results into a Layer: the (already-fetched, possibly
    parallel) external tool outputs + the per-type built-in fallback per policy.
    This is the single path that makes 'drop an adapter file under scanners/ → it
    runs in every channel' true — scan_all, the Action and the MCP server all
    reach a tool through the registry, here."""
    findings: list = []
    engines: list = []
    for name, rows in ext_results:
        findings += _from_ext(scan_type, rows)
        engines.append(name)

    fb = BUILTIN_FALLBACK.get(scan_type)
    if fb:
        fn, always = fb
        if always or not engines:
            findings += fn(ctx)
            engines.append("built-in")

    # When no real OSS tool ran (built-in-only, or nothing), point at what to install.
    note = ""
    if not any(e != "built-in" for e in engines):
        missing = [a for a in registry.adapters_for(scan_type) if not a.available()]
        if missing:
            note = ("install " + ", ".join(a.name for a in missing[:3])
                    + f" for deeper {LABELS.get(scan_type, scan_type)} coverage — "
                    + missing[0].install)
    engine = " + ".join(dict.fromkeys(engines)) if engines else "not run"
    return Layer(scan_type, engine, findings, note=note)


def builtin_ai_posture(ctx: "registry.ScanContext") -> list:
    # The AI Agent Blast Radius checkup (MCP/IDE/Claude/Actions posture). Applies
    # the repo's secure-ai-pipeline.yml policy so this matches the standalone
    # `posture` command (path excludes, rule ignores, MCP allowlist). Runs as the
    # ai_posture built-in fallback; external ai_posture adapters merge alongside it.
    report = policy_mod.apply(br.assess(ctx.root, offline=True), ctx.policy or {})
    return [ScanFinding("ai_posture", f["severity"], f["title"], f.get("detail", ""),
                        f.get("file", ""), int(f.get("line") or 0), f.get("fix", ""), "built-in")
            for f in report["findings"]]


def run_dast(url: str, ctx: "registry.ScanContext") -> Layer:
    ctx.dast_url = url
    findings, engines = [], []
    for adapter in registry.available_adapters("dast"):
        rows = adapter.run(ctx)
        if rows is None:
            continue
        findings += _from_ext("dast", rows)
        engines.append(adapter.name)
    if not engines:
        return Layer("dast", "unavailable", [],
                     note=f"install ZAP or Docker to run DAST — {ext.INSTALL_HINTS['docker']}")
    return Layer("dast", " + ".join(dict.fromkeys(engines)), findings, note=f"target: {url}")


def _scan_context(root: Path, offline: bool, dast_url: str = "") -> "registry.ScanContext":
    base = Path(__file__).resolve().parent.parent
    return registry.ScanContext(
        root=root, offline=offline, dast_url=dast_url,
        semgrep_ruleset=base / ".semgrep" / "ai-insecure-defaults.yml",
        zap_rules=base / ".zap" / "rules.tsv")


def orchestrate(root: Path, *, offline: bool, only: list, dast_url: str = "",
                exclude: list = None, deep: bool = False) -> dict:
    pol = policy_mod.load_policy(root)
    excludes = list(pol.get("exclude", []) or []) + list(exclude or [])
    ctx = _scan_context(root, offline, dast_url)
    ctx.policy = pol            # ai_posture's built-in applies it
    registry.clear_file_index()  # fresh file-listing for this scan (the has_files cache)

    # Default set: every non-DAST type that has a built-in OR an installed tool.
    # iac/ci_cd therefore appear automatically once checkov/zizmor are on PATH
    # (e.g. the Action installs them) and stay hidden on a bare local repo.
    # An explicit --only always runs exactly what was asked (even "not run" types).
    if only:
        selected = [t for t in TABLE_ORDER if t in only]
    else:
        selected = [t for t in TABLE_ORDER if t != "dast" and (
            t in BUILTIN_FALLBACK or registry.available_adapters(t))]

    # Run every external scanner across all selected types CONCURRENTLY (each is a
    # subprocess, so threads give real parallelism). Running ~10 tools one after
    # another with no output is what made the CI step look frozen; progress now
    # streams to stderr and wall-clock collapses toward the slowest single tool.
    _progress(f"Secure AI Pipeline — scanning {root}")
    ext_jobs = [(t, a) for t in selected
                for a in registry.available_adapters(t, include_heavy=deep)]
    if not deep:
        skipped = sorted({a.name for t in selected
                          for a in registry.available_adapters(t) if a.heavy})
        if skipped:
            _progress(f"  (deep-scan off — skipping heavy tool(s): {', '.join(skipped)}; "
                      "pass --deep to include)")
    ext_results: dict = {t: [] for t in selected}
    if ext_jobs:
        try:
            workers = min(int(os.environ.get("SAP_SCAN_CONCURRENCY", "4")), len(ext_jobs))
        except ValueError:
            workers = min(4, len(ext_jobs))
        _progress(f"  {len(ext_jobs)} tool(s), ≤{max(1, workers)} at once: "
                  + ", ".join(sorted(a.name for _, a in ext_jobs)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futs = {pool.submit(_run_adapter, a, ctx): (t, a) for (t, a) in ext_jobs}
            for fut in concurrent.futures.as_completed(futs):
                t, a = futs[fut]
                rows, elapsed = fut.result()
                if rows is None:
                    _progress(f"    · {a.name} ({t}) — skipped, {elapsed:.0f}s")
                    continue
                ext_results[t].append((a.name, rows))
                _progress(f"    ✓ {a.name} ({t}) — {len(rows)} finding(s), {elapsed:.0f}s")

    # ai_posture goes through the same path now: its built-in (blast radius,
    # always=True) plus any external ai_posture adapters that ran, merged.
    layers: dict = {t: _assemble_layer(t, ext_results.get(t, []), ctx) for t in selected}
    if dast_url:
        layers["dast"] = run_dast(dast_url, ctx)

    # Honor exclude globs (policy file + --exclude) across every layer, so
    # fixture/vendor/test dirs can be silenced uniformly.
    if excludes:
        for lyr in layers.values():
            lyr.findings = [f for f in lyr.findings
                            if not policy_mod._excluded(f.file, excludes)]
    return {"root": str(root), "tools": registry.detect(), "layers": layers,
            "excludes": excludes, "ctx": ctx}


# ─────────────────────────────────────────────────────────────────────────────
# Rendering
# ─────────────────────────────────────────────────────────────────────────────

_C = {"CRITICAL": "\033[91m\033[1m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
      "LOW": "\033[96m", "INFO": "\033[2m", "_": "\033[0m", "B": "\033[1m",
      "DIM": "\033[2m", "OK": "\033[92m"}


def _color_on(no_color: bool) -> bool:
    return (not no_color) and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(key: str, text: str, on: bool) -> str:
    return f"{_C[key]}{text}{_C['_']}" if on else text


def _counts(findings: list) -> dict:
    d = {s: 0 for s in SEVERITIES}
    for f in findings:
        d[f.severity] = d.get(f.severity, 0) + 1
    return d


def _summary_chips(counts: dict, on: bool) -> str:
    parts = [_c(s, f"{counts[s]} {s.lower()}", on) for s in SEVERITIES if counts[s]]
    return "  ".join(parts) if parts else _c("OK", "clean", on)


def _group(findings: list) -> list:
    """Group by (severity, title) → (severity, title, count). Sorted by
    severity then count desc. Keeps the compact table readable on big repos."""
    agg: dict = {}
    for f in findings:
        agg.setdefault((f.severity, f.title), 0)
        agg[(f.severity, f.title)] += 1
    rows = [(sev, title, n) for (sev, title), n in agg.items()]
    rows.sort(key=lambda r: (_RANK.get(r[0], 9), -r[2]))
    return rows


def render_compact(result: dict, no_color: bool = False, group_cap: int = 12) -> str:
    on = _color_on(no_color)
    out: list = []
    layers = result["layers"]

    total = sum(len([f for f in lyr.findings if f.severity != "INFO"])
                for lyr in layers.values())
    out.append("")
    out.append(_c("B", "  Secure AI Pipeline — full scan", on))
    out.append(_c("DIM", f"  {result['root']}", on))
    out.append("")

    for t in TABLE_ORDER:
        lyr = layers.get(t)
        if lyr is None:
            continue
        counts = _counts(lyr.findings)
        actionable = sum(counts[s] for s in SEVERITIES if s != "INFO")
        head = f"  ▍ {LABELS[t]}"
        engine = _c("DIM", f"· {lyr.engine}", on)
        out.append(f"{_c('B', head, on)}   {engine}")
        if actionable == 0 and counts["INFO"] == 0:
            out.append(f"      {_c('OK', '✓ no findings', on)}")
        else:
            out.append(f"      {_summary_chips(counts, on)}")
            for sev, title, n in _group([f for f in lyr.findings if f.severity != "INFO"])[:group_cap]:
                badge = _c(sev, f"{sev:<8}", on)
                mult = _c("DIM", f"×{n}", on) if n > 1 else "   "
                out.append(f"      {badge} {mult}  {title[:84]}")
            groups = _group([f for f in lyr.findings if f.severity != "INFO"])
            if len(groups) > group_cap:
                out.append(_c("DIM", f"      … +{len(groups) - group_cap} more "
                                     f"(run --detail {t})", on))
        if lyr.note:
            out.append(_c("DIM", f"      ⓘ {lyr.note}", on))
        out.append("")

    if "dast" not in layers:
        out.append(_c("DIM", "  ▍ DYNAMIC ANALYSIS (DAST)   · not run", on))
        out.append(_c("DIM", "      pass --dast-url <url> (or answer the prompt) to scan a running app", on))
        out.append("")

    verdict = (_c("OK", "  ✓  No blocking findings.", on) if total == 0
               else _c("HIGH", f"  ⚠  {total} actionable finding(s) across "
                               f"{sum(1 for l in layers.values() if any(f.severity!='INFO' for f in l.findings))} layer(s).", on))
    out.append(verdict)
    return "\n".join(out)


def _first_line(s: str, limit: int = 300) -> str:
    """First non-blank line of s, truncated. Safe on empty/whitespace-only input
    (`'\\n'.strip().splitlines()[0]` is an IndexError; this returns '')."""
    for ln in (s or "").splitlines():
        ln = ln.strip()
        if ln:
            return ln[:limit]
    return ""


def render_detail(result: dict, scan_type: str, no_color: bool = False) -> str:
    on = _color_on(no_color)
    lyr = result["layers"].get(scan_type)
    if lyr is None:
        return _c("DIM", f"  (no '{scan_type}' results)", on)
    out = ["", _c("B", f"  ── {LABELS.get(scan_type, scan_type.upper())} · {lyr.engine} ──", on)]
    findings = sorted(lyr.findings, key=lambda f: (_RANK.get(f.severity, 9), f.file))
    if not findings:
        out.append(_c("OK", "  ✓ no findings", on))
        return "\n".join(out)
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"  {_c(f.severity, '● ' + f.severity, on)}  {f.title}")
        if loc:
            out.append(_c("DIM", f"      {loc}", on))
        detail = _first_line(f.detail)
        if detail:
            out.append(f"      {detail}")
        fix = _first_line(f.fix)
        if fix:
            out.append(_c("OK", f"      fix: {fix}", on))
        out.append("")
    return "\n".join(out)


def render_tools(result: dict, no_color: bool = False) -> str:
    on = _color_on(no_color)
    out = [_c("B", "  Scanner engines  (OSS — installed ones run, the rest are optional)", on)]
    installed = result["tools"]
    for t in TABLE_ORDER:
        for a in registry.adapters_for(t):
            if installed.get(a.name):
                out.append(f"    {_c('OK', '✓', on)} {a.name:<15} {_c('DIM', t, on)}")
            else:
                out.append(f"    {_c('DIM', '·', on)} {a.name:<15} "
                           f"{_c('DIM', f'{t} — {a.install}', on)}")
    sh = ext.socket_hint()
    if sh:
        out.append(_c("DIM", f"    ⓘ {sh}", on))
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Fix prompts
# ─────────────────────────────────────────────────────────────────────────────

def fix_prompt(scan_type: str, findings: list, root: str) -> str:
    # The per-type "Task:" wording lives once in scanners/registry.py so scan_all
    # and the Action job summary phrase the AI fix prompt identically.
    lines = [f"# Fix prompt — {LABELS.get(scan_type, scan_type)}",
             "",
             f"You are a senior application-security engineer. In the repo at `{root}`, "
             f"{registry.intro_for(scan_type)}.",
             "",
             "Rules:",
             "- Fix only what each finding describes; do not touch unrelated code.",
             "- Show a diff per file and explain the change in one line.",
             "- If a fix needs a decision (e.g. which env var name), ask before guessing.",
             "",
             "## Findings",
             ""]
    for f in sorted(findings, key=lambda x: (_RANK.get(x.severity, 9), x.file)):
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "—")
        lines.append(f"- **[{f.severity}]** {f.title}  ({loc})")
        fix = _first_line(f.fix, limit=10_000)
        if fix:
            lines.append(f"  - suggested: {fix}")
    lines.append("")
    return "\n".join(lines)


def write_fix_prompts(result: dict, out_dir: Path) -> list:
    written = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for t, lyr in result["layers"].items():
        actionable = [f for f in lyr.findings if f.severity != "INFO"]
        if not actionable:
            continue
        path = out_dir / f"fix-{t}.md"
        path.write_text(fix_prompt(t, actionable, result["root"]), encoding="utf-8")
        written.append(path)
    return written


# ─────────────────────────────────────────────────────────────────────────────
# Unified clickable HTML report
# ─────────────────────────────────────────────────────────────────────────────

def render_html(result: dict) -> str:
    import html
    sev_color = {"CRITICAL": "#b00020", "HIGH": "#d93025", "MEDIUM": "#e8710a",
                 "LOW": "#1a73e8", "INFO": "#9aa0a6"}
    sections = []
    for t in TABLE_ORDER:
        lyr = result["layers"].get(t)
        if lyr is None:
            continue
        counts = _counts(lyr.findings)
        chips = "".join(
            f'<span class="chip" style="background:{sev_color[s]}">{counts[s]} {s}</span>'
            for s in SEVERITIES if counts[s]) or '<span class="chip ok">clean</span>'
        rows = ""
        for f in sorted(lyr.findings, key=lambda x: (_RANK.get(x.severity, 9), x.file)):
            loc = html.escape(f.file + (f":{f.line}" if f.line else ""))
            rows += (f'<tr><td><span class="sev" style="background:{sev_color.get(f.severity,"#888")}">'
                     f'{f.severity}</span></td><td>{html.escape(f.title)}'
                     f'<div class="d">{html.escape(_first_line(f.detail))}</div>'
                     f'<div class="fx">{html.escape(f.fix)}</div></td>'
                     f'<td class="loc">{loc}</td></tr>')
        if not rows:
            rows = '<tr><td colspan="3" class="okrow">✓ no findings</td></tr>'
        note = f'<div class="note">ⓘ {html.escape(lyr.note)}</div>' if lyr.note else ""
        sections.append(f"""
  <details {'open' if any(f.severity in ('CRITICAL','HIGH') for f in lyr.findings) else ''}>
    <summary><b>{html.escape(LABELS[t])}</b> <span class="eng">· {html.escape(lyr.engine)}</span>
      <span class="chips">{chips}</span></summary>
    {note}
    <table><tr><th>Severity</th><th>Finding</th><th>Location</th></tr>{rows}</table>
  </details>""")
    body = "\n".join(sections)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure AI Pipeline — full scan</title><style>
:root{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif}}
body{{margin:0;background:#f5f6f7;color:#202124}} .wrap{{max-width:920px;margin:0 auto;padding:28px 20px 64px}}
h1{{font-size:20px;margin:0 0 2px}} .sub{{color:#5f6368;font-size:13px;margin:0 0 20px}}
details{{background:#fff;border-radius:10px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.08);overflow:hidden}}
summary{{cursor:pointer;padding:14px 16px;font-size:14px;list-style:none;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
summary::-webkit-details-marker{{display:none}} .eng{{color:#9aa0a6;font-size:12px}}
.chips{{margin-left:auto}} .chip{{color:#fff;border-radius:999px;padding:2px 9px;font-size:11px;margin-left:5px}}
.chip.ok{{background:#137333}} table{{border-collapse:collapse;width:100%}}
th,td{{padding:8px 14px;text-align:left;font-size:13px;border-top:1px solid #eee;vertical-align:top}}
th{{background:#fafafa;color:#5f6368;font-size:11px;text-transform:uppercase}}
.sev{{color:#fff;font-size:10px;font-weight:700;border-radius:4px;padding:2px 6px;white-space:nowrap}}
.loc{{color:#1a73e8;font-family:ui-monospace,Menlo,monospace;font-size:11px;white-space:nowrap}}
.d{{color:#3c4043;font-size:12px;margin-top:3px}} .fx{{color:#137333;font-size:12px;margin-top:3px}}
.note{{color:#8a6d00;background:#fff8e1;padding:8px 16px;font-size:12px}} .okrow{{color:#137333}}
</style></head><body><div class="wrap">
<h1>Secure AI Pipeline — full scan</h1>
<p class="sub">{html.escape(result['root'])} · click any section to expand. Secrets · SCA + malicious packages · SAST · DAST · AI workflow blast radius.</p>
{body}
</div></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Combined SARIF (one document for every tool → the GitHub Security tab)
# ─────────────────────────────────────────────────────────────────────────────

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}
_SARIF_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}


def render_sarif(result: dict) -> dict:
    """One SARIF 2.1.0 document covering every layer/tool, so a single upload
    populates GitHub code scanning with the whole consolidated result."""
    rules: dict = {}
    results: list = []
    for stype, lyr in result["layers"].items():
        for f in lyr.findings:
            if f.severity == "INFO":
                continue
            rid = f"sap/{stype}/{f.tool or 'built-in'}"
            if rid not in rules:
                rules[rid] = {
                    "id": rid, "name": rid.replace("/", "-"),
                    "shortDescription": {"text": f"{LABELS.get(stype, stype)} · {f.tool or 'built-in'}"},
                    "properties": {"security-severity": _SARIF_SCORE.get(f.severity, "5.0"),
                                   "tags": ["security", stype]}}
            results.append({
                "ruleId": rid,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.title + (f"\n\nFix: {f.fix}" if f.fix else "")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": (f.file or ".").lstrip("/")},
                    "region": {"startLine": max(1, int(f.line or 1))}}}],
                "properties": {"tool": f.tool, "severity": f.severity},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Secure AI Pipeline",
                "informationUri": "https://github.com/AvinashNutalapati/secure-ai-pipeline",
                "rules": list(rules.values())}},
            "results": results,
        }],
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _all_findings(result: dict) -> list:
    return [f for lyr in result["layers"].values() for f in lyr.findings]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Unified local security scan.")
    parser.add_argument("root", nargs="?",
                        default=os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    parser.add_argument("--offline", action="store_true",
                        help="Skip network checks (anti-slopsquatting package lookups).")
    parser.add_argument("--deep", action="store_true",
                        help="Also run the heaviest scanners (e.g. GuardDog deep package "
                             "analysis). Off by default so the standard scan stays fast.")
    parser.add_argument("--only", default="",
                        help="Comma-separated scan types to run "
                             "(secrets,packages,sca,sast,iac,ci_cd,ai_posture).")
    parser.add_argument("--exclude", default="",
                        help="Comma-separated path globs to drop from every layer "
                             "(e.g. 'test/**,data/**'). Merged with the policy file's exclude.")
    parser.add_argument("--detail", default="",
                        help="Expand one or more layers: a type, comma-list, or 'all'.")
    parser.add_argument("--dast-url", default="", help="Run a ZAP DAST scan against this URL.")
    parser.add_argument("--no-dast", action="store_true", help="Never prompt for a DAST URL.")
    parser.add_argument("--json", metavar="OUT", help="Write the full result as JSON.")
    parser.add_argument("--html", metavar="OUT", help="Write the clickable HTML report.")
    parser.add_argument("--sarif", metavar="OUT",
                        help="Write a combined SARIF 2.1.0 file (for GitHub code scanning).")
    parser.add_argument("--fix-prompts-dir", default=".secure-ai-pipeline",
                        help="Where to write per-type AI fix prompts (default: .secure-ai-pipeline).")
    parser.add_argument("--no-fix-prompts", action="store_true",
                        help="Do not generate fix-prompt files.")
    parser.add_argument("--fail-on", type=str.lower, choices=["critical", "high", "medium"],
                        help="Exit 1 if a finding at/above this severity exists.")
    parser.add_argument("--no-input", action="store_true",
                        help="Never prompt (CI mode).")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--tools", action="store_true",
                        help="Show which scanner engines are installed, then scan.")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    only = [s.strip() for s in args.only.split(",") if s.strip()]
    cli_excludes = [s.strip() for s in args.exclude.split(",") if s.strip()]
    interactive = sys.stdin.isatty() and not args.no_input

    result = orchestrate(root, offline=args.offline, only=only,
                         dast_url=args.dast_url, exclude=cli_excludes, deep=args.deep)

    if args.tools:
        print(render_tools(result, no_color=args.no_color))
        print()
    print(render_compact(result, no_color=args.no_color))

    # Explicit drill-down requested on the command line.
    detail = [s.strip() for s in args.detail.split(",") if s.strip()]
    if "all" in detail:
        detail = list(result["layers"].keys())
    for t in detail:
        print(render_detail(result, t, no_color=args.no_color))

    # Interactive drill-down ("click in").
    if interactive and not detail and not args.json and not args.html:
        _interactive_detail(result, args.no_color)

    # DAST: offer to scan a running app if we didn't already.
    if "dast" not in result["layers"] and not args.no_dast and not args.dast_url and interactive:
        _interactive_dast(result, args.no_color)

    # Fix prompts.
    if not args.no_fix_prompts:
        written = write_fix_prompts(result, root / args.fix_prompts_dir)
        if written:
            on = _color_on(args.no_color)
            print(_c("B", "\n  Fix prompts (paste into Cursor / Claude Code):", on))
            for p in written:
                print(_c("DIM", f"    {_rel(p, root)}", on))

    if args.json:
        Path(args.json).write_text(json.dumps({
            "root": result["root"],
            "tools": {k: bool(v) for k, v in result["tools"].items()},
            "layers": {t: {"engine": l.engine, "note": l.note,
                           "findings": [f.to_dict() for f in l.findings]}
                       for t, l in result["layers"].items()},
        }, indent=2), encoding="utf-8")
        print(f"\n  JSON written to {args.json}")
    if args.html:
        Path(args.html).write_text(render_html(result), encoding="utf-8")
        print(f"  HTML report written to {args.html}")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(render_sarif(result), indent=2), encoding="utf-8")
        print(f"  SARIF written to {args.sarif}")

    if args.fail_on:
        threshold = _RANK[args.fail_on.upper()]
        worst = min((_RANK.get(f.severity, 9) for f in _all_findings(result)), default=9)
        if worst <= threshold:
            print(_c("CRITICAL", f"\n  ⛔ gate: finding at/above {args.fail_on.upper()}.",
                     _color_on(args.no_color)))
            return 1
    return 0


def _interactive_detail(result: dict, no_color: bool) -> None:
    on = _color_on(no_color)
    avail = [t for t in TABLE_ORDER if t in result["layers"]
             and any(f.severity != "INFO" for f in result["layers"][t].findings)]
    if not avail:
        return
    prompt = _c("DIM", f"  ▸ Expand a layer for details [{', '.join(avail)}, all, Enter=skip]: ", on)
    while True:
        try:
            choice = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if not choice:
            return
        if choice == "all":
            for t in avail:
                print(render_detail(result, t, no_color=no_color))
            return
        # Accept 'posture' as an alias for ai_posture.
        t = "ai_posture" if choice in ("posture", "ai", "ai_posture") else choice
        if t in result["layers"]:
            print(render_detail(result, t, no_color=no_color))
        else:
            print(_c("DIM", f"    no such layer: {choice}", on))


def _interactive_dast(result: dict, no_color: bool) -> None:
    on = _color_on(no_color)
    try:
        url = input(_c("DIM", "  ▸ Run a DAST scan? Enter a running app URL "
                              "(e.g. http://localhost:3000), or Enter to skip: ", on)).strip()
    except (EOFError, KeyboardInterrupt):
        return
    if not url:
        return
    layer = run_dast(url, result["ctx"])
    result["layers"]["dast"] = layer
    print(render_detail(result, "dast", no_color=no_color) if layer.findings
          else _c("DIM", f"    {layer.note or 'no DAST findings'}", on))


if __name__ == "__main__":
    sys.exit(main())
