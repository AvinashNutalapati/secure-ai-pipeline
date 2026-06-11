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
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import external_tools as ext  # noqa: E402
import check_packages  # noqa: E402
import run_pipeline as rp  # noqa: E402
import blast_radius as br  # noqa: E402
import policy as policy_mod  # noqa: E402
from scanners import secrets_in_config, prompt_privacy  # noqa: E402

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

TABLE_ORDER = ["secrets", "sca", "sast", "dast", "ai_posture"]
LABELS = {
    "secrets": "SECRETS",
    "sca": "DEPENDENCIES  (SCA + malicious packages)",
    "sast": "STATIC ANALYSIS  (SAST)",
    "dast": "DYNAMIC ANALYSIS  (DAST)",
    "ai_posture": "AI WORKFLOW BLAST RADIUS",
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


def builtin_sca(root: Path, offline: bool) -> list:
    out: list = []
    # Slopsquatting / hallucinated + registry-unreachable (reuses blast_radius).
    if not offline:
        for f in br.package_findings(root):
            out.append(ScanFinding("sca", f.severity, f.title, f.detail,
                                   f.file, f.line, f.fix, "built-in (anti-slopsquatting)"))
    # Curated CVEs for pinned requirements.txt deps.
    for req in root.rglob("requirements*.txt"):
        if check_packages._skip(req):
            continue
        for f in rp.stage1_sca(req):
            if f.rule_id in ("requirements-not-found",):
                continue
            out.append(ScanFinding("sca", ext._norm_sev(f.severity), f.message.split(" (fix")[0],
                                   f.message, _rel(req, root), f.line, f.message,
                                   "built-in (curated CVEs)"))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────

def _from_ext(scan_type: str, rows: list) -> list:
    return [ScanFinding(scan_type, ext._norm_sev(r["severity"]), r["title"],
                        r.get("detail", ""), r.get("file", ""), int(r.get("line") or 0),
                        r.get("fix", ""), r.get("tool", "")) for r in rows]


def run_secrets(root: Path, tools: dict) -> Layer:
    rows = ext.run_gitleaks(root)
    if rows is not None:
        return Layer("secrets", "gitleaks", _from_ext("secrets", rows))
    return Layer("secrets", "built-in", builtin_secrets(root),
                 note=f"install gitleaks for full git-history coverage — {ext.INSTALL_HINTS['gitleaks']}")


def run_sca(root: Path, tools: dict, offline: bool) -> Layer:
    findings: list = []
    engines: list = []
    trivy = ext.run_trivy(root)
    if trivy is not None:
        findings += _from_ext("sca", trivy)
        engines.append("trivy")
    osv = ext.run_osv(root)
    if osv is not None:
        findings += _from_ext("sca", osv)
        engines.append("osv-scanner")
    # Slopsquatting always adds value and needs no external tool.
    findings += builtin_sca(root, offline)
    note = ""
    if not trivy and not osv:
        note = ("install trivy + osv-scanner for CVE and malicious-package detection — "
                f"{ext.INSTALL_HINTS['trivy']}; {ext.INSTALL_HINTS['osv-scanner']}")
    engine = " + ".join(engines + ["built-in"]) if engines else "built-in"
    return Layer("sca", engine, findings, note=note)


def run_sast(root: Path, tools: dict) -> Layer:
    ruleset = Path(__file__).resolve().parent.parent / ".semgrep" / "ai-insecure-defaults.yml"
    rows = ext.run_semgrep(root, extra_config=ruleset)
    if rows is not None:
        return Layer("sast", "semgrep", _from_ext("sast", rows))
    return Layer("sast", "built-in", builtin_sast(root),
                 note=f"install semgrep for full SAST coverage (JS/TS + community rules) — {ext.INSTALL_HINTS['semgrep']}")


def run_ai_posture(root: Path, pol: dict) -> Layer:
    # Apply the repo's secure-ai-pipeline.yml policy so this layer matches the
    # standalone `posture` command (path excludes, rule ignores, MCP allowlist).
    report = policy_mod.apply(br.assess(root, offline=True), pol)
    rows = [ScanFinding("ai_posture", f["severity"], f["title"], f.get("detail", ""),
                        f.get("file", ""), int(f.get("line") or 0), f.get("fix", ""), "built-in")
            for f in report["findings"]]
    return Layer("ai_posture", "built-in", rows)


def run_dast(url: str, tools: dict) -> Layer:
    rules = Path(__file__).resolve().parent.parent / ".zap" / "rules.tsv"
    rows = ext.run_zap(url, rules_file=rules)
    if rows is None:
        return Layer("dast", "unavailable", [],
                     note=f"install ZAP or Docker to run DAST — {ext.INSTALL_HINTS['docker']}")
    return Layer("dast", "zap", _from_ext("dast", rows), note=f"target: {url}")


def orchestrate(root: Path, *, offline: bool, only: list, dast_url: str = "",
                exclude: list = None) -> dict:
    tools = ext.detect()
    pol = policy_mod.load_policy(root)
    excludes = list(pol.get("exclude", []) or []) + list(exclude or [])
    layers: dict = {}
    selected = only or [t for t in TABLE_ORDER if t != "dast"]
    if "secrets" in selected:
        layers["secrets"] = run_secrets(root, tools)
    if "sca" in selected:
        layers["sca"] = run_sca(root, tools, offline)
    if "sast" in selected:
        layers["sast"] = run_sast(root, tools)
    if "ai_posture" in selected:
        layers["ai_posture"] = run_ai_posture(root, pol)
    if dast_url:
        layers["dast"] = run_dast(dast_url, tools)
    # Honor exclude globs (policy file + --exclude) across every layer, so
    # fixture/vendor/test dirs can be silenced uniformly.
    if excludes:
        for lyr in layers.values():
            lyr.findings = [f for f in lyr.findings
                            if not policy_mod._excluded(f.file, excludes)]
    return {"root": str(root), "tools": tools, "layers": layers, "excludes": excludes}


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
        if f.detail:
            out.append(f"      {f.detail.strip().splitlines()[0][:300]}")
        if f.fix:
            out.append(_c("OK", f"      fix: {f.fix.strip().splitlines()[0][:300]}", on))
        out.append("")
    return "\n".join(out)


def render_tools(result: dict, no_color: bool = False) -> str:
    on = _color_on(no_color)
    out = [_c("B", "  Scanner engines", on)]
    for name, role in ext.TOOL_ROLES.items():
        path = result["tools"].get(name)
        if path:
            out.append(f"    {_c('OK', '✓', on)} {name:<14} {_c('DIM', role, on)}")
        else:
            hint = ext.INSTALL_HINTS.get(name, "")
            out.append(f"    {_c('DIM', '·', on)} {name:<14} {_c('DIM', 'not installed — ' + hint, on)}")
    sh = ext.socket_hint()
    if sh:
        out.append(_c("DIM", f"    ⓘ {sh}", on))
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Fix prompts
# ─────────────────────────────────────────────────────────────────────────────

FIX_PROMPT_INTRO = {
    "secrets": "remove every hardcoded secret and replace it with an environment "
               "variable or secrets-manager lookup, then note that the exposed value must be rotated",
    "sca": "upgrade or remove each flagged dependency: patch known-vulnerable versions to "
           "the fixed release, and REMOVE any package flagged malicious or non-existent (slopsquatting)",
    "sast": "fix each insecure code pattern using the secure idiom (parameterised queries, "
            "verify=True, no shell=True, no eval on input, env-gated debug, no hardcoded creds)",
    "dast": "fix each runtime/HTTP issue at the server: add the missing security headers, "
            "secure cookies, and input handling identified by the DAST scan",
    "ai_posture": "harden the AI workflow: pin actions to commit SHAs, remove pull_request_target "
                  "where possible, scope agent permissions, and stop passing secrets to MCP servers",
}


def fix_prompt(scan_type: str, findings: list, root: str) -> str:
    lines = [f"# Fix prompt — {LABELS.get(scan_type, scan_type)}",
             "",
             f"You are a senior application-security engineer. In the repo at `{root}`, "
             f"{FIX_PROMPT_INTRO.get(scan_type, 'fix the security findings below')}.",
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
        if f.fix:
            lines.append(f"  - suggested: {f.fix.strip().splitlines()[0]}")
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
                     f'<div class="d">{html.escape((f.detail or "").splitlines()[0] if f.detail else "")}</div>'
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
    parser.add_argument("--only", default="",
                        help="Comma-separated scan types to run (secrets,sca,sast,ai_posture).")
    parser.add_argument("--exclude", default="",
                        help="Comma-separated path globs to drop from every layer "
                             "(e.g. 'test/**,data/**'). Merged with the policy file's exclude.")
    parser.add_argument("--detail", default="",
                        help="Expand one or more layers: a type, comma-list, or 'all'.")
    parser.add_argument("--dast-url", default="", help="Run a ZAP DAST scan against this URL.")
    parser.add_argument("--no-dast", action="store_true", help="Never prompt for a DAST URL.")
    parser.add_argument("--json", metavar="OUT", help="Write the full result as JSON.")
    parser.add_argument("--html", metavar="OUT", help="Write the clickable HTML report.")
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
                         dast_url=args.dast_url, exclude=cli_excludes)

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
    layer = run_dast(url, result["tools"])
    result["layers"]["dast"] = layer
    print(render_detail(result, "dast", no_color=no_color) if layer.findings
          else _c("DIM", f"    {layer.note or 'no DAST findings'}", on))


if __name__ == "__main__":
    sys.exit(main())
