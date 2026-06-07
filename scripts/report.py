#!/usr/bin/env python3
"""Render a Blast Radius report (the dict from blast_radius.assess) as HTML.

Self-contained — inline CSS, no external assets — so the output is a single file
you can open or attach to a security review.
"""

from __future__ import annotations

import html

SEV_COLOR = {
    "CRITICAL": "#b00020",
    "HIGH": "#d93025",
    "MEDIUM": "#e8710a",
    "LOW": "#80868b",
    "INFO": "#9aa0a6",
}


def _grade_color(score: int) -> str:
    return ("#137333" if score >= 75 else "#e8710a" if score >= 40 else "#b00020")


def render_html(report: dict, title: str = "AI Agent Blast Radius") -> str:
    score = report.get("score", 0)
    grade = report.get("grade", "?")
    counts = report.get("counts", {})
    findings = report.get("findings", [])
    by_cat = report.get("by_category", {})

    chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR[s]}">{counts.get(s,0)} {s}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s, 0)
    ) or '<span class="chip" style="background:#137333">no findings</span>'

    cat_rows = "".join(
        f"<tr><td>{html.escape(cat)}</td>"
        + "".join(f"<td>{c.get(s,0) or ''}</td>" for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"))
        + "</tr>"
        for cat, c in sorted(by_cat.items())
    )

    rows = []
    for f in findings:
        if f.get("severity") == "INFO":
            continue
        loc = html.escape(f.get("file", ""))
        if f.get("line"):
            loc += f":{f['line']}"
        rows.append(f"""
        <div class="finding">
          <div class="fhead">
            <span class="sev" style="background:{SEV_COLOR.get(f['severity'],'#888')}">{f['severity']}</span>
            <span class="ftitle">{html.escape(f['title'])}</span>
            <span class="cat">{html.escape(f.get('category',''))}</span>
          </div>
          <div class="loc">{loc}</div>
          <div class="detail">{html.escape(f.get('detail',''))}</div>
          <div class="fix"><b>Fix:</b> {html.escape(f.get('fix',''))}</div>
        </div>""")
    findings_html = "\n".join(rows) or '<p class="empty">No actionable findings. 🎉</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }}
  body {{ margin: 0; background: #f5f6f7; color: #202124; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .sub {{ color: #5f6368; margin: 0 0 24px; font-size: 13px; }}
  .scorecard {{ display: flex; align-items: center; gap: 24px; background: #fff;
    border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  .score {{ font-size: 56px; font-weight: 700; color: {_grade_color(score)}; line-height: 1; }}
  .score small {{ font-size: 20px; color: #9aa0a6; }}
  .grade {{ font-size: 32px; font-weight: 700; color: {_grade_color(score)};
    border: 3px solid {_grade_color(score)}; border-radius: 10px; padding: 4px 14px; }}
  .chips {{ margin-top: 10px; }}
  .chip {{ color:#fff; border-radius: 999px; padding: 3px 10px; font-size: 12px;
    margin-right: 6px; display: inline-block; }}
  table {{ border-collapse: collapse; width: 100%; background:#fff; margin-top: 20px;
    border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  th, td {{ padding: 8px 12px; text-align: left; font-size: 13px; border-bottom: 1px solid #eee; }}
  th {{ background: #fafafa; color:#5f6368; }}
  td:not(:first-child), th:not(:first-child) {{ text-align: center; width: 70px; }}
  .finding {{ background:#fff; border-radius: 10px; padding: 14px 16px; margin-top: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .fhead {{ display:flex; align-items:center; gap:10px; }}
  .sev {{ color:#fff; font-size: 11px; font-weight:700; border-radius: 4px; padding: 2px 7px; }}
  .ftitle {{ font-weight: 600; }}
  .cat {{ margin-left:auto; color:#9aa0a6; font-size: 12px; }}
  .loc {{ color:#1a73e8; font-family: ui-monospace, Menlo, monospace; font-size: 12px; margin: 4px 0; }}
  .detail {{ font-size: 13px; color:#3c4043; }}
  .fix {{ font-size: 13px; color:#137333; margin-top: 6px; }}
  .empty {{ color:#137333; font-size: 15px; }}
  h2 {{ font-size: 15px; margin: 28px 0 4px; }}
</style></head>
<body><div class="wrap">
  <h1>AI Agent Blast Radius</h1>
  <p class="sub">How far an attacker who gets a foothold in your AI coding workflow can reach. 100 = minimal blast radius.</p>
  <div class="scorecard">
    <div class="score">{score}<small>/100</small></div>
    <div class="grade">{grade}</div>
    <div><div class="chips">{chips}</div></div>
  </div>
  <h2>By category</h2>
  <table><tr><th>Category</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th></tr>
  {cat_rows}</table>
  <h2>Findings</h2>
  {findings_html}
</div></body></html>"""


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("usage: report.py REPORT.json [OUT.html]", file=sys.stderr)
        sys.exit(2)
    data = json.loads(open(sys.argv[1], encoding="utf-8").read())
    out = render_html(data)
    if len(sys.argv) > 2:
        open(sys.argv[2], "w", encoding="utf-8").write(out)
    else:
        sys.stdout.write(out)
