"""Render audit results as JSON + HTML report + SARIF (for CI gating)."""
from __future__ import annotations

import html
import json
import time
from typing import Iterable

from .audits import Finding, SEVERITY_RANK


def to_json(findings: list[Finding], context: dict) -> dict:
    return {
        "scanner": "ragsec",
        "version": "1.0.0",
        "generated_at": time.time(),
        "context": context,
        "summary": {
            "total": len(findings),
            "by_severity": {
                s: sum(1 for f in findings if f.severity == s)
                for s in ("info", "low", "medium", "high", "critical")
            },
            "by_category": {
                c: sum(1 for f in findings if f.category == c)
                for c in {f.category for f in findings} or {"none"}
            },
        },
        "findings": [f.to_dict() for f in findings],
    }


def to_sarif(findings: list[Finding], context: dict) -> dict:
    """SARIF 2.1.0 — drops into GitHub code-scanning, Defender, etc."""
    sev_map = {"info": "note", "low": "note",
               "medium": "warning", "high": "error", "critical": "error"}
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = f.audit
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": f.title[:120]},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {"level": sev_map[f.severity]},
            "properties": {"category": f.category},
        })
        loc_objs = [
            {"physicalLocation": {
                "artifactLocation": {"uri": f"vector-doc://{aid}"}
            }} for aid in f.affected[:20]
        ] or [{"physicalLocation": {"artifactLocation": {"uri": "vector-collection"}}}]
        results.append({
            "ruleId": rule_id,
            "level": sev_map[f.severity],
            "message": {"text": f.title},
            "locations": loc_objs,
            "properties": {"evidence": f.evidence[:5]},
        })
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ragsec", "version": "1.0.0",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"context": context},
        }],
    }


def to_html(findings: list[Finding], context: dict) -> str:
    rows = []
    for f in findings:
        sev_color = {"critical": "#f85149", "high": "#f0883e",
                     "medium": "#d29922", "low": "#3fb950",
                     "info": "#58a6ff"}[f.severity]
        ev = json.dumps(f.evidence[:3], indent=1)[:1200]
        rows.append(f"""
<tr>
  <td><span style="background:{sev_color};color:#000;padding:2px 8px;
        border-radius:3px">{f.severity.upper()}</span></td>
  <td>{html.escape(f.category)}</td>
  <td><b>{html.escape(f.title)}</b><br>
      <small>{html.escape(f.description)}</small></td>
  <td><code style="font-size:11px;white-space:pre-wrap;display:block;
       max-width:500px;overflow:auto">{html.escape(ev)}</code></td>
  <td>{len(f.affected)}</td>
</tr>""")
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return f"""<!doctype html><html><head><title>RAG Security Audit</title>
<style>
body{{font-family:system-ui;background:#0d1117;color:#c9d1d9;
max-width:1400px;margin:2em auto;padding:0 1em}}
h1,h2{{color:#58a6ff}}
table{{border-collapse:collapse;width:100%;margin:1em 0}}
th,td{{border:1px solid #30363d;padding:8px 10px;text-align:left;
vertical-align:top;font-size:13px}}
th{{background:#161b22}}
.kpi{{display:inline-block;background:#161b22;padding:1em;margin:.5em;
border-radius:6px;min-width:120px;text-align:center}}
.kpi b{{font-size:1.6em;display:block}}
code{{background:#161b22;padding:2px 5px;border-radius:3px}}
</style></head><body>
<h1>RAG Security Scan Report</h1>
<p><b>Scanner:</b> ragsec 1.0.0
&nbsp;|&nbsp; <b>Store:</b> {html.escape(str(context.get('store')))}
&nbsp;|&nbsp; <b>Collection:</b> {html.escape(str(context.get('collection')))}
&nbsp;|&nbsp; <b>Documents:</b> {context.get('document_count', 'n/a')}
</p>
<div>
{''.join(f'<div class=kpi style="border:1px solid {{c:s}}">'
          f'{s.upper()}<b>{counts[s]}</b></div>'
          for s, c in [("critical","#f85149"),("high","#f0883e"),
                       ("medium","#d29922"),("low","#3fb950"),("info","#58a6ff")])}
</div>
<h2>Findings ({len(findings)})</h2>
<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th>
<th>Evidence</th><th>Affected</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
