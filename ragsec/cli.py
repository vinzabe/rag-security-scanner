"""CLI: `ragsec scan --store chroma --collection foo --output report.html`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


# --- standalone-repo shim: add project root to sys.path ---
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.normpath(_os.path.join(_HERE, '..'))

sys.path.insert(0, _PROJECT_ROOT)

from .audits import SEVERITY_RANK, run_full_audit
from .connectors import ChromaConnector, InMemoryConnector
from .report import to_html, to_json, to_sarif


def _embed_fn(client_kind: str = "shared"):
    if client_kind == "hash":
        from llm_client import LLMClient  # type: ignore
        c = LLMClient()
        return lambda texts: c.embed(texts)
    from llm_client import LLMClient  # type: ignore
    c = LLMClient()
    return lambda texts: c.embed(texts)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ragsec",
                                description="RAG security scanner")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("scan", help="Audit a vector DB collection")
    s.add_argument("--store", choices=["chroma", "inmemory"], default="chroma")
    s.add_argument("--persist-path", default=None,
                   help="ChromaDB persistent path (omit for ephemeral)")
    s.add_argument("--collection", required=True)
    s.add_argument("--tenant-field", default="tenant_id")
    s.add_argument("--output", "-o", default="ragsec_report.json")
    s.add_argument("--format", choices=["json", "html", "sarif"], default="json")
    s.add_argument("--fail-on", choices=list(SEVERITY_RANK.keys()),
                   default="critical",
                   help="Exit non-zero if any finding >= this severity")
    args = p.parse_args(argv)

    if args.store == "chroma":
        store = ChromaConnector(args.persist_path)
    else:
        store = InMemoryConnector()
    embed_fn = _embed_fn()
    findings = run_full_audit(store, args.collection, embed_fn, args.tenant_field)
    docs_n = store.count(args.collection)
    ctx = {"store": args.store, "collection": args.collection,
           "document_count": docs_n}
    if args.format == "json":
        text = json.dumps(to_json(findings, ctx), indent=2, default=str)
    elif args.format == "sarif":
        text = json.dumps(to_sarif(findings, ctx), indent=2, default=str)
    else:
        text = to_html(findings, ctx)
    Path(args.output).write_text(text)
    threshold = SEVERITY_RANK[args.fail_on]
    failed = [f for f in findings if SEVERITY_RANK[f.severity] >= threshold]
    print(f"wrote {args.output} ({len(findings)} findings, "
          f"{len(failed)} >= {args.fail_on})")
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
