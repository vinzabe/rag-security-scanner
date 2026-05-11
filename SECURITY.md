# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **RAG Security Scanner**,
please report it privately. Do **not** open a public GitHub issue.

**Email:** security@vinzabe.dev (or open a GitHub Security Advisory)

Please include:
- A clear description of the issue
- Steps to reproduce (PoC preferred)
- The version / commit SHA you tested against
- Any suggested mitigation

We aim to acknowledge new reports within **72 hours** and to publish a
fix or mitigation within **30 days** for high-severity issues.

## Scope

In scope:
- False negatives in PII / secret detection (a leaked AWS key the
  scanner misses) — **highest priority**
- Cross-tenant retrieval audit failing to detect known leaks
- Hidden-text payload (zero-width / homoglyph) detection bypass
- Audit results that don't reflect the actual store contents
  (consistency bugs)
- SARIF / HTML output XSS or injection
- Path traversal via `--persist-path`

Out of scope:
- Scanner cannot detect *all* poisoning attacks — it is heuristic
- Issues that require write access to the vector store (the scanner is
  read-only)

## Critical safety warning

**The scanner reads from production vector stores.** Findings may
include real PII, secrets, or proprietary content. The HTML/SARIF
report **embeds excerpts of the offending content** so operators can
triage. Treat scan reports as **TLP:RED** and store them with the same
sensitivity as the source store.

Recommended workflow:
1. Scan against a **read replica** if possible
2. Run scanner with a **service account** that has read-only RBAC
3. Pipe results to a SIEM / DLP queue, not to a public CI artifact
4. Set `--fail-on critical` in CI to block deploys on tenant leakage

## Threat model

We assume:
- The vector store contains untrusted user-uploaded content
  (RAG corpora are full of attacker-controlled data)
- Adversaries may attempt to:
  - Inject prompt-override text into documents (poisoning)
  - Hide payloads via zero-width chars, homoglyphs, base64
  - Monopolize retrieval by submitting many near-duplicate embeddings
  - Cross-tenant retrieval via missing or wrong metadata
- The host running the scanner is trusted

## Hardening checklist for production deployments

- [ ] Run scanner with a **read-only** service account on the store
- [ ] Store scan reports in a TLP:RED-classified bucket
- [ ] Encrypt reports at rest
- [ ] Run on a schedule (daily) and alert on critical findings via
      webhook integration
- [ ] If using ChromaDB persistent mode, ensure `--persist-path` is
      not user-controllable (avoid path traversal at the orchestration
      layer)
- [ ] When integrating with CI, mask report artifacts and pass only
      the SARIF summary to non-trusted runners

## Supply chain

- All Python deps are pinned via `requirements.txt`
- ChromaDB and sentence-transformers are large; consider a slim
  container image that excludes optional extras

## Contact

Responsible disclosure: **g@abejar.net**
