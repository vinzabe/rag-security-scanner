# RAG Security Scanner

Audits vector databases (ChromaDB, in-memory, plus a clean abstraction
ready for Pinecone/Qdrant/Weaviate) for the most common RAG security
flaws — there's no mature open-source tool that does this today.

## Audits

| Audit | Category | Severity |
|---|---|---|
| `poisoned_text_injection_phrases` | poisoning | high |
| `hidden_text_payloads` (zero-width / homoglyphs) | poisoning | high |
| `embedding_norm_outliers` | poisoning | medium |
| `near_duplicate_embeddings` (retrieval monopolization) | poisoning | medium |
| `pii_*` (SSN, credit-card, AWS/OpenAI/GitHub keys, private keys, emails) | leakage | critical/low |
| `missing_tenant_metadata` | leakage | high |
| `cross_tenant_retrieval_leakage` | leakage | critical |
| `retrieval_returns_injection` (red-team probes) | retrieval_injection | critical |
| `empty_documents` / `missing_embeddings` / `oversized_chunks` | hygiene | low/medium/info |

## Install

```bash
git clone https://github.com/vinzabe/rag-security-scanner.git
cd rag-security-scanner
pip install -r requirements.txt
```

## CLI

```bash
# Audit a ChromaDB collection
python -m ragsec.cli scan --store chroma \
    --persist-path /var/lib/chroma --collection knowledge \
    --format html -o report.html

# Output SARIF for CI gating
python -m ragsec.cli scan --store chroma --collection knowledge \
    --format sarif -o report.sarif --fail-on high
```

Exit code `2` if any finding ≥ `--fail-on`.

## Test
```bash
python tests/test_ragsec.py
```

11/11 tests pass against ChromaDB + in-memory backends.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

## License

MIT — see [LICENSE](./LICENSE).
