"""Adapters for vector DBs. Each exposes:
- list_collections()
- list_documents(collection)
- query(collection, embedding, k)
- upsert(collection, ids, embeddings, documents, metadatas)
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol


@dataclass
class Document:
    id: str
    text: str
    embedding: list[float]
    metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore(Protocol):
    name: str
    def list_collections(self) -> list[str]: ...
    def list_documents(self, collection: str, limit: int = 1000) -> list[Document]: ...
    def query(self, collection: str, embedding: list[float], k: int = 5) -> list[Document]: ...
    def upsert(self, collection: str, docs: list[Document]) -> None: ...
    def count(self, collection: str) -> int: ...


# ---- ChromaDB adapter ----

class ChromaConnector:
    name = "chromadb"

    def __init__(self, persist_path: str | None = None) -> None:
        import chromadb
        if persist_path:
            self.client = chromadb.PersistentClient(path=persist_path)
        else:
            self.client = chromadb.EphemeralClient()

    def list_collections(self) -> list[str]:
        return [c.name for c in self.client.list_collections()]

    def _coll(self, name: str):
        return self.client.get_or_create_collection(name=name)

    def list_documents(self, collection: str, limit: int = 1000) -> list[Document]:
        c = self._coll(collection)
        got = c.get(limit=limit, include=["documents", "embeddings", "metadatas"])
        out: list[Document] = []
        ids = got.get("ids") or []
        docs = got.get("documents") or [None] * len(ids)
        embs = got.get("embeddings")
        if embs is None:
            embs = [None] * len(ids)
        else:
            try:
                embs = list(embs)
            except Exception:
                embs = [None] * len(ids)
        metas = got.get("metadatas") or [{} for _ in ids]
        for i, _id in enumerate(ids):
            emb = embs[i] if i < len(embs) and embs[i] is not None else []
            try:
                emb = list(emb) if emb is not None else []
            except Exception:
                emb = []
            out.append(Document(
                id=_id, text=docs[i] or "",
                embedding=emb,
                metadata=metas[i] or {},
            ))
        return out

    def query(self, collection: str, embedding: list[float], k: int = 5) -> list[Document]:
        c = self._coll(collection)
        r = c.query(query_embeddings=[embedding], n_results=k,
                    include=["documents", "embeddings", "metadatas", "distances"])
        out: list[Document] = []
        ids = (r["ids"] or [[]])[0]
        docs = (r["documents"] or [[]])[0]
        embs = (r["embeddings"] or [[]])[0]
        metas = (r["metadatas"] or [[]])[0]
        for i, _id in enumerate(ids):
            emb = embs[i] if i < len(embs) else []
            try:
                emb = list(emb) if emb is not None else []
            except Exception:
                emb = []
            out.append(Document(
                id=_id, text=docs[i] if i < len(docs) else "",
                embedding=emb, metadata=metas[i] if i < len(metas) else {},
            ))
        return out

    def upsert(self, collection: str, docs: list[Document]) -> None:
        c = self._coll(collection)
        c.upsert(
            ids=[d.id for d in docs],
            embeddings=[d.embedding for d in docs],
            documents=[d.text for d in docs],
            metadatas=[d.metadata or {"_": "x"} for d in docs],
        )

    def count(self, collection: str) -> int:
        return self._coll(collection).count()


# ---- In-memory adapter (for tests with no extra deps) ----

class InMemoryConnector:
    name = "inmemory"

    def __init__(self) -> None:
        self.collections: dict[str, list[Document]] = {}

    def list_collections(self) -> list[str]:
        return list(self.collections.keys())

    def list_documents(self, collection: str, limit: int = 1000) -> list[Document]:
        return list(self.collections.get(collection, []))[:limit]

    def query(self, collection: str, embedding: list[float], k: int = 5) -> list[Document]:
        import math
        items = self.collections.get(collection, [])
        def cos(a, b):
            n = min(len(a), len(b))
            num = sum(a[i] * b[i] for i in range(n))
            da = math.sqrt(sum(x * x for x in a[:n])) or 1
            db = math.sqrt(sum(x * x for x in b[:n])) or 1
            return num / (da * db)
        ranked = sorted(items, key=lambda d: -cos(d.embedding, embedding))
        return ranked[:k]

    def upsert(self, collection: str, docs: list[Document]) -> None:
        self.collections.setdefault(collection, [])
        existing = {d.id: i for i, d in enumerate(self.collections[collection])}
        for d in docs:
            if d.id in existing:
                self.collections[collection][existing[d.id]] = d
            else:
                self.collections[collection].append(d)

    def count(self, collection: str) -> int:
        return len(self.collections.get(collection, []))
