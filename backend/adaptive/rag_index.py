"""
Lightweight local RAG using TF-IDF — no internet downloads required.
Provides vector retrieval over historical parser templates.

Classification: IMPLEMENTED (TF-IDF retrieval, fully offline)
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any


class TFIDFIndex:
    """
    Simple TF-IDF vector index for document similarity search.
    Pure Python, no external dependencies, fully offline.
    """

    def __init__(self):
        self.documents: dict[str, dict[str, Any]] = {}  # doc_id -> {text, metadata, tf}
        self.idf: dict[str, float] = {}
        self.vocab: set[str] = set()
        self._dirty = True

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple tokenization: lowercase, split on non-alphanumeric."""
        return re.findall(r"[a-z0-9_]+", text.lower())

    def add_document(self, doc_id: str, text: str, metadata: dict[str, Any] | None = None):
        """Add a document to the index."""
        tokens = self._tokenize(text)
        tf = Counter(tokens)
        total = len(tokens) if tokens else 1
        # Normalize TF
        tf_norm = {term: count / total for term, count in tf.items()}
        self.documents[doc_id] = {
            "text": text,
            "metadata": metadata or {},
            "tf": tf_norm,
            "tokens": set(tokens),
        }
        self.vocab.update(tokens)
        self._dirty = True

    def _rebuild_idf(self):
        """Rebuild IDF scores."""
        if not self._dirty:
            return
        n = len(self.documents)
        if n == 0:
            return
        doc_freq: Counter[str] = Counter()
        for doc in self.documents.values():
            doc_freq.update(doc["tokens"])
        self.idf = {
            term: math.log((n + 1) / (df + 1)) + 1
            for term, df in doc_freq.items()
        }
        self._dirty = False

    def _tfidf_vector(self, tf: dict[str, float]) -> dict[str, float]:
        """Compute TF-IDF vector."""
        return {
            term: tf_val * self.idf.get(term, 0)
            for term, tf_val in tf.items()
        }

    @staticmethod
    def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
        """Compute cosine similarity between two sparse vectors."""
        common_terms = set(vec_a.keys()) & set(vec_b.keys())
        if not common_terms:
            return 0.0
        dot = sum(vec_a[t] * vec_b[t] for t in common_terms)
        norm_a = math.sqrt(sum(v ** 2 for v in vec_a.values()))
        norm_b = math.sqrt(sum(v ** 2 for v in vec_b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def search(self, query: str, top_k: int = 3) -> list[tuple[str, float, dict[str, Any]]]:
        """
        Search for similar documents.
        Returns: [(doc_id, similarity, metadata), ...]
        """
        self._rebuild_idf()

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        query_tf = Counter(query_tokens)
        total = len(query_tokens)
        query_tf_norm = {term: count / total for term, count in query_tf.items()}
        query_vec = self._tfidf_vector(query_tf_norm)

        results = []
        for doc_id, doc in self.documents.items():
            doc_vec = self._tfidf_vector(doc["tf"])
            sim = self._cosine_similarity(query_vec, doc_vec)
            if sim > 0:
                results.append((doc_id, sim, doc["metadata"]))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]


class ParserRAG:
    """
    RAG over historical parser templates.
    Uses TF-IDF for retrieval — no internet downloads required.

    Classification: IMPLEMENTED (fully offline)
    """

    def __init__(self):
        self.index = TFIDFIndex()
        self._seeded = False

    def seed_known_templates(self):
        """Seed with known parser templates."""
        if self._seeded:
            return

        from backend.parsers.templates import KNOWN_PARSERS

        for parser_id, (name, spec) in KNOWN_PARSERS.items():
            # Build a text representation for retrieval
            text = f"{spec.template} {' '.join(spec.fields.keys())} {' '.join(spec.fields.values())}"
            self.index.add_document(
                doc_id=parser_id,
                text=text,
                metadata={
                    "template_id": parser_id,
                    "source": spec.source_hint,
                    "spec": spec.model_dump(),
                    "previously_validated": True,
                    "name": name,
                },
            )

        self._seeded = True

    def add_template(self, parser_id: str, spec: Any):
        """Add a new validated template to the RAG index."""
        from backend.models import ParserSpecification
        if isinstance(spec, ParserSpecification):
            text = f"{spec.template} {' '.join(spec.fields.keys())} {' '.join(spec.fields.values())}"
            self.index.add_document(
                doc_id=parser_id,
                text=text,
                metadata={
                    "template_id": parser_id,
                    "source": spec.source_hint,
                    "spec": spec.model_dump(),
                    "previously_validated": True,
                },
            )

    def retrieve_similar(self, log_line: str, top_k: int = 3) -> list[dict[str, Any]]:
        """
        Retrieve similar historical templates for a log line.
        Returns list of {template_id, similarity, source, spec, previously_validated}
        """
        self.seed_known_templates()
        results = self.index.search(log_line, top_k=top_k)

        return [
            {
                "template_id": doc_id,
                "similarity": round(sim, 4),
                "source": meta.get("source", ""),
                "spec": meta.get("spec", {}),
                "previously_validated": meta.get("previously_validated", False),
                "name": meta.get("name", doc_id),
            }
            for doc_id, sim, meta in results
        ]
