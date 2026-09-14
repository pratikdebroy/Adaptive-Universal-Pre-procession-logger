"""
Drain-style template miner — Tier 1 adaptive parsing.
Custom implementation (~200 lines), no external dependencies.

Classification: IMPLEMENTED
"""

from __future__ import annotations

import re
from typing import Any

from backend.config import settings


class LogCluster:
    """A cluster of log lines sharing the same template pattern."""

    def __init__(self, tokens: list[str], cluster_id: int):
        self.template = list(tokens)
        self.cluster_id = cluster_id
        self.size = 1

    def get_template_str(self) -> str:
        return " ".join(self.template)

    def __repr__(self):
        return f"<Cluster #{self.cluster_id} (size={self.size}): {self.get_template_str()}>"


class DrainNode:
    """Internal node of the Drain parse tree."""

    def __init__(self):
        self.children: dict[Any, DrainNode] = {}
        self.clusters: list[LogCluster] = []


class DrainMiner:
    """
    Simplified but functional Drain algorithm for log template mining.
    Tree structure: Root → Length node → Token prefix nodes → Leaf with clusters.
    """

    def __init__(
        self,
        depth: int = 4,
        sim_th: float = 0.5,
        max_children: int = 100,
    ):
        self.depth = depth
        self.sim_th = sim_th
        self.max_children = max_children
        self.root = DrainNode()
        self.clusters: list[LogCluster] = []
        self._next_id = 1

    @staticmethod
    def preprocess(log_line: str) -> list[str]:
        """Tokenize by whitespace."""
        return log_line.strip().split()

    @staticmethod
    def _has_digits(token: str) -> bool:
        return bool(re.search(r"\d", token))

    def _tree_search(self, tokens: list[str]) -> list[LogCluster]:
        """Traverse tree to find candidate clusters."""
        curr = self.root
        length = len(tokens)

        # Layer 2: length
        if length not in curr.children:
            return []
        curr = curr.children[length]

        # Layers 3..depth-1: prefix tokens
        for i in range(self.depth - 2):
            if i >= length:
                break
            token = tokens[i]
            if self._has_digits(token):
                if "*" in curr.children:
                    curr = curr.children["*"]
                else:
                    return []
            elif token in curr.children:
                curr = curr.children[token]
            elif "*" in curr.children:
                curr = curr.children["*"]
            else:
                return []

        return curr.clusters

    def _similarity(self, template: list[str], tokens: list[str]) -> tuple[float, int]:
        """
        Drain similarity: count of matching non-wildcard tokens / total tokens.
        Wildcard <*> does NOT count as a match.
        """
        if len(template) != len(tokens):
            return 0.0, 0
        sim_count = 0
        non_wildcard = 0
        for t, s in zip(template, tokens):
            if t == "<*>":
                continue
            non_wildcard += 1
            if t == s:
                sim_count += 1
        total = len(tokens)
        return (sim_count / total if total > 0 else 0.0), non_wildcard

    def _find_best(self, candidates: list[LogCluster], tokens: list[str]) -> tuple[LogCluster | None, float]:
        """Find best matching cluster above threshold."""
        best = None
        best_sim = -1.0
        best_nwc = -1

        for cluster in candidates:
            sim, nwc = self._similarity(cluster.template, tokens)
            if sim >= self.sim_th:
                if sim > best_sim or (sim == best_sim and nwc > best_nwc):
                    best_sim = sim
                    best_nwc = nwc
                    best = cluster

        return best, best_sim

    def add_log_message(self, log_line: str) -> tuple[LogCluster | None, bool]:
        """Online ingestion: match or create cluster. Returns (cluster, is_new)."""
        tokens = self.preprocess(log_line)
        if not tokens:
            return None, False

        candidates = self._tree_search(tokens)
        best, sim = self._find_best(candidates, tokens)

        if best is not None:
            # Update template with wildcards where tokens differ
            for i in range(len(tokens)):
                if best.template[i] != tokens[i]:
                    best.template[i] = "<*>"
            best.size += 1
            return best, False
        else:
            # Create new cluster
            cluster = LogCluster(tokens, self._next_id)
            self._next_id += 1
            self.clusters.append(cluster)
            self._insert(tokens, cluster)
            return cluster, True

    def _insert(self, tokens: list[str], cluster: LogCluster):
        """Insert cluster into parse tree."""
        curr = self.root
        length = len(tokens)

        if length not in curr.children:
            curr.children[length] = DrainNode()
        curr = curr.children[length]

        for i in range(self.depth - 2):
            if i >= length:
                break
            token = tokens[i]
            if self._has_digits(token):
                key = "*"
            elif token in curr.children:
                key = token
            elif len(curr.children) < self.max_children:
                key = token
            else:
                key = "*"
            if key not in curr.children:
                curr.children[key] = DrainNode()
            curr = curr.children[key]

        curr.clusters.append(cluster)

    def match(self, log_line: str) -> tuple[LogCluster | None, float]:
        """Match without modifying tree (read-only mode)."""
        tokens = self.preprocess(log_line)
        if not tokens:
            return None, 0.0
        candidates = self._tree_search(tokens)
        return self._find_best(candidates, tokens)

    def extract_variables(self, log_line: str, cluster: LogCluster) -> list[str]:
        """Extract variable values from a log line using the cluster template."""
        tokens = self.preprocess(log_line)
        if len(tokens) != len(cluster.template):
            return []
        return [tokens[i] for i in range(len(tokens)) if cluster.template[i] == "<*>"]

    def detect_drift(self, log_line: str) -> dict[str, Any]:
        """
        Inference mode: evaluate log against existing templates without modification.
        """
        tokens = self.preprocess(log_line)
        if not tokens:
            return {"status": "EMPTY"}

        candidates = self._tree_search(tokens)
        if not candidates:
            return {
                "status": "DRIFT_NOVEL",
                "reason": "No tree path found (unseen token length or prefix)",
            }

        best, sim = self._find_best(candidates, tokens)
        if best is None:
            return {
                "status": "DRIFT_NOVEL",
                "reason": f"Below similarity threshold ({self.sim_th})",
            }

        # Check for mutations
        mutations = [
            tokens[i] for i in range(len(tokens))
            if best.template[i] != "<*>" and best.template[i] != tokens[i]
        ]

        if mutations:
            return {
                "status": "DRIFT_MUTATION",
                "cluster_id": best.cluster_id,
                "template": best.get_template_str(),
                "similarity": sim,
                "mutated_tokens": mutations,
            }

        variables = self.extract_variables(log_line, best)
        return {
            "status": "MATCHED",
            "cluster_id": best.cluster_id,
            "template": best.get_template_str(),
            "similarity": sim,
            "variables": variables,
        }


class Tier1Matcher:
    """
    Tier 1: Custom Bidirectional Template Matching (BDPT).
    Combines Drain-style tree mining with custom bidirectional scanning:
      - Front-side scanning (prefix constants / headers)
      - Back-side scanning (suffix constants / status / actions)
      - Variable position alignment (<*> slots)
      - Structural similarity diagnostics (matched, similarities, reasons)
    """

    def __init__(self):
        self.miner = DrainMiner(
            depth=settings.drain_depth,
            sim_th=settings.drain_sim_threshold,
            max_children=settings.drain_max_children,
        )
        self._seed_known_templates()

    def _seed_known_templates(self):
        """Pre-load known log formats into the miner."""
        known_logs = [
            "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW",
            "SRC=192.168.1.100 DST=10.0.0.1 PROTO=UDP DPT=53 ACTION=ALLOW",
            "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
            "%LINK-5-CHANGED: Interface Serial0/0, changed state to administratively down",
            '[**] [1:2001:3] ET SCAN Potential SSH Scan [**] {TCP} 192.168.1.100:45123 -> 10.0.0.1:22',
        ]
        for log in known_logs:
            self.miner.add_log_message(log)

    @staticmethod
    def _token_matches(msg_tok: str, tmpl_tok: str) -> bool:
        """Evaluate structural token equality or key=<*> slot alignment."""
        if tmpl_tok == "<*>":
            return True
        if tmpl_tok == msg_tok:
            return True
        if "=" in tmpl_tok and "=" in msg_tok:
            tmpl_key = tmpl_tok.split("=", 1)[0]
            msg_key = msg_tok.split("=", 1)[0]
            if tmpl_key == msg_key:
                tmpl_val = tmpl_tok.split("=", 1)[1]
                if tmpl_val == "<*>":
                    return True
                msg_val = msg_tok.split("=", 1)[1]
                return tmpl_val == msg_val
        return False

    def _bidirectional_scan(
        self, tokens: list[str], tmpl_tokens: list[str]
    ) -> tuple[float, float, float, list[str]]:
        """
        Execute front-side and back-side structural scans between tokens and a template.
        Returns: (front_sim, back_sim, overall_sim, drift_tokens)
        """
        total = max(len(tokens), len(tmpl_tokens))
        if total == 0:
            return 0.0, 0.0, 0.0, []

        min_len = min(len(tokens), len(tmpl_tokens))

        # 1. Front-side scan (prefix tokens)
        front_matches = 0
        drift_tokens = []
        for i in range(min_len):
            if self._token_matches(tokens[i], tmpl_tokens[i]):
                front_matches += 1
            else:
                drift_tokens.append(f"{tokens[i]} ≠ {tmpl_tokens[i]}")

        # 2. Back-side scan (suffix tokens)
        back_matches = 0
        for j in range(min_len):
            if self._token_matches(tokens[-(j + 1)], tmpl_tokens[-(j + 1)]):
                back_matches += 1

        front_sim = front_matches / total
        back_sim = back_matches / total
        overall_sim = (front_sim + back_sim) / 2.0

        return front_sim, back_sim, overall_sim, drift_tokens

    def match(self, message: str) -> tuple[bool, float, dict[str, Any]]:
        """
        Evaluate log message against known templates using Custom BDPT.
        Returns: (confident, similarity_score, diagnostic_detail)
        """
        tokens = DrainMiner.preprocess(message)
        if not tokens:
            return False, 0.0, {
                "tier": "TIER-1 TEMPLATE MATCHING (BDPT)",
                "status": "EMPTY",
                "matched": False,
                "similarity": 0.0,
                "front_similarity": 0.0,
                "back_similarity": 0.0,
                "reason": "Empty message tokens",
            }

        # Find best matching candidate cluster via Drain tree
        drain_result = self.miner.detect_drift(message)
        best_cluster, _ = self.miner.match(message)

        # Fallback to all clusters if Drain tree didn't find path
        clusters = [best_cluster] if best_cluster else self.miner.clusters

        best_sim = -1.0
        best_front = 0.0
        best_back = 0.0
        best_tmpl = ""
        best_drifts: list[str] = []
        best_cluster_obj: LogCluster | None = None

        for cluster in clusters:
            if cluster is None:
                continue
            f_sim, b_sim, o_sim, drifts = self._bidirectional_scan(tokens, cluster.template)
            if o_sim > best_sim:
                best_sim = o_sim
                best_front = f_sim
                best_back = b_sim
                best_tmpl = cluster.get_template_str()
                best_drifts = drifts
                best_cluster_obj = cluster

        if best_sim < 0.0:
            best_sim = 0.0

        threshold = settings.structural_confidence_threshold
        confident = best_sim >= threshold and best_cluster_obj is not None

        variables = []
        if best_cluster_obj:
            variables = self.miner.extract_variables(message, best_cluster_obj)

        if confident:
            reason = (
                f"BDPT Match: Front ({best_front:.2f}) and back ({best_back:.2f}) tokens "
                f"align with template '{best_tmpl}' (similarity: {best_sim:.2f} >= {threshold})"
            )
            status = "MATCHED"
        else:
            drift_summary = f" Drift: [{', '.join(best_drifts[:3])}]" if best_drifts else ""
            reason = (
                f"BDPT Miss: Structural tokens drifted{drift_summary} "
                f"(front: {best_front:.2f}, back: {best_back:.2f}, similarity: {best_sim:.2f} < {threshold})"
            )
            status = drain_result.get("status", "DRIFT_DETECTED")

        return confident, best_sim, {
            "tier": "TIER-1 TEMPLATE MATCHING (BDPT)",
            "status": status,
            "matched": confident,
            "candidate_template": best_tmpl,
            "similarity": round(best_sim, 4),
            "front_similarity": round(best_front, 4),
            "back_similarity": round(best_back, 4),
            "reason": reason,
            "variables": variables,
        }

