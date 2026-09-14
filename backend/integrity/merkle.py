"""
Merkle tree for tamper-evident verification.
Classification: IMPLEMENTED
"""

from __future__ import annotations

import hashlib


class MerkleTree:
    """SHA-256 Merkle tree for integrity verification."""

    def __init__(self, hashes: list[str]):
        self.leaves = list(hashes)
        self.tree: list[list[str]] = []
        self.root = ""
        if hashes:
            self._build()

    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        return hashlib.sha256(f"{left}{right}".encode()).hexdigest()

    @staticmethod
    def hash_single(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def _build(self):
        """Build Merkle tree from leaves upward."""
        if not self.leaves:
            return

        current_level = list(self.leaves)
        self.tree.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self.hash_pair(left, right))
            self.tree.append(next_level)
            current_level = next_level

        self.root = current_level[0] if current_level else ""

    def verify(self, hashes: list[str]) -> tuple[bool, str]:
        """
        Recompute tree from hashes and compare root.
        Returns: (is_valid, computed_root)
        """
        recomputed = MerkleTree(hashes)
        return recomputed.root == self.root, recomputed.root

    def get_proof(self, index: int) -> list[tuple[str, str]]:
        """Get Merkle proof path for a leaf at given index."""
        if not self.tree or index >= len(self.leaves):
            return []

        proof = []
        idx = index
        for level in self.tree[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                direction = "right"
            else:
                sibling_idx = idx - 1
                direction = "left"

            if sibling_idx < len(level):
                proof.append((level[sibling_idx], direction))
            idx //= 2

        return proof
