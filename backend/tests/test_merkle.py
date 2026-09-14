"""
Tests for Merkle Tree implementation and tamper-evident verification.
"""

from backend.integrity.merkle import MerkleTree
import hashlib


def test_merkle_tree_construction():
    hashes = [
        hashlib.sha256(b"event 1").hexdigest(),
        hashlib.sha256(b"event 2").hexdigest(),
        hashlib.sha256(b"event 3").hexdigest(),
        hashlib.sha256(b"event 4").hexdigest(),
    ]

    tree = MerkleTree(hashes)
    assert tree.root != ""
    assert len(tree.root) == 64

    # Verification with same hashes succeeds
    is_valid, computed_root = tree.verify(hashes)
    assert is_valid is True
    assert computed_root == tree.root


def test_merkle_tamper_detection():
    hashes = [
        hashlib.sha256(b"event 1").hexdigest(),
        hashlib.sha256(b"event 2").hexdigest(),
        hashlib.sha256(b"event 3").hexdigest(),
    ]

    tree = MerkleTree(hashes)
    original_root = tree.root

    # Tamper one event hash
    tampered_hashes = list(hashes)
    tampered_hashes[1] = hashlib.sha256(b"tampered event 2").hexdigest()

    is_valid, computed_root = tree.verify(tampered_hashes)
    assert is_valid is False
    assert computed_root != original_root
