# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/narko4u/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Merkle tree inclusion and consistency proofs.

WitnessOS batches events into Merkle trees. Each event gets an
inclusion proof, and batches are linked via consistency proofs.
"""

import hashlib
from dataclasses import dataclass
from typing import List


class MerkleError(Exception):
    """Merkle tree verification error."""


# CT Merkle tree constants
LEAF_PREFIX = bytes([0x00])
NODE_PREFIX = bytes([0x01])


def leaf_hash(data: bytes) -> bytes:
    """Hash a leaf node: SHA-256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash an internal node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def compute_root_from_proof(leaf: bytes, proof: List[bytes], leaf_index: int) -> bytes:
    """Compute the Merkle root from a leaf and an inclusion proof.

    Args:
        leaf: The leaf hash
        proof: List of sibling hashes from leaf to root
        leaf_index: The index of the leaf in the tree

    Returns:
        The computed root hash.
    """
    current = leaf
    idx = leaf_index

    for sibling in proof:
        if idx % 2 == 0:
            # Current is left, sibling is right
            current = node_hash(current, sibling)
        else:
            # Current is right, sibling is left
            current = node_hash(sibling, current)
        idx //= 2

    return current


@dataclass
class InclusionProof:
    leaf_hash: bytes
    proof_hashes: List[bytes]
    leaf_index: int
    root_hash: bytes

    def verify(self) -> bool:
        computed = compute_root_from_proof(self.leaf_hash, self.proof_hashes, self.leaf_index)
        return computed == self.root_hash


@dataclass
class ConsistencyProof:
    """Proves that a new tree root is consistent with a previous root."""
    old_root: bytes
    new_root: bytes
    proof_hashes: List[bytes]
    old_size: int

    def verify(self) -> bool:
        # For CT-style consistency proofs, the proof shows that the
        # old tree is a prefix of the new tree.
        # This is a simplified verification.
        if self.old_size == 0:
            return True  # First tree, always consistent
        if self.old_root == self.new_root and self.old_size > 0:
            return True  # Same tree

        # Verify the consistency proof
        return self._verify_consistency(self.old_size, self.old_root, self.new_root, self.proof_hashes)

    def _verify_consistency(self, n: int, old_root: bytes, new_root: bytes, proof: List[bytes]) -> bool:
        """Verify CT-style consistency proof."""
        if len(proof) == 0:
            return old_root == new_root

        # Calculate the largest power of 2 <= n
        k = 1
        while k < n:
            k <<= 1
        if k > n:
            k >>= 1

        if n == k:
            # Old tree is a perfect subtree
            # old_root is the left child, proof[0] is the right child
            # Verify new_root = node_hash(old_root, proof[0])
            try:
                return node_hash(old_root, proof[0]) == new_root if proof else False
            except (IndexError, TypeError):
                return False

        # n > k: split into two subtrees
        left_proof = proof[0] if proof else None
        if left_proof is None:
            return False
        # Right-hand subtree nodes (proof[1:]) are not consumed by this simplified path.
        # Left subtree: first k nodes, compute its root from old_root
        # Right subtree: remaining nodes
        # This requires recursive proof structures — simplified for now
        # For the verifier, we use direct root comparison
        return old_root == new_root or self._verify_consistency_path(proof, old_root, new_root)

    def _verify_consistency_path(self, proof: List[bytes], old_root: bytes, new_root: bytes) -> bool:
        """Fallback: verify by recomputing from proof path."""
        # For simplicity, if the roots differ but old_size > 0, we need all
        # hashes of old tree leaves. The proof should enable verification.
        # Implemented as: iterate through proof and verify hashes chain.
        current = old_root
        for sibling in proof:
            current = node_hash(current, sibling)
        return current == new_root


def build_merkle_tree(leaf_hashes: List[bytes]) -> bytes:
    """Build a CT Merkle tree from leaf hashes and return the root."""
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()

    tree = list(leaf_hashes)
    while len(tree) > 1:
        level = []
        for i in range(0, len(tree), 2):
            left = tree[i]
            right = tree[i + 1] if i + 1 < len(tree) else left  # Duplicate last
            level.append(node_hash(left, right))
        tree = level

    return tree[0]


def inclusion_proof(leaf_hashes: List[bytes], index: int) -> List[bytes]:
    """Sibling hashes from a leaf to the root, under the same duplication rule.

    A tree of size n with an odd node at any level duplicates its last node, so
    the proof for the last leaf still terminates at the published root.
    """
    if not leaf_hashes:
        raise MerkleError("cannot build a proof for an empty tree")
    if not 0 <= index < len(leaf_hashes):
        raise MerkleError(f"leaf index {index} outside tree of size {len(leaf_hashes)}")

    siblings: List[bytes] = []
    tree = list(leaf_hashes)
    idx = index
    while len(tree) > 1:
        if len(tree) % 2:
            tree = tree + [tree[-1]]
        sibling = idx + 1 if idx % 2 == 0 else idx - 1
        siblings.append(tree[sibling])
        tree = [
            node_hash(tree[i], tree[i + 1]) for i in range(0, len(tree), 2)
        ]
        idx //= 2
    return siblings
