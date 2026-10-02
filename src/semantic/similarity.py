"""Deterministic cosine similarity computations for ScamShield AI.

Provides mathematical utilities for:
- Vector-to-vector cosine similarity
- Vector-to-matrix top-K ranking
- Matrix-to-matrix batch similarity
Guarantees unit normalization, numerical stability, and [-1.0, 1.0] bounding.
"""

from typing import Tuple, Union
import numpy as np


def ensure_unit_norm(vec: np.ndarray, eps: float = 1e-12) -> np.ndarray:
    """Normalizes vector or matrix rows to unit L2 norm.

    Args:
        vec: 1D vector (dim,) or 2D matrix (N, dim).
        eps: Small epsilon to prevent division by zero.

    Returns:
        L2 unit-normalized array with identical shape.
    """
    if vec.ndim == 1:
        norm = np.linalg.norm(vec)
        if norm < eps:
            return np.zeros_like(vec)
        return vec / norm
    elif vec.ndim == 2:
        norms = np.linalg.norm(vec, axis=1, keepdims=True)
        norms = np.where(norms < eps, 1.0, norms)
        return vec / norms
    else:
        raise ValueError(f"Expected 1D or 2D array, got {vec.ndim}D array")


def compute_cosine_similarity(
    vec_a: np.ndarray,
    vec_b: np.ndarray,
    assume_normalized: bool = False,
) -> float:
    """Calculates cosine similarity between two 1D vectors.

    Args:
        vec_a: First vector of shape (D,).
        vec_b: Second vector of shape (D,).
        assume_normalized: If True, skips L2 normalization and computes direct dot product.

    Returns:
        Cosine similarity scalar float clamped to [-1.0, 1.0].
    """
    if vec_a.shape != vec_b.shape:
        raise ValueError(
            f"Shape mismatch: vec_a shape {vec_a.shape} vs vec_b shape {vec_b.shape}"
        )

    if not assume_normalized:
        u = ensure_unit_norm(vec_a)
        v = ensure_unit_norm(vec_b)
    else:
        u, v = vec_a, vec_b

    sim = float(np.dot(u, v))
    return float(np.clip(sim, -1.0, 1.0))


def compute_similarity_1d_to_2d(
    query: np.ndarray,
    ref_matrix: np.ndarray,
    assume_normalized: bool = False,
) -> np.ndarray:
    """Calculates cosine similarity between a single query vector and a matrix of reference vectors.

    Args:
        query: 1D query vector of shape (D,).
        ref_matrix: 2D reference matrix of shape (N, D).
        assume_normalized: If True, assumes query and ref_matrix rows are already unit normalized.

    Returns:
        1D array of similarity scores of shape (N,) clamped to [-1.0, 1.0].
    """
    if query.ndim != 1:
        raise ValueError(f"Expected 1D query vector, got ndim={query.ndim}")
    if ref_matrix.ndim != 2:
        raise ValueError(f"Expected 2D reference matrix, got ndim={ref_matrix.ndim}")
    if query.shape[0] != ref_matrix.shape[1]:
        raise ValueError(
            f"Dimension mismatch: query dim {query.shape[0]} != ref dim {ref_matrix.shape[1]}"
        )

    if not assume_normalized:
        q = ensure_unit_norm(query)
        r = ensure_unit_norm(ref_matrix)
    else:
        q, r = query, ref_matrix

    sims = np.dot(r, q)
    return np.clip(sims, -1.0, 1.0)


def compute_similarity_matrix(
    queries: np.ndarray,
    ref_matrix: np.ndarray,
    assume_normalized: bool = False,
) -> np.ndarray:
    """Calculates cosine similarity between M query vectors and N reference vectors.

    Args:
        queries: 2D matrix of shape (M, D).
        ref_matrix: 2D matrix of shape (N, D).
        assume_normalized: If True, skips normalization.

    Returns:
        2D matrix of shape (M, N) containing cosine similarity scores.
    """
    if queries.ndim != 2 or ref_matrix.ndim != 2:
        raise ValueError("Both queries and ref_matrix must be 2D arrays")
    if queries.shape[1] != ref_matrix.shape[1]:
        raise ValueError("Embedding dimensions must match")

    if not assume_normalized:
        q = ensure_unit_norm(queries)
        r = ensure_unit_norm(ref_matrix)
    else:
        q, r = queries, ref_matrix

    sims = np.dot(q, r.T)
    return np.clip(sims, -1.0, 1.0)
