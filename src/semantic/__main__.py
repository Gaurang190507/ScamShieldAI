"""CLI entrypoint for ScamShield AI Phase 7 Semantic Similarity & Novelty Layer.

Usage:
    python -m src.semantic --build-index   # Build and cache reference corpus index from TRAIN split
    python -m src.semantic --demo          # Run interactive demonstrations
"""

import argparse
from pathlib import Path
import sys
import time

from .analyzer import SemanticAnalyzer
from .embedder import TextEmbedder
from .reference_index import SemanticReferenceIndex
from .split_loader import load_canonical_splits


def build_reference_index(output_dir: Path) -> SemanticReferenceIndex:
    """Builds and caches semantic reference index strictly from the TRAIN split."""
    print("=" * 80)
    print(" ScamShield AI — Phase 7 Reference Corpus Index Construction")
    print("=" * 80)

    print("1. Loading authoritative Phase 3 train partition (3,881 records)...")
    train_df, val_df, test_df = load_canonical_splits()
    print(
        f"   Loaded partitions: TRAIN={len(train_df)}, VAL={len(val_df)}, TEST={len(test_df)}"
    )

    records = train_df.to_dict(orient="records")
    print(f"   Train class distribution: {(train_df['label'] == 'scam').sum()} scam, "
          f"{(train_df['label'] == 'non_scam').sum()} non_scam")

    print("\n2. Initializing local text embedder (sentence-transformers/all-MiniLM-L6-v2)...")
    embedder = TextEmbedder()

    print("\n3. Generating reference embeddings matrix (shape: 3881 x 384)...")
    start_t = time.perf_counter()
    index = SemanticReferenceIndex.build_from_records(
        records=records,
        embedder=embedder,
        batch_size=64,
        show_progress=True,
    )
    elapsed = time.perf_counter() - start_t
    print(f"   Embeddings completed in {elapsed:.2f}s ({len(records)/elapsed:.1f} samples/sec)")

    print(f"\n4. Saving reference index and binary cache to: {output_dir}")
    index.save(output_dir)
    print("   Successfully saved reference index artifacts:")
    print(f"   - {output_dir / 'reference_items.jsonl'}")
    print(f"   - {output_dir / 'reference_embeddings.npy'}")
    print(f"   - {output_dir / 'reference_embeddings.meta.json'}")

    return index


def run_demo(index_dir: Path) -> None:
    """Runs demonstration of semantic retrieval and novelty detection on sample cases."""
    print("=" * 80)
    print(" ScamShield AI — Phase 7 Semantic Similarity & Novelty Detection Demo")
    print("=" * 80)

    if not (index_dir / "reference_items.jsonl").is_file():
        print("Reference index not found. Building it first...")
        index = build_reference_index(index_dir)
    else:
        print(f"Loading reference index from {index_dir}...")
        index = SemanticReferenceIndex.load(index_dir)
        print(f"Reference index loaded: {index.size} samples, dim={index.dimension}")

    embedder = TextEmbedder(model_name=index.model_name)
    analyzer = SemanticAnalyzer(reference_index=index, embedder=embedder)

    demo_cases = [
        (
            "Case 1: Standard Bank KYC Phishing (High Similarity Scam)",
            "URGENT: Your SBI bank account has been locked. Verify your KYC immediately at http://sbi-kyc.net or card will be blocked.",
        ),
        (
            "Case 2: Ordinary Social Plan (High Similarity Non-Scam)",
            "Hey, are you free for dinner tonight around 7pm? Let me know if that works.",
        ),
        (
            "Case 3: Emerging / Novel Threat Form (Low Similarity Scam)",
            "Notice: Power grid inspection alert. Unauthorized smart meter bypass detected at your address. Pay penalty fine via QR scan.",
        ),
        (
            "Case 4: Benign Highly Unusual Context (Low Similarity Non-Scam)",
            "The archaeological excavation revealed mid-Pleistocene strata with lithic tool assemblages preserved under volcanic tuff.",
        ),
    ]

    for title, text in demo_cases:
        print(f"\n--- [{title}] ---")
        print(f"Input Text: \"{text}\"")
        res = analyzer.analyze(text=text, top_k=3, disallow_same_id=False)

        sem = res.semantic
        print(f"Semantic Metrics:")
        print(f"  • Top-1 Similarity:        {sem.top_1_similarity:.4f}")
        print(f"  • Top-3 Mean Similarity:   {sem.top_5_mean_similarity:.4f}")
        print(f"  • Nearest Scam Similarity: {sem.nearest_scam_similarity}")
        print(f"  • Nearest Non-Scam Sim:    {sem.nearest_non_scam_similarity}")
        print(f"  • Semantic Novelty Score:  {sem.semantic_novelty_score:.4f}")
        print(f"  • Semantic Status:         [{sem.semantic_status.upper()}]")

        print("Nearest Reference Neighbors (from TRAIN only):")
        for i, n in enumerate(res.neighbors, 1):
            print(f"  {i}. [Sim: {n.similarity:.4f} | Label: {n.label.upper()} | ID: {n.sample_id}]")
            print(f"     \"{n.text_preview}\"")

    print("\n" + "=" * 80)
    print(" Demo complete. Fully offline inference, zero API calls, zero LLMs.")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="ScamShield AI Phase 7 Semantic Layer")
    parser.add_argument("--build-index", action="store_true", help="Build reference index")
    parser.add_argument("--demo", action="store_true", help="Run interactive demo")
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parents[2]
    ref_dir = root_dir / "data" / "semantic" / "reference"

    if args.build_index:
        build_reference_index(ref_dir)
    elif args.demo:
        run_demo(ref_dir)
    else:
        # Default: if index doesn't exist, build, else run demo
        if not (ref_dir / "reference_items.jsonl").is_file():
            build_reference_index(ref_dir)
        run_demo(ref_dir)


if __name__ == "__main__":
    main()
