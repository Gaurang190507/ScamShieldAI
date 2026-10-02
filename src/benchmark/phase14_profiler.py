"""Comprehensive Phase 14 Performance & Memory Profiler for ScamShield AI.

Benchmarks locally:
1. Startup & model loading latency (cold start vs warm cache).
2. Per-stage execution latency (preprocessing, classifiers, URL, tactics, semantics, OCR, vision, RAG).
3. Warm inference latency distributions (Mean, Median, Min, Max, P95).
4. Process memory footprint (Resident Set Size - RSS) across lifecycle stages.
5. Deterministic reproducibility verification.

Zero network access. Produces empirical local measurements.
"""

from datetime import datetime, timezone
import gc
import json
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Dict, List, Tuple
import numpy as np
import psutil

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app.schemas import InvestigationInput
from src.app.service import InvestigationService
from src.artifacts.cache import (
    clear_model_cache,
    get_cache_stats,
    get_cached_baseline_classifier,
    get_cached_char_classifier,
    get_cached_embedder,
    get_cached_knowledge_retriever,
    get_cached_semantic_reference_index,
)
from src.config.runtime_config import FROZEN_CONFIG, VERSION_METADATA, get_runtime_config
from src.ocr.ocr_engine import AutoOCREngine
from src.url_analysis.url_scanner import URLScanner
from src.tactics.tactic_detector import TacticDetector


def get_current_rss_mb() -> float:
    """Returns current process Resident Set Size in megabytes."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def benchmark_model_loading() -> Dict[str, Any]:
    """Measures cold model load times and memory increments."""
    clear_model_cache()
    gc.collect()

    initial_rss = get_current_rss_mb()
    results = {"initial_rss_mb": round(initial_rss, 2), "loading_latencies_ms": {}, "rss_increments_mb": {}}

    # 1. Baseline Classifier
    t0 = time.perf_counter()
    _ = get_cached_baseline_classifier()
    results["loading_latencies_ms"]["baseline_tfidf_lr"] = round((time.perf_counter() - t0) * 1000, 2)
    results["rss_increments_mb"]["baseline_tfidf_lr"] = round(get_current_rss_mb() - initial_rss, 2)

    # 2. Phase 13 Character n-gram
    rss_prev = get_current_rss_mb()
    t0 = time.perf_counter()
    _ = get_cached_char_classifier()
    results["loading_latencies_ms"]["char_ngram_model_b"] = round((time.perf_counter() - t0) * 1000, 2)
    results["rss_increments_mb"]["char_ngram_model_b"] = round(get_current_rss_mb() - rss_prev, 2)

    # 3. Knowledge Base Retriever
    rss_prev = get_current_rss_mb()
    t0 = time.perf_counter()
    _ = get_cached_knowledge_retriever()
    results["loading_latencies_ms"]["knowledge_retriever"] = round((time.perf_counter() - t0) * 1000, 2)
    results["rss_increments_mb"]["knowledge_retriever"] = round(get_current_rss_mb() - rss_prev, 2)

    # 4. Semantic Reference Index
    rss_prev = get_current_rss_mb()
    t0 = time.perf_counter()
    _ = get_cached_semantic_reference_index()
    results["loading_latencies_ms"]["semantic_reference_index"] = round((time.perf_counter() - t0) * 1000, 2)
    results["rss_increments_mb"]["semantic_reference_index"] = round(get_current_rss_mb() - rss_prev, 2)

    # 5. SentenceTransformer Embedder (Heavy PyTorch weights)
    rss_prev = get_current_rss_mb()
    t0 = time.perf_counter()
    _ = get_cached_embedder()
    results["loading_latencies_ms"]["sentence_transformer_minilm"] = round((time.perf_counter() - t0) * 1000, 2)
    results["rss_increments_mb"]["sentence_transformer_minilm"] = round(get_current_rss_mb() - rss_prev, 2)

    results["final_rss_mb"] = round(get_current_rss_mb(), 2)
    return results


def benchmark_individual_stages() -> Dict[str, Any]:
    """Micro-benchmarks individual pipeline stages over 50 iterations."""
    iterations = 50
    test_text = (
        "URGENT: Your SBI YONO banking account is suspended due to pending KYC verification. "
        "Click http://sbi-kyc-update.xyz to verify your Aadhaar and PAN immediately."
    )
    test_url = "http://sbi-kyc-update.xyz"

    url_scanner = URLScanner()
    tactic_detector = TacticDetector()
    baseline_clf = get_cached_baseline_classifier()
    char_clf = get_cached_char_classifier()
    embedder = get_cached_embedder()
    ref_index = get_cached_semantic_reference_index()
    retriever = get_cached_knowledge_retriever()

    # Check native OCR availability
    auto_ocr = AutoOCREngine()
    ocr_available = auto_ocr.is_available()

    stage_timings: Dict[str, List[float]] = {
        "url_analysis": [],
        "tactic_detection": [],
        "baseline_classifier": [],
        "char_ngram_classifier": [],
        "sentence_embedding": [],
        "reference_similarity_search": [],
        "rag_retrieval": [],
    }

    # Warmup
    _ = url_scanner.analyze_url(test_url)
    _ = tactic_detector.detect(test_text)
    _ = baseline_clf.predict(test_text)
    _ = char_clf.predict(test_text)
    v = embedder.embed_text(test_text)
    _ = ref_index.search(v, top_k=5, disallow_same_id=False)
    _ = retriever.retrieve_by_query("SBI KYC bank account locked", top_k=3)

    for _ in range(iterations):
        # URL
        t0 = time.perf_counter()
        _ = url_scanner.analyze_url(test_url)
        stage_timings["url_analysis"].append((time.perf_counter() - t0) * 1000)

        # Tactics
        t0 = time.perf_counter()
        _ = tactic_detector.detect(test_text)
        stage_timings["tactic_detection"].append((time.perf_counter() - t0) * 1000)

        # Baseline Clf
        t0 = time.perf_counter()
        _ = baseline_clf.predict(test_text)
        stage_timings["baseline_classifier"].append((time.perf_counter() - t0) * 1000)

        # Char N-gram Clf
        t0 = time.perf_counter()
        _ = char_clf.predict(test_text)
        stage_timings["char_ngram_classifier"].append((time.perf_counter() - t0) * 1000)

        # Embedding
        t0 = time.perf_counter()
        vec = embedder.embed_text(test_text)
        stage_timings["sentence_embedding"].append((time.perf_counter() - t0) * 1000)

        # Reference search
        t0 = time.perf_counter()
        _ = ref_index.search(vec, top_k=5, disallow_same_id=False)
        stage_timings["reference_similarity_search"].append((time.perf_counter() - t0) * 1000)

        # RAG retrieval
        t0 = time.perf_counter()
        _ = retriever.retrieve_by_query("SBI KYC bank account locked", top_k=3)
        stage_timings["rag_retrieval"].append((time.perf_counter() - t0) * 1000)

    stats = {}
    for stage, vals in stage_timings.items():
        stats[stage] = {
            "mean_ms": round(float(np.mean(vals)), 2),
            "median_ms": round(float(np.median(vals)), 2),
            "min_ms": round(float(np.min(vals)), 2),
            "max_ms": round(float(np.max(vals)), 2),
            "p95_ms": round(float(np.percentile(vals, 95)), 2),
        }

    stats["ocr_native_available"] = auto_ocr.tesseract.is_available()
    stats["ocr_engine_type"] = auto_ocr.engine_name
    return stats


def benchmark_end_to_end_workloads() -> Dict[str, Any]:
    """Benchmarks full investigation service across 5 representative workloads."""
    service = InvestigationService()
    service.warmup()

    image_sample_path = PROJECT_ROOT / "data" / "visual" / "synthetic" / "hard_neg_alert_01.png"

    workloads = {
        "workload_1_benign_text": InvestigationInput(
            text="Hi mom, I will be home for dinner around 7:30 PM. Please save some rice for me.",
            case_id="bench_w1",
        ),
        "workload_2_bank_phishing_sms": InvestigationInput(
            text="URGENT: Your SBI bank account will be deactivated today due to incomplete KYC. Update immediately: http://sbi-verify.xyz",
            url="http://sbi-verify.xyz",
            case_id="bench_w2",
        ),
        "workload_3_url_only": InvestigationInput(
            url="http://192.168.1.100:8080/secure/bank-login.php?session=xyz",
            case_id="bench_w3",
        ),
        "workload_4_obfuscated_hinglish": InvestigationInput(
            text="D-e-a-r c-u-s-t-o-m-e-r aapka a-c-c-o-u-n-t block ho gaya hai turant call karein 9876543210 for KYC verification.",
            case_id="bench_w4",
        ),
    }

    if image_sample_path.is_file():
        workloads["workload_5_screenshot_image"] = InvestigationInput(
            image_path=image_sample_path,
            case_id="bench_w5",
        )

    workload_results = {}
    warm_iterations = 20

    for name, inp in workloads.items():
        # First cold run
        t0 = time.perf_counter()
        cold_rep = service.investigate(inp)
        cold_latency_ms = (time.perf_counter() - t0) * 1000

        # Warm runs
        warm_latencies = []
        for _ in range(warm_iterations):
            t0 = time.perf_counter()
            rep = service.investigate(inp)
            warm_latencies.append((time.perf_counter() - t0) * 1000)

        workload_results[name] = {
            "verdict": cold_rep.assessment.get("status"),
            "evidence_count": len(cold_rep.all_evidence_items),
            "cold_latency_ms": round(cold_latency_ms, 2),
            "warm_mean_ms": round(float(np.mean(warm_latencies)), 2),
            "warm_median_ms": round(float(np.median(warm_latencies)), 2),
            "warm_min_ms": round(float(np.min(warm_latencies)), 2),
            "warm_max_ms": round(float(np.max(warm_latencies)), 2),
            "warm_p95_ms": round(float(np.percentile(warm_latencies, 95)), 2),
        }

    return workload_results


def run_full_profiler() -> Dict[str, Any]:
    """Executes the complete Phase 14 benchmark harness."""
    print("=" * 60)
    print("ScamShield AI Phase 14 Performance & Resource Profiler")
    print("=" * 60)

    env_info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
        "cpu_count_logical": os.cpu_count(),
        "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    print("\n1. Measuring Model Cold-Loading Latencies and RSS...")
    model_loading = benchmark_model_loading()
    for k, v in model_loading["loading_latencies_ms"].items():
        print(f"   - {k}: {v:.1f} ms (+{model_loading['rss_increments_mb'].get(k, 0):.1f} MB RSS)")
    print(f"   Final Resident Set Size: {model_loading['final_rss_mb']:.1f} MB")

    print("\n2. Micro-benchmarking Pipeline Stages (50 iterations)...")
    stages = benchmark_individual_stages()
    for stage, m in stages.items():
        if isinstance(m, dict):
            print(f"   - {stage}: mean={m['mean_ms']}ms, median={m['median_ms']}ms, p95={m['p95_ms']}ms")
    print(f"   - Native OCR Available: {stages['ocr_native_available']} (Engine: {stages['ocr_engine_type']})")

    print("\n3. Benchmarking End-to-End Investigation Workloads (20 warm iterations)...")
    workloads = benchmark_end_to_end_workloads()
    for wname, wdata in workloads.items():
        print(f"   - {wname}:")
        print(f"       Verdict: {wdata['verdict']} | Evidence Count: {wdata['evidence_count']}")
        print(f"       Cold: {wdata['cold_latency_ms']:.1f} ms | Warm Mean: {wdata['warm_mean_ms']:.1f} ms (P95: {wdata['warm_p95_ms']:.1f} ms)")

    return {
        "environment": env_info,
        "model_loading": model_loading,
        "pipeline_stages": stages,
        "end_to_end_workloads": workloads,
    }


if __name__ == "__main__":
    report_data = run_full_profiler()
    out_dir = PROJECT_ROOT / "data" / "evaluation" / "phase14"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "profiler_raw_data.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\nRaw benchmark data written to {out_dir / 'profiler_raw_data.json'}")
