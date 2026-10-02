"""Explainable visual evidence extractor for ScamShield AI Phase 9B.

Translates quantitative visual feature measurements into transparent,
traceable observations with neutral forensic rationales.

CRITICAL POLICY:
- Measurements are NEVER labeled as definitive scam verdicts.
- Features like QR codes, banners, or buttons are recorded as visual observations.
"""

from typing import List
from .schemas import VisualEvidenceItem, VisualFeatures


def extract_visual_evidence(features: VisualFeatures) -> List[VisualEvidenceItem]:
    """Generates explainable evidence items from extracted visual features.

    Args:
        features: VisualFeatures instance.

    Returns:
        List of VisualEvidenceItem instances.
    """
    evidence: List[VisualEvidenceItem] = []

    # 1. Structural layout elements
    if features.header_banner_detected:
        evidence.append(
            VisualEvidenceItem(
                feature="header_banner_detected",
                value=True,
                role="visual_observation",
                reason=(
                    "High-contrast top banner detected in screenshot layout. "
                    "Note: Header banners are common in both official apps and phishing screens."
                ),
            )
        )

    if features.button_candidate_count > 0:
        evidence.append(
            VisualEvidenceItem(
                feature="button_candidate_count",
                value=features.button_candidate_count,
                role="visual_observation",
                reason=(
                    f"Identified {features.button_candidate_count} rectangular action button candidate(s) "
                    "in the interface layout."
                ),
            )
        )

    if features.qr_candidate_detected:
        evidence.append(
            VisualEvidenceItem(
                feature="qr_candidate_detected",
                value=True,
                role="visual_observation",
                reason=(
                    "Dense high-frequency square pattern characteristic of a QR code detected. "
                    "This is a visual observation and is not independently sufficient to establish fraud."
                ),
            )
        )

    # 2. Chromatic & Photometric profile
    if features.red_ratio >= 0.42:
        evidence.append(
            VisualEvidenceItem(
                feature="red_ratio",
                value=features.red_ratio,
                role="visual_observation",
                reason=(
                    f"Elevated red channel proportion ({features.red_ratio:.2f}); frequently seen "
                    "in urgent alerts, branding accents, or critical system notifications."
                ),
            )
        )

    if features.edge_density >= 0.25:
        evidence.append(
            VisualEvidenceItem(
                feature="edge_density",
                value=features.edge_density,
                role="visual_observation",
                reason=(
                    f"High edge gradient density ({features.edge_density:.2f}), indicating visual "
                    "complexity or dense graphical elements."
                ),
            )
        )
    elif features.edge_density <= 0.05:
        evidence.append(
            VisualEvidenceItem(
                feature="edge_density",
                value=features.edge_density,
                role="visual_observation",
                reason=(
                    f"Low edge gradient density ({features.edge_density:.2f}), indicating a plain, "
                    "monochrome, or minimal layout."
                ),
            )
        )

    if features.mean_saturation >= 0.50:
        evidence.append(
            VisualEvidenceItem(
                feature="mean_saturation",
                value=features.mean_saturation,
                role="visual_observation",
                reason=(
                    f"High color saturation ({features.mean_saturation:.2f}), common in promotional "
                    "marketing graphics or high-contrast alerts."
                ),
            )
        )

    return evidence
