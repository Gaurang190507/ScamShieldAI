"""Deterministic local visual feature extraction for ScamShield AI Phase 9A / 9B.

OPERATIONAL PRINCIPLE:
- Strictly Pixel & Layout Driven: Does NOT use OCR text, word counts, or lexical probabilities.
- Deterministic & Explainable: Extracts pure photometric, chromatic, and structural measurements.
- 100% Offline: Relies entirely on NumPy, SciPy, and Pillow without network or external model calls.
"""

from typing import Any, Dict, Tuple, Union
import numpy as np
from PIL import Image
from scipy.signal import convolve2d

from .schemas import VisualFeatures


def compute_shannon_entropy(gray_array: np.ndarray) -> float:
    """Computes Shannon entropy of pixel intensity distribution in bits."""
    hist, _ = np.histogram(gray_array, bins=256, range=(0, 256), density=True)
    # Remove zeros for log computation
    non_zero_hist = hist[hist > 0]
    entropy = -float(np.sum(non_zero_hist * np.log2(non_zero_hist)))
    return round(entropy, 4)


def compute_edge_density(gray_array: np.ndarray, threshold: float = 30.0) -> float:
    """Computes edge pixel density using 2D Sobel spatial gradient convolution.

    Args:
        gray_array: 2D numpy array of uint8 or float grayscale pixel values.
        threshold: Gradient magnitude threshold defining an edge pixel.

    Returns:
        Fraction of pixels in [0.0, 1.0] whose gradient magnitude exceeds threshold.
    """
    # Downsample if image is very large for deterministic fast computation
    h, w = gray_array.shape
    if max(h, w) > 800:
        step = int(np.ceil(max(h, w) / 800))
        gray = gray_array[::step, ::step].astype(np.float32)
    else:
        gray = gray_array.astype(np.float32)

    sobel_x = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float32)
    sobel_y = np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]], dtype=np.float32)

    grad_x = convolve2d(gray, sobel_x, mode="same", boundary="symm")
    grad_y = convolve2d(gray, sobel_y, mode="same", boundary="symm")

    magnitude = np.sqrt(grad_x ** 2 + grad_y ** 2)
    edge_ratio = float(np.mean(magnitude > threshold))
    return round(edge_ratio, 4)


def detect_header_banner(rgb_array: np.ndarray) -> bool:
    """Detects whether a high-contrast horizontal banner occupies the top header."""
    h, w, _ = rgb_array.shape
    if h < 20 or w < 20:
        return False

    top_h = max(int(h * 0.15), 10)
    top_region = rgb_array[:top_h, :, :]
    body_region = rgb_array[top_h:, :, :]

    top_mean = np.mean(top_region, axis=(0, 1))
    body_mean = np.mean(body_region, axis=(0, 1))

    # Check color/luminance contrast distance between header and body
    color_diff = float(np.linalg.norm(top_mean - body_mean))
    return color_diff > 45.0


def count_button_candidates(rgb_array: np.ndarray) -> int:
    """Detects distinct rectangular contrasting blocks in the middle/lower portions."""
    h, w, _ = rgb_array.shape
    if h < 50 or w < 50:
        return 0

    # Examine lower 70% of image
    start_y = int(h * 0.3)
    lower_region = rgb_array[start_y:, :, :]

    # Convert to grayscale
    gray_lower = np.mean(lower_region, axis=2)
    median_val = np.median(gray_lower)

    # Threshold pixels that diverge sharply from median background
    contrasting = np.abs(gray_lower - median_val) > 40.0

    # Horizontal row projection of contrasting pixels
    row_sums = np.sum(contrasting, axis=1) / float(w)
    # Rows with 15% to 80% width covered by contrasting region (button-like strip)
    button_rows = (row_sums > 0.15) & (row_sums < 0.85)

    # Find contiguous row bands of height 15px to 80px
    candidate_count = 0
    in_band = False
    current_h = 0

    for is_btn in button_rows:
        if is_btn:
            in_band = True
            current_h += 1
        else:
            if in_band:
                if 12 <= current_h <= 90:
                    candidate_count += 1
                in_band = False
                current_h = 0
    if in_band and 12 <= current_h <= 90:
        candidate_count += 1

    return min(candidate_count, 5)


def detect_qr_candidate(gray_array: np.ndarray) -> bool:
    """Detects dense, high-frequency, square-like contrasting blocks (e.g. QR codes)."""
    h, w = gray_array.shape
    if h < 80 or w < 80:
        return False

    # Slide square patches across image and compute variance of local gradient
    patch_size = min(int(min(h, w) * 0.4), 160)
    if patch_size < 40:
        return False

    step = max(int(patch_size // 2), 20)
    for y in range(0, h - patch_size + 1, step):
        for x in range(0, w - patch_size + 1, step):
            patch = gray_array[y : y + patch_size, x : x + patch_size]
            # QR codes have roughly balanced black/white pixels and high variance
            mean_val = np.mean(patch)
            std_val = np.std(patch)
            # High standard deviation and balanced median
            if 60.0 < std_val < 125.0 and 60.0 < mean_val < 195.0:
                # Check high edge density in patch
                patch_edges = compute_edge_density(patch, threshold=40.0)
                if patch_edges > 0.35:
                    return True
    return False


def extract_visual_features(image: Image.Image) -> VisualFeatures:
    """Extracts deterministic visual and structural features from an image.

    Args:
        image: PIL Image instance.

    Returns:
        Populated VisualFeatures dataclass.
    """
    # Standardize image to RGB
    rgb_img = image.convert("RGB")
    width, height = rgb_img.size

    rgb_array = np.array(rgb_img, dtype=np.float32)
    # Grayscale conversion using standard luminance weights
    gray_array = 0.2989 * rgb_array[:, :, 0] + 0.5870 * rgb_array[:, :, 1] + 0.1140 * rgb_array[:, :, 2]

    aspect_ratio = round(float(width) / float(max(height, 1)), 4)
    mean_brightness = round(float(np.mean(gray_array)), 4)
    std_brightness = round(float(np.std(gray_array)), 4)
    entropy = compute_shannon_entropy(gray_array.astype(np.uint8))

    # Fraction of near-white background pixels
    whitespace_ratio = round(float(np.mean(gray_array > 240.0)), 4)

    # Color channel statistics
    r_chan = rgb_array[:, :, 0]
    g_chan = rgb_array[:, :, 1]
    b_chan = rgb_array[:, :, 2]

    mean_red = round(float(np.mean(r_chan)), 4)
    mean_green = round(float(np.mean(g_chan)), 4)
    mean_blue = round(float(np.mean(b_chan)), 4)

    total_rgb = mean_red + mean_green + mean_blue + 1e-5
    red_ratio = round(mean_red / total_rgb, 4)

    # HSV Saturation approximation: (max - min) / (max + 1e-5)
    max_c = np.maximum(np.maximum(r_chan, g_chan), b_chan)
    min_c = np.minimum(np.minimum(r_chan, g_chan), b_chan)
    sat = (max_c - min_c) / (max_c + 1e-5)
    mean_saturation = round(float(np.mean(sat)), 4)

    color_variance = round(float(np.var([mean_red, mean_green, mean_blue])), 4)

    # Spatial edge complexity
    edge_density = compute_edge_density(gray_array, threshold=30.0)

    # Vertical distribution
    top_20 = gray_array[: max(int(height * 0.2), 1), :]
    bottom_20 = gray_array[int(height * 0.8) :, :]
    top_lum_ratio = round(float(np.mean(top_20)) / (mean_brightness + 1e-5), 4)
    bottom_lum_ratio = round(float(np.mean(bottom_20)) / (mean_brightness + 1e-5), 4)

    # Horizontal asymmetry
    half_w = max(int(width * 0.5), 1)
    left_half = np.mean(gray_array[:, :half_w])
    right_half = np.mean(gray_array[:, half_w:])
    horiz_asym = round(float(np.abs(left_half - right_half)), 4)

    # Structural layout heuristics
    header_banner = detect_header_banner(rgb_array.astype(np.uint8))
    button_count = count_button_candidates(rgb_array.astype(np.uint8))
    qr_detected = detect_qr_candidate(gray_array)

    return VisualFeatures(
        width=width,
        height=height,
        aspect_ratio=aspect_ratio,
        mean_brightness=mean_brightness,
        std_brightness=std_brightness,
        entropy=entropy,
        whitespace_ratio=whitespace_ratio,
        mean_red=mean_red,
        mean_green=mean_green,
        mean_blue=mean_blue,
        red_ratio=red_ratio,
        mean_saturation=mean_saturation,
        color_variance=color_variance,
        edge_density=edge_density,
        top_luminance_ratio=top_lum_ratio,
        bottom_luminance_ratio=bottom_lum_ratio,
        horizontal_asymmetry=horiz_asym,
        header_banner_detected=header_banner,
        button_candidate_count=button_count,
        qr_candidate_detected=qr_detected,
    )
