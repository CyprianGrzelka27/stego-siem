"""
image.py — ImageDetector opakowujący chi_square, rs_analysis, shannon_entropy
"""

import sys
import os
import io
from pathlib import Path
from PIL import Image

from .common import SharedResult, get_verdict, now_iso

# Add steg-lab to path for imports
_STEG_LAB = Path(__file__).parent.parent / "steg-lab"
if str(_STEG_LAB) not in sys.path:
    sys.path.insert(0, str(_STEG_LAB))

from chi_square import ChiSquareDetector as _ChiSquareDetector
from rs_analysis import RSAnalysisDetector as _RSAnalysisDetector
from shannon_entropy import ShannonEntropyDetector as _ShannonEntropyDetector

# image_profiler lives in the same detectors/ package
_DETECTORS_DIR = Path(__file__).parent
if str(_DETECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(_DETECTORS_DIR))

from image_profiler import profile_image as _profile_image


class ImageDetector:
    """Unified detector for images using chi-square, RS analysis, and Shannon entropy."""

    SUPPORTED_FORMATS = {".png", ".bmp", ".tiff", ".tif", ".pgm",
                        ".jpg", ".jpeg", ".jfif", ".webp"}
    LOSSY_FORMATS = {".jpg", ".jpeg", ".jfif", ".webp"}

    # Default weights (can be overridden by image_profiler if needed)
    DEFAULT_WEIGHTS = {
        "chi_square": 0.45,
        "rs_analysis": 0.40,
        "shannon_entropy": 0.15,
    }

    def __init__(self):
        self.chi_detector = _ChiSquareDetector(threshold=0.05)
        self.rs_detector = _RSAnalysisDetector(threshold=0.02)
        self.ent_detector = _ShannonEntropyDetector(threshold=7.8)

    def analyze(self, filepath: str) -> SharedResult:
        """
        Analyze image for steganography.

        Args:
            filepath: path to image file

        Returns:
            SharedResult with detection verdict and risk score
        """
        try:
            if not os.path.exists(filepath):
                return SharedResult(
                    timestamp=now_iso(),
                    file_name=os.path.basename(filepath),
                    file_path=os.path.abspath(filepath),
                    verdict="CLEAN",
                    risk_score=0,
                    errors=f"File not found: {filepath}",
                    source_module="image",
                )

            ext = os.path.splitext(filepath)[1].lower()
            if ext not in self.SUPPORTED_FORMATS:
                return SharedResult(
                    timestamp=now_iso(),
                    file_name=os.path.basename(filepath),
                    file_path=os.path.abspath(filepath),
                    verdict="CLEAN",
                    risk_score=0,
                    errors=f"Unsupported format: {ext}",
                    source_module="image",
                )

            stat = os.stat(filepath)
            warnings = []
            pil_image = None

            # Probe image characteristics and get detector-specific weights.
            # Falls back to DEFAULT_WEIGHTS if profiler fails (e.g., corrupt header).
            try:
                profile = _profile_image(filepath)
                weights = profile["weights"]
                warnings.extend(profile.get("warnings", []))
            except Exception:
                weights = self.DEFAULT_WEIGHTS

            # Convert lossy formats to PNG in memory for analysis
            if ext in self.LOSSY_FORMATS:
                src = Image.open(filepath)
                buf = io.BytesIO()
                src.convert("RGB").save(buf, format="PNG")
                buf.seek(0)
                pil_image = Image.open(buf)
                pil_image.load()
                warnings.append(
                    f"Format {ext.lstrip('.').upper()} is lossy (DCT/WebP). "
                    "LSBs may have been modified by compression. "
                    "Image converted to PNG in memory before analysis."
                )

            # Run three detectors
            chi_result = self.chi_detector.analyze(filepath, pil_image)
            rs_result = self.rs_detector.analyze(filepath, pil_image)
            ent_result = self.ent_detector.analyze(filepath, pil_image)

            # Calculate risk score using profiler-adjusted weights
            risk = int(round((
                chi_result["confidence"] * weights["chi_square"] +
                rs_result["confidence"] * weights["rs_analysis"] +
                ent_result["confidence"] * weights["shannon_entropy"]
            ) * 100))

            # Count detectors triggered
            triggered = sum([chi_result["detected"], rs_result["detected"], ent_result["detected"]])

            # Determine verdict
            verdict = get_verdict(triggered, risk, detectors_total=3)

            triggered_rules = []
            if chi_result.get("detected"):
                p_val = chi_result.get("p_value") or 0.0
                triggered_rules.append({
                    "rule": "chi_square",
                    "metric": "p_value",
                    "value": round(p_val, 4),
                    "threshold": 0.95,
                    "direction": "above",
                    "message": f"Chi²: p={p_val:.4f} > 0.95 — pary PoV wyrównane, wskazuje fill ≥75%",
                })
            if rs_result.get("detected"):
                rs_diff = rs_result.get("rs_difference") or 0.0
                triggered_rules.append({
                    "rule": "rs_analysis",
                    "metric": "rs_diff",
                    "value": round(rs_diff, 4),
                    "threshold": -0.02,
                    "direction": "below",
                    "message": f"RS: rs_diff={rs_diff:.4f} < -0.02 — asymetria Regular/Singular, wskazuje fill ≥25%",
                })
            if ent_result.get("detected"):
                ent_val = ent_result.get("entropy") or 0.0
                triggered_rules.append({
                    "rule": "shannon_entropy",
                    "metric": "lsb_entropy",
                    "value": round(ent_val, 4),
                    "threshold": 7.8,
                    "direction": "above",
                    "message": f"Entropia: H={ent_val:.4f} > 7.8 bit — LSB plane bliskie losowym",
                })

            return SharedResult(
                timestamp=now_iso(),
                source_module="image",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=stat.st_size,
                file_format=ext.upper().lstrip(".") or "UNKNOWN",
                verdict=verdict,
                risk_score=risk,
                detectors_triggered=triggered,
                detectors_total=3,
                warnings=warnings,
                triggered_rules=triggered_rules,
                detectors={
                    "chi_square": {
                        "p_value": chi_result.get("p_value"),
                        "detected": chi_result.get("detected", False),
                        "confidence": chi_result.get("confidence", 0.0),
                        "weight": weights["chi_square"],
                    },
                    "rs_analysis": {
                        "rs_difference": rs_result.get("rs_difference"),
                        "detected": rs_result.get("detected", False),
                        "confidence": rs_result.get("confidence", 0.0),
                        "weight": weights["rs_analysis"],
                    },
                    "shannon_entropy": {
                        "entropy": ent_result.get("entropy"),
                        "detected": ent_result.get("detected", False),
                        "confidence": ent_result.get("confidence", 0.0),
                        "weight": weights["shannon_entropy"],
                    },
                },
            )

        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"Analysis failed: {str(e)}",
                source_module="image",
            )
