"""
video.py — VideoDetector wrapper dla steg-lab/video_detector.py
"""

import sys
import os
from pathlib import Path

from .common import SharedResult, now_iso

# Add steg-lab to path for imports
_STEG_LAB = Path(__file__).parent.parent / "steg-lab"
if str(_STEG_LAB) not in sys.path:
    sys.path.insert(0, str(_STEG_LAB))

from video_detector import VideoDetector as _VideoDetector


class VideoDetector:
    """Unified detector for video files (MP4, AVI, MKV, MOV, WebM)."""

    SUPPORTED_FORMATS = {".mp4", ".avi", ".mkv", ".mov", ".webm"}

    def __init__(self):
        self._video_det = _VideoDetector()

    def analyze(self, filepath: str) -> SharedResult:
        """
        Analyze video file for steganography.

        Args:
            filepath: path to video file

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
                    source_module="video",
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
                    source_module="video",
                )

            stat = os.stat(filepath)
            raw = self._video_det.analyze(filepath)

            if raw.get("error"):
                return SharedResult(
                    timestamp=now_iso(),
                    source_module="video",
                    file_name=os.path.basename(filepath),
                    file_path=os.path.abspath(filepath),
                    file_size_bytes=stat.st_size,
                    file_format=ext.upper().lstrip("."),
                    verdict="CLEAN",
                    risk_score=0,
                    errors=raw["error"],
                )

            return SharedResult(
                timestamp=now_iso(),
                source_module="video",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=stat.st_size,
                file_format=ext.upper().lstrip("."),
                verdict=raw.get("verdict", "CLEAN"),
                risk_score=int(raw.get("risk_score", 0)),
                detectors_triggered=raw.get("detectors_triggered", 0),
                detectors_total=raw.get("detectors_total", 3),
                detectors={
                    "chi_square": {
                        "detection_rate": raw.get("chi_detection_rate"),
                    },
                    "rs_analysis": {
                        "detection_rate": raw.get("rs_detection_rate"),
                    },
                    "temporal": {
                        "suspicious": raw.get("temporal_suspicious"),
                        "variance":   raw.get("temporal_variance"),
                    },
                    "video_meta": {
                        "fps":              raw.get("fps"),
                        "duration_seconds": raw.get("duration_seconds"),
                        "total_frames":     raw.get("total_frames"),
                        "frames_analyzed":  raw.get("frames_analyzed"),
                    },
                },
                triggered_rules=raw.get("triggered_rules", []),
                warnings=list(raw.get("warnings", [])),
            )

        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"Analysis failed: {str(e)}",
                source_module="video",
            )
