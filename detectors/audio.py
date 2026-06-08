"""
audio.py — AudioDetector opakowujący audio_detector z detectors/audio/
"""

import sys
import os
from pathlib import Path

from .common import SharedResult, now_iso

# Add audio detector to path
_AUDIO_DETECTOR = Path(__file__).parent / "audio"
if str(_AUDIO_DETECTOR) not in sys.path:
    sys.path.insert(0, str(_AUDIO_DETECTOR))

from audio_detector import AudioGroupParityDetector as _AudioGroupParityDetector


class AudioDetector:
    """Unified detector for audio files (WAV format with group parity LSB method)."""

    SUPPORTED_FORMATS = {".wav", ".wave"}

    def __init__(self):
        self.detector = _AudioGroupParityDetector(group_size=8, threshold=0.05)

    def analyze(self, filepath: str) -> SharedResult:
        """
        Analyze audio file for steganography.

        Args:
            filepath: path to audio file (WAV)

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
                    source_module="audio",
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
                    source_module="audio",
                )

            stat = os.stat(filepath)

            # Run audio detector
            audio_result = self.detector.analyze(filepath)

            if "error" in audio_result:
                return SharedResult(
                    timestamp=now_iso(),
                    source_module="audio",
                    file_name=os.path.basename(filepath),
                    file_path=os.path.abspath(filepath),
                    file_size_bytes=stat.st_size,
                    file_format=ext.upper().lstrip("."),
                    verdict="CLEAN",
                    risk_score=0,
                    errors=audio_result.get("error"),
                )

            # Audio detector returns confidence directly (0.0-1.0)
            confidence = audio_result.get("confidence", 0.0)
            risk_score = int(round(confidence * 100))
            is_suspicious = audio_result.get("suspicious", False)

            # Convert to verdict
            if is_suspicious or confidence > 0.8:
                verdict = "DETECTED"
            elif confidence > 0.5:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            detectors_triggered = 1 if is_suspicious else 0

            triggered_rules = []
            parity_deviation = audio_result.get("score", 0.0)
            if is_suspicious:
                triggered_rules.append({
                    "rule": "group_parity",
                    "metric": "parity_deviation",
                    "value": round(parity_deviation, 4),
                    "threshold": 0.05,
                    "direction": "above",
                    "message": f"GroupParity: odchylenie={parity_deviation:.4f} > 0.05 — bity LSB niespójne w grupach",
                })
            p_value_parity = audio_result.get("p_value_parity")
            if p_value_parity is not None and p_value_parity < 0.05:
                triggered_rules.append({
                    "rule": "parity_chi_test",
                    "metric": "p_value_parity",
                    "value": round(p_value_parity, 4),
                    "threshold": 0.05,
                    "direction": "below",
                    "message": f"Chi-kwadrat parytetu: p={p_value_parity:.4f} < 0.05 — LSB nie są losowe",
                })

            return SharedResult(
                timestamp=now_iso(),
                source_module="audio",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=stat.st_size,
                file_format=ext.upper().lstrip("."),
                verdict=verdict,
                risk_score=risk_score,
                detectors_triggered=detectors_triggered,
                detectors_total=1,
                triggered_rules=triggered_rules,
                detectors={
                    "audio_group_parity": {
                        "confidence": confidence,
                        "suspicious": is_suspicious,
                        "score": audio_result.get("score", 0.0),
                        "p_value_parity": audio_result.get("p_value_parity"),
                        "p_value_pairs": audio_result.get("p_value_pairs"),
                        "header_score": audio_result.get("header_score"),
                        "n_samples": audio_result.get("n_samples", 0),
                        "n_groups": audio_result.get("n_groups", 0),
                        "sampwidth": audio_result.get("sampwidth"),
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
                source_module="audio",
            )
