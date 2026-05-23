"""
Detektor steganografii LSB w plikach wideo.

Próbkuje ~30 klatek z wideo, uruchamia chi-square, RS i entropię Shannona
na każdej klatce, następnie agreguje wyniki i oblicza risk score (0–100).

Uruchom: python video_detector.py plik.avi
"""

import sys
import os
import json
import numpy as np
import cv2
from PIL import Image

from chi_square      import ChiSquareDetector
from rs_analysis     import RSAnalysisDetector
from shannon_entropy import ShannonEntropyDetector


class VideoDetector:

    def analyze(self, video_path: str) -> dict:
        result = {
            "source_file":         video_path,
            "format":              os.path.splitext(video_path)[1].upper().lstrip(".") or "UNKNOWN",
            "fps":                 None,
            "duration_seconds":    None,
            "total_frames":        None,
            "frames_analyzed":     0,
            "frame_results":       [],
            "chi_detection_rate":  0.0,
            "rs_detection_rate":   0.0,
            "temporal_variance":   None,
            "temporal_suspicious": False,
            "risk_score":          0,
            "verdict":             "CLEAN",
            "detectors_triggered": 0,
        }

        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            result["error"] = f"Nie można otworzyć wideo: {video_path}"
            return result

        fps          = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width        = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height       = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        result["fps"]              = round(float(fps), 2) if fps > 0 else 0.0
        result["total_frames"]     = total_frames
        result["duration_seconds"] = round(total_frames / fps, 2) if fps > 0 else 0.0

        # Próbkuj co N-tą klatkę, by zebrać max ~10 klatek
        N = max(1, total_frames // 10)

        chi_det = ChiSquareDetector(threshold=0.05)
        rs_det  = RSAnalysisDetector(threshold=0.02)
        ent_det = ShannonEntropyDetector(threshold=7.8)

        frame_results = []
        frame_idx     = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            if frame_idx % N == 0:
                frame_pil = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))

                chi_r = chi_det.analyze(filepath="", pil_image=frame_pil)
                rs_r  = rs_det.analyze(filepath="",  pil_image=frame_pil)
                ent_r = ent_det.analyze(filepath="", pil_image=frame_pil)

                frame_results.append({
                    "frame_idx":    frame_idx,
                    "chi_detected": chi_r.get("detected", False),
                    "chi_p_value":  chi_r.get("p_value"),
                    "rs_detected":  rs_r.get("detected",  False),
                    "rs_difference": rs_r.get("rs_difference"),
                    "ent_detected": ent_r.get("detected", False),
                    "ent_entropy":  ent_r.get("entropy"),
                })

            frame_idx += 1

        cap.release()

        if not frame_results:
            return result

        result["frame_results"]  = frame_results
        result["frames_analyzed"] = len(frame_results)

        # ── Wskaźniki detekcji ────────────────────────────────────────────
        n = len(frame_results)
        chi_rate = sum(1 for f in frame_results if f["chi_detected"]) / n
        rs_rate  = sum(1 for f in frame_results if f["rs_detected"])  / n
        result["chi_detection_rate"] = round(chi_rate, 4)
        result["rs_detection_rate"]  = round(rs_rate,  4)

        # ── Analiza temporalna (wariancja p-value chi-square) ─────────────
        p_values = [f["chi_p_value"] for f in frame_results if f["chi_p_value"] is not None]
        if p_values:
            variance = float(np.var(p_values))
            # Niski rozrzut p-value + wysoki odsetek detekcji → sygnał regularny, podejrzany
            temporal_suspicious = variance < 0.01 and chi_rate > 0.5
            result["temporal_variance"]   = round(variance, 6)
            result["temporal_suspicious"] = temporal_suspicious
        else:
            temporal_suspicious = False

        # ── Risk score (0–100) ────────────────────────────────────────────
        risk = 0
        if chi_rate > 0.5:
            risk += 40
        if rs_rate > 0.4:
            risk += 35
        if temporal_suspicious:
            risk += 25
        result["risk_score"] = min(100, risk)

        # ── Werdykt ───────────────────────────────────────────────────────
        if risk < 20:
            result["verdict"] = "CLEAN"
        elif risk >= 60:
            result["verdict"] = "DETECTED"
        else:
            result["verdict"] = "SUSPICIOUS"

        result["detectors_triggered"] = sum([
            chi_rate > 0.5,
            rs_rate  > 0.4,
            temporal_suspicious,
        ])

        return result


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Użycie: python video_detector.py plik_wideo.avi")
        sys.exit(1)

    detector = VideoDetector()
    wynik    = detector.analyze(sys.argv[1])
    summary  = {k: v for k, v in wynik.items() if k != "frame_results"}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
