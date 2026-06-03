"""
Detektor steganografii LSB w plikach wideo.

Próbkuje ~10 klatek z wideo, uruchamia chi-square, RS i entropię Shannona
na każdej klatce, następnie agreguje wyniki i oblicza risk score (0–100).
Opcjonalnie analizuje ścieżkę audio osadzoną w pliku wideo.

Risk score łączony: 0.70 * risk_visual + 0.30 * risk_audio
Werdykt: <20 CLEAN, 20-59 SUSPICIOUS, >=60 DETECTED

Uruchom: python video_detector.py plik.avi
"""

import sys
import os
import json
import tempfile
import subprocess
import shutil
import numpy as np
import cv2
from PIL import Image

from chi_square      import ChiSquareDetector
from rs_analysis     import RSAnalysisDetector
from shannon_entropy import ShannonEntropyDetector


def _import_audio_detector():
    """Importuje AudioGroupParityDetector z detectors/audio/ obok repozytorium."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        audio_dir  = os.path.abspath(os.path.join(script_dir, '..', 'detectors', 'audio'))
        if os.path.isdir(audio_dir) and audio_dir not in sys.path:
            sys.path.insert(0, audio_dir)
        from audio_detector import AudioGroupParityDetector
        return AudioGroupParityDetector
    except ImportError:
        return None


_AudioDetectorCls = _import_audio_detector()


def _find_ffmpeg() -> str:
    """Zwraca pełną ścieżkę do ffmpeg lub pusty string jeśli nie znaleziono."""
    candidate = shutil.which('ffmpeg')
    if candidate:
        return candidate
    home = os.path.expanduser('~')
    for path in [
        os.path.join(home, 'Anaconda3',  'Library', 'bin', 'ffmpeg.exe'),
        os.path.join(home, 'anaconda3',  'Library', 'bin', 'ffmpeg.exe'),
        r'C:\ProgramData\anaconda3\Library\bin\ffmpeg.exe',
        '/usr/bin/ffmpeg',
        '/usr/local/bin/ffmpeg',
    ]:
        if os.path.isfile(path):
            return path
    return ''


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
            "detectors_total":     3,
            "detectors":           {},
            "warnings":            [],
        }

        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            result["error"] = f"Nie można otworzyć wideo: {video_path}"
            return result

        fps          = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        result["fps"]              = round(float(fps), 2) if fps > 0 else 0.0
        result["total_frames"]     = total_frames
        result["duration_seconds"] = round(total_frames / fps, 2) if fps > 0 else 0.0

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
                    "frame_idx":     frame_idx,
                    "chi_detected":  chi_r.get("detected", False),
                    "chi_p_value":   chi_r.get("p_value"),
                    "rs_detected":   rs_r.get("detected",  False),
                    "rs_difference": rs_r.get("rs_difference"),
                    "ent_detected":  ent_r.get("detected", False),
                    "ent_entropy":   ent_r.get("entropy"),
                })

            frame_idx += 1

        cap.release()

        if not frame_results:
            return result

        result["frame_results"]   = frame_results
        result["frames_analyzed"] = len(frame_results)

        # ── Wskaźniki detekcji wizualnej ──────────────────────────────
        n        = len(frame_results)
        chi_rate = sum(1 for f in frame_results if f["chi_detected"]) / n
        rs_rate  = sum(1 for f in frame_results if f["rs_detected"])  / n
        result["chi_detection_rate"] = round(chi_rate, 4)
        result["rs_detection_rate"]  = round(rs_rate,  4)

        # ── Analiza temporalna (wariancja p-value chi-square) ─────────
        p_values = [f["chi_p_value"] for f in frame_results if f["chi_p_value"] is not None]
        if p_values:
            variance = float(np.var(p_values))
            temporal_suspicious = variance < 0.01 and chi_rate > 0.5
            result["temporal_variance"]   = round(variance, 6)
            result["temporal_suspicious"] = temporal_suspicious
        else:
            temporal_suspicious = False

        # ── Visual risk score (0–100) ──────────────────────────────────
        risk_visual = 0
        if chi_rate > 0.5:
            risk_visual += 40
        if rs_rate > 0.4:
            risk_visual += 35
        if temporal_suspicious:
            risk_visual += 25
        risk_visual = min(100, risk_visual)

        visual_triggered = int(chi_rate > 0.5) + int(rs_rate > 0.4) + int(temporal_suspicious)
        visual_total     = 3

        result["detectors"]["visual_chi"]      = {
            "triggered": chi_rate > 0.5, "rate": round(chi_rate, 4)
        }
        result["detectors"]["visual_rs"]       = {
            "triggered": rs_rate > 0.4,  "rate": round(rs_rate, 4)
        }
        result["detectors"]["visual_temporal"] = {
            "triggered": temporal_suspicious, "variance": result.get("temporal_variance")
        }

        # ── Analiza ścieżki audio ─────────────────────────────────────
        audio_result = self._analyze_audio_track(video_path)

        if audio_result is None:
            result["warnings"].append("no_audio_track")
            risk_audio      = 0.0
            audio_triggered = 0
            audio_total     = 0
        else:
            result["detectors"]["audio_track"] = audio_result
            risk_audio      = float(audio_result.get("score", 0.0))
            audio_triggered = 1 if audio_result.get("suspicious", False) else 0
            audio_total     = 1
            if audio_result.get("error"):
                result["warnings"].append(f"audio_analysis_error: {audio_result['error']}")
            else:
                result["warnings"].append("audio_track_analyzed")

        # ── Risk score łączony: 70% visual + 30% audio ────────────────
        if audio_total > 0:
            risk_combined = 0.70 * risk_visual + 0.30 * risk_audio
        else:
            risk_combined = float(risk_visual)
        risk_combined = min(100.0, risk_combined)

        result["risk_score"]          = round(risk_combined)
        result["detectors_triggered"] = visual_triggered + audio_triggered
        result["detectors_total"]     = visual_total + audio_total

        # ── Werdykt ───────────────────────────────────────────────────
        if risk_combined < 20:
            result["verdict"] = "CLEAN"
        elif risk_combined >= 60:
            result["verdict"] = "DETECTED"
        else:
            result["verdict"] = "SUSPICIOUS"

        return result

    def _analyze_audio_track(self, video_path: str):
        """
        Wyodrębnia ścieżkę audio z pliku wideo i analizuje ją AudioGroupParityDetector.

        Zwraca dict z wynikami lub None jeśli plik nie ma ścieżki audio bądź
        ffmpeg/AudioDetector jest niedostępny.
        """
        if _AudioDetectorCls is None:
            return None

        ffmpeg = _find_ffmpeg()
        if not ffmpeg:
            return None

        tmp_wav = None
        try:
            fd, tmp_wav = tempfile.mkstemp(suffix='.wav')
            os.close(fd)

            # Wyodrębnij audio: mono 44100 Hz WAV (pcm_s16le)
            proc = subprocess.run(
                [ffmpeg, '-y', '-i', video_path,
                 '-vn', '-ar', '44100', '-ac', '1',
                 '-acodec', 'pcm_s16le', '-f', 'wav', tmp_wav],
                capture_output=True,
                timeout=120,
            )

            # Brak ścieżki audio → ffmpeg zwróci błąd lub pusty plik
            if proc.returncode != 0:
                return None
            if not os.path.isfile(tmp_wav) or os.path.getsize(tmp_wav) < 44:
                return None

            detector = _AudioDetectorCls()
            return detector.analyze(tmp_wav)

        except Exception as exc:
            return {
                "detector":   "audio_group_parity",
                "suspicious": False,
                "score":      0.0,
                "confidence": 0.0,
                "error":      str(exc),
            }
        finally:
            if tmp_wav and os.path.exists(tmp_wav):
                try:
                    os.unlink(tmp_wav)
                except OSError:
                    pass


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Użycie: python video_detector.py plik_wideo.avi")
        sys.exit(1)

    detector = VideoDetector()
    wynik    = detector.analyze(sys.argv[1])
    summary  = {k: v for k, v in wynik.items() if k != "frame_results"}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
