"""
scan.py — interaktywny skaner steganografii dla SIEM
Wypisuje JSON na stdout. Opcjonalnie dopisuje do pliku logów.

Użycie:
  python scan.py                  # tryb interaktywny (pyta o ścieżkę)
  python scan.py obraz.png        # bezpośrednie podanie ścieżki
  python scan.py obraz.png --log  # + zapis do stego_scan.log
"""

import sys
import os
import io
import json
import datetime
import argparse
from PIL import Image

# ── importy detektorów ────────────────────────────────────────────
from chi_square     import ChiSquareDetector
from rs_analysis    import RSAnalysisDetector
from shannon_entropy import ShannonEntropyDetector

LOG_FILE = "stego_scan.log"

WEIGHTS = {"chi_square": 0.45, "rs_analysis": 0.40, "shannon_entropy": 0.15}

LOSSY_FORMATS     = {".jpg", ".jpeg", ".jfif", ".webp"}
SUPPORTED_FORMATS = {".png", ".bmp", ".tiff", ".tif", ".pgm",
                     ".jpg", ".jpeg", ".jfif", ".webp"}
VIDEO_FORMATS     = {".mp4", ".avi", ".mkv", ".mov", ".webm"}


def scan(filepath: str) -> dict:
    if not os.path.exists(filepath):
        return {"error": f"Plik nie istnieje: {filepath}"}

    ext = os.path.splitext(filepath)[1].lower()

    if ext in VIDEO_FORMATS:
        from video_detector import VideoDetector
        return VideoDetector().analyze(filepath)

    if ext not in SUPPORTED_FORMATS:
        return {"error": f"Nieobsługiwany format: '{ext}'. Obsługiwane: {', '.join(sorted(SUPPORTED_FORMATS))}"}

    stat = os.stat(filepath)
    scan_warnings = []
    pil_image = None

    if ext in LOSSY_FORMATS:
        src = Image.open(filepath)
        buf = io.BytesIO()
        src.convert("RGB").save(buf, format="PNG")
        buf.seek(0)
        pil_image = Image.open(buf)
        pil_image.load()
        scan_warnings.append(
            f"Format {ext.lstrip('.').upper()} jest stratny (DCT/WebP). "
            "Bity LSB mogły zostać zmodyfikowane przez kompresję. "
            "Obraz skonwertowany w pamięci do PNG przed analizą."
        )

    chi = ChiSquareDetector(threshold=0.05).analyze(filepath, pil_image)
    rs  = RSAnalysisDetector(threshold=0.02).analyze(filepath, pil_image)
    ent = ShannonEntropyDetector(threshold=7.8).analyze(filepath, pil_image)

    risk = int(round((
        chi["confidence"] * WEIGHTS["chi_square"] +
        rs["confidence"]  * WEIGHTS["rs_analysis"] +
        ent["confidence"] * WEIGHTS["shannon_entropy"]
    ) * 100))

    triggered = sum([chi["detected"], rs["detected"], ent["detected"]])

    if triggered == 0 and risk < 20:
        verdict = "CLEAN"
    elif triggered >= 2 or risk >= 60:
        verdict = "DETECTED"
    else:
        verdict = "SUSPICIOUS"

    return {
        "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type":  "stego_scan",
        "file": {
            "path":       os.path.abspath(filepath),
            "name":       os.path.basename(filepath),
            "size_bytes": stat.st_size,
            "format":     ext.upper().lstrip(".") or "UNKNOWN",
            "lossy_source": ext in LOSSY_FORMATS,
        },
        "warnings": scan_warnings,
        "detectors": {
            "chi_square":      {"p_value":       chi["p_value"],
                                "detected":      chi["detected"],
                                "confidence":    chi["confidence"]},
            "rs_analysis":     {"rs_difference": rs["rs_difference"],
                                "detected":      rs["detected"],
                                "confidence":    rs["confidence"]},
            "shannon_entropy": {"entropy":       ent["entropy"],
                                "detected":      ent["detected"],
                                "confidence":    ent["confidence"]},
        },
        "verdict":             verdict,
        "risk_score":          risk,
        "detectors_triggered": triggered,
        "detectors_total":     3,
    }


def print_summary(report: dict):
    """Krótkie czytelne podsumowanie przed JSON-em."""
    if "error" in report:
        print(f"  BŁĄD: {report['error']}")
        return
    v = report["verdict"]
    color = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m", "DETECTED": "\033[91m"}.get(v, "")
    reset = "\033[0m"
    print(f"  Plik:       {report['file']['name']}")
    print(f"  Wynik:      {color}{v}{reset}  (risk_score={report['risk_score']})")
    d = report["detectors"]
    print(f"  Chi-square: p={d['chi_square']['p_value']}  "
          f"RS: diff={d['rs_analysis']['rs_difference']}  "
          f"Entropia: H={d['shannon_entropy']['entropy']}")


def run_interactive(log: bool):
    print("=== Skaner steganografii LSB — moduł SIEM ===")
    print("Wpisz ścieżkę do obrazu (lub 'q' aby wyjść)\n")
    while True:
        try:
            path = input("Ścieżka: ").strip().strip('"').strip("'")
        except (EOFError, KeyboardInterrupt):
            print("\nZakończono.")
            break
        if path.lower() in ("q", "quit", "exit", ""):
            print("Zakończono.")
            break

        print()
        report = scan(path)
        print_summary(report)
        json_line = json.dumps(report, ensure_ascii=False)
        print()
        print(json_line)

        if log and "error" not in report:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")
            print(f"  → dopisano do {LOG_FILE}")
        print()


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filepath", nargs="?", help="Ścieżka do pliku (opcjonalne)")
    parser.add_argument("--log", action="store_true", help=f"Dopisuj logi do {LOG_FILE}")
    args = parser.parse_args()

    if args.filepath:
        # tryb nieinteraktywny — jeden plik, czysty JSON na stdout
        report = scan(args.filepath)
        if not args.log:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            json_line = json.dumps(report, ensure_ascii=False)
            print(json_line)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")
    else:
        run_interactive(log=args.log)
