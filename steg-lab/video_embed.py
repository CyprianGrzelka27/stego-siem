"""
Generator wideo ze steganografią LSB.

Analogiczny do lsb_embed.py, ale operuje na plikach wideo klatka po klatce.
Wyjście: MKV z kodekiem FFV1 (bezstratny) — bity LSB są zachowane po zapisie.

Uruchom:
  python video_embed.py input.mp4 --fill 0.5
  python video_embed.py input.mp4 --fill 1.0
"""

import sys
import os
import argparse
import numpy as np
import cv2


def embed_lsb_video(input_path: str, output_path: str, fill_ratio: float = 0.5) -> dict:
    """
    Wpisuje losowe bity w LSB każdej klatki wideo.

    Parametry:
      input_path  — ścieżka do pliku wideo wejściowego (MP4, AVI, ...)
      output_path — pełna ścieżka do pliku wyjściowego (.mkv)
      fill_ratio  — jaka frakcja wartości kanałów jest modyfikowana (0.0–1.0)

    Logika LSB: identyczna jak lsb_embed.py:
      flat[:n] = (flat[:n] & 0xFE) | random_bits

    Zapis przez ffmpeg (FFV1 w MKV) zamiast cv2.VideoWriter (XVID byłby stratny).
    FFV1 jest bezstratny i zachowuje wartości pikseli co do bitu.
    """
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError(f"Nie można otworzyć wideo: {input_path}")

    fps          = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    width        = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height       = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)

    fourcc = cv2.VideoWriter_fourcc(*"FFV1")
    writer = cv2.VideoWriter(output_path, cv2.CAP_FFMPEG, fourcc, fps, (width, height))

    frames_written = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break

        flat    = frame.flatten()
        n_embed = int(len(flat) * fill_ratio)

        random_bits = np.random.randint(0, 2, size=n_embed, dtype=np.uint8)
        flat[:n_embed] = (flat[:n_embed] & np.uint8(0xFE)) | random_bits

        writer.write(flat.reshape(frame.shape))
        frames_written += 1

    cap.release()
    writer.release()

    return {
        "input":        input_path,
        "output":       output_path,
        "fill_ratio":   fill_ratio,
        "total_frames": frames_written,
        "fps":          fps,
        "resolution":   (width, height),
    }


def embed_all_videos(clean_dir: str, stego_dir: str,
                     fills: list = None) -> list:
    """
    Przetwarza wszystkie pliki .mp4/.avi z clean_dir i zapisuje do stego_dir.
    Dla każdego pliku tworzy osobną wersję per fill ratio.
    """
    if fills is None:
        fills = [0.25, 0.5, 1.0]

    os.makedirs(stego_dir, exist_ok=True)
    video_exts = {".mp4", ".avi"}
    results = []

    for fname in sorted(os.listdir(clean_dir)):
        if os.path.splitext(fname)[1].lower() not in video_exts:
            continue
        input_path = os.path.join(clean_dir, fname)
        for fill in fills:
            output_path = _make_output_path(fname, stego_dir, fill)
            print(f"  {fname}  fill={fill:.2f}  =>  {os.path.basename(output_path)}")
            results.append(embed_lsb_video(input_path, output_path, fill))

    return results


def _make_output_path(input_filename: str, output_dir: str, fill_ratio: float) -> str:
    stem     = os.path.splitext(os.path.basename(input_filename))[0]
    fill_pct = f"{int(fill_ratio * 100):03d}"
    return os.path.join(output_dir, f"{stem}_stego_{fill_pct}pct.mkv")


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSB Video Embedder — do testów steganografii")
    parser.add_argument("input",  help="Plik wejściowy (MP4, AVI, ...)")
    parser.add_argument("--fill", type=float, default=0.5,
                        help="Współczynnik wypełnienia 0.0–1.0 (domyślnie 0.5)")
    args = parser.parse_args()

    if not (0.0 < args.fill <= 1.0):
        print("Błąd: --fill musi być między 0.01 a 1.0")
        sys.exit(1)

    output_path = _make_output_path(
        args.input,
        os.path.dirname(os.path.abspath(args.input)),
        args.fill,
    )
    info = embed_lsb_video(args.input, output_path, args.fill)

    print(f"\n  Gotowe!")
    print(f"  Wejście:        {info['input']}")
    print(f"  Wyjście:        {info['output']}")
    print(f"  Klatek:         {info['total_frames']}")
    print(f"  FPS:            {info['fps']}")
    print(f"  Rozdzielczość:  {info['resolution'][0]}x{info['resolution'][1]}")
    print(f"  Fill ratio:     {info['fill_ratio'] * 100:.0f}%")
