"""
embed_video_full.py — osadzanie steganografii w obu kanałach wideo (LSB visual + group-parity audio)

Dla każdego pliku wideo:
  1. Klatki wizualne : LSB 50% fill (identycznie jak video_embed.py)
  2. Ścieżka audio  : group-parity LSB ~50% capacity (identycznie jak audio_lsb.py)
  3. Mux            : ffmpeg łączy bezstratne klatki (FFV1) + PCM audio → MKV

Wyjście: <stem>_stego_full.mkv

Uruchom:
  python embed_video_full.py "ścieżka/do/video.mp4"
  python embed_video_full.py "ścieżka/do/video.mp4" "ścieżka/do/video2.mov"
"""

import sys
import os
import argparse
import struct
import tempfile
import shutil
import subprocess
import wave
import random
import string
import numpy as np
import cv2


# ── Ścieżka do audio_lsb.py ───────────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_AUDIO_LSB  = os.path.join(_SCRIPT_DIR, '..', 'detectors', 'audio', 'audio_lsb.py')

sys.path.insert(0, os.path.abspath(os.path.join(_SCRIPT_DIR, '..', 'detectors', 'audio')))
try:
    from audio_lsb import hide_message as audio_hide_message
    _HAS_AUDIO_LSB = True
except ImportError:
    _HAS_AUDIO_LSB = False


# ── Lokalizacja ffmpeg ────────────────────────────────────────────────────────

def _find_ffmpeg() -> str:
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


FFMPEG = _find_ffmpeg()


# ── Wizualny LSB embed w klatkach ─────────────────────────────────────────────

def _embed_visual_frames(input_path: str, output_mkv: str, fill_ratio: float = 0.5) -> dict:
    """
    Wpisuje losowe bity w LSB każdej klatki wideo i zapisuje do bezstratnego MKV (FFV1).
    Plik wyjściowy nie zawiera ścieżki audio.
    """
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise ValueError(f"Nie można otworzyć wideo: {input_path}")

    fps          = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    width        = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height       = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    fourcc = cv2.VideoWriter_fourcc(*"FFV1")
    writer = cv2.VideoWriter(output_mkv, cv2.CAP_FFMPEG, fourcc, fps, (width, height))

    frames_written = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break

        flat    = frame.flatten()
        n_embed = int(len(flat) * fill_ratio)
        bits    = np.random.randint(0, 2, size=n_embed, dtype=np.uint8)
        flat[:n_embed] = (flat[:n_embed] & np.uint8(0xFE)) | bits
        writer.write(flat.reshape(frame.shape))
        frames_written += 1

    cap.release()
    writer.release()

    return {
        "frames_written": frames_written,
        "fill_ratio":     fill_ratio,
        "fps":            fps,
        "resolution":     (width, height),
    }


# ── Ekstrakcja audio do WAV ───────────────────────────────────────────────────

def _extract_audio(video_path: str, out_wav: str) -> bool:
    """Wyodrębnij ścieżkę audio z wideo do mono WAV 44100 Hz. Zwraca True jeśli udało się."""
    if not FFMPEG:
        return False

    proc = subprocess.run(
        [FFMPEG, '-y', '-i', video_path,
         '-vn', '-ar', '44100', '-ac', '1',
         '-acodec', 'pcm_s16le', '-f', 'wav', out_wav],
        capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        return False
    return os.path.isfile(out_wav) and os.path.getsize(out_wav) > 44


# ── Payload na 50% capacity ──────────────────────────────────────────────────

def _make_50pct_payload(wav_path: str, group_size: int = 8) -> str:
    """
    Generuje losowy payload ASCII o długości ~50% pojemności pliku WAV.
    audio_lsb używa 1 grupy na 1 bit → każdy bajt tekstu UTF-8 zużywa 8 grup.
    """
    with wave.open(wav_path, 'rb') as wf:
        n_channels = wf.getnchannels()
        n_frames   = wf.getnframes()
    n_samples  = n_frames * n_channels
    n_groups   = n_samples // group_size
    # 32 grup na nagłówek długości; reszta to bity wiadomości (1 bit = 1 bit UTF-8)
    capacity_bits = n_groups - 32
    if capacity_bits <= 0:
        return "StegTest50pct"
    payload_bits  = capacity_bits // 2         # 50% capacity
    payload_bytes = max(1, payload_bits // 8)  # UTF-8 ASCII: 1 bajt = 8 bitów = 8 grup

    chars = string.ascii_letters + string.digits + " .,!?-_"
    return ''.join(random.choices(chars, k=payload_bytes))


# ── Audio stego embed ─────────────────────────────────────────────────────────

def _embed_audio_stego(input_wav: str, output_wav: str) -> dict:
    """Osadza losowy payload ~50% capacity w pliku WAV metodą group-parity LSB."""
    if not _HAS_AUDIO_LSB:
        raise ImportError("audio_lsb.py niedostępny — sprawdź detectors/audio/audio_lsb.py")

    payload = _make_50pct_payload(input_wav)
    audio_hide_message(input_wav, payload, output_wav)
    return {
        "payload_bytes": len(payload.encode('utf-8')),
        "method":        "group_parity_lsb",
    }


# ── Mux wideo + audio ─────────────────────────────────────────────────────────

def _mux(video_no_audio: str, audio_wav: str, output_path: str):
    """Łączy wideo (FFV1) i audio (WAV) w jeden plik MKV zachowując lossless."""
    if not FFMPEG:
        raise RuntimeError("ffmpeg nie znaleziony — nie można zmuxować pliku.")

    subprocess.run(
        [FFMPEG, '-y',
         '-i', video_no_audio,
         '-i', audio_wav,
         '-c:v', 'copy',
         '-c:a', 'pcm_s16le',
         output_path],
        capture_output=True, check=True, timeout=300,
    )


# ── Główna funkcja embeddera ──────────────────────────────────────────────────

def embed_full(input_path: str, output_path: str, fill_ratio: float = 0.5) -> dict:
    """
    Tworzy plik wideo ze steganografią w obu kanałach.

    Parametry
    ---------
    input_path  : plik wejściowy (MP4, MOV, AVI, ...)
    output_path : plik wyjściowy (MKV)
    fill_ratio  : udział pikseli z LSB-stego w klatce (domyślnie 0.5 = 50%)
    """
    tmp_vid  = tempfile.mktemp(suffix='_vid.mkv')
    tmp_wav  = tempfile.mktemp(suffix='_audio_clean.wav')
    tmp_steg = tempfile.mktemp(suffix='_audio_stego.wav')
    report   = {
        "input":      input_path,
        "output":     output_path,
        "fill_ratio": fill_ratio,
        "visual":     {},
        "audio":      {},
        "has_audio":  False,
    }

    try:
        print(f"[1/3] Osadzanie LSB w klatkach ({int(fill_ratio*100)}% fill)...")
        report["visual"] = _embed_visual_frames(input_path, tmp_vid, fill_ratio)
        print(f"      {report['visual']['frames_written']} klatek zapisano => {os.path.basename(tmp_vid)}")

        print("[2/3] Ekstrakcja ścieżki audio...")
        has_audio = _extract_audio(input_path, tmp_wav)

        if has_audio:
            report["has_audio"] = True
            print("      Audio znalezione — osadzanie group-parity stego (50% capacity)...")
            report["audio"] = _embed_audio_stego(tmp_wav, tmp_steg)
            print(f"      Payload: {report['audio']['payload_bytes']:,} bajtów")

            print("[3/3] Muxowanie wideo + audio → wynik...")
            _mux(tmp_vid, tmp_steg, output_path)
        else:
            print("      Brak ścieżki audio — zapis tylko wizualnego stego.")
            report["audio"]["note"] = "no_audio_track"
            shutil.copy2(tmp_vid, output_path)

        size_mb = os.path.getsize(output_path) / (1024 * 1024)
        print(f"\n  [OK] {os.path.basename(output_path)} ({size_mb:.1f} MB)\n")
        report["output_size_mb"] = round(size_mb, 2)

    finally:
        for f in [tmp_vid, tmp_wav, tmp_steg]:
            if os.path.exists(f):
                try:
                    os.unlink(f)
                except OSError:
                    pass

    return report


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dual-channel stego embedder: LSB w klatkach + group-parity w audio"
    )
    parser.add_argument("inputs", nargs="+", help="Pliki wideo wejściowe (MP4, MOV, AVI ...)")
    parser.add_argument("--fill", type=float, default=0.5,
                        help="Wypełnienie LSB w klatkach, 0.01–1.0 (domyślnie 0.5)")
    parser.add_argument("--outdir", default=None,
                        help="Katalog wyjściowy (domyślnie: ten sam co plik wejściowy)")
    args = parser.parse_args()

    if not FFMPEG:
        print("BŁĄD: ffmpeg nie znaleziony. Zainstaluj przez: conda install ffmpeg")
        sys.exit(1)

    if not _HAS_AUDIO_LSB:
        print("BŁĄD: audio_lsb.py nie znaleziony w detectors/audio/")
        sys.exit(1)

    for src in args.inputs:
        if not os.path.isfile(src):
            print(f"[POMINIĘTO] Plik nie istnieje: {src}")
            continue

        stem    = os.path.splitext(os.path.basename(src))[0]
        outdir  = args.outdir if args.outdir else os.path.dirname(os.path.abspath(src))
        outfile = os.path.join(outdir, f"{stem}_stego_full.mkv")

        print(f"\n{'='*60}")
        print(f"  Wejście : {src}")
        print(f"  Wyjście : {outfile}")
        print(f"{'='*60}")

        import json as _json
        rpt = embed_full(src, outfile, args.fill)
        print(_json.dumps(rpt, indent=2, ensure_ascii=False))
