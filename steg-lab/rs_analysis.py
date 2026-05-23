"""
Detektor steganografii — metoda RS (Regular-Singular)
Na podstawie: Fridrich, Goljan, Du (2001)

Uruchom: python rs_analysis.py ścieżka/do/obrazu.png
"""

import sys
import datetime
import logging
import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)


class RSAnalysisDetector:
    """
    Jak działa RS w jednym zdaniu:
      nakładamy dwie maski (M i -M) na bloki 4 pikseli i liczymy
      ile bloków stało się 'głośniejszych' (Regular) po maskowaniu.

    Kluczowa obserwacja (Fridrich 2001):
      Czysty obraz:  maska M daje WIĘCEJ bloków Regular niż maska -M
                     → rm_rate > r_m_rate  → rs_diff DODATNI
      Obraz ze stego: maska -M daje WIĘCEJ bloków Regular niż maska M
                     → r_m_rate > rm_rate  → rs_diff UJEMNY → detekcja

    Detekcja: rs_diff < -threshold
      (domyślnie threshold=0.01 — mała wartość żeby unikać szumu)

    Dlaczego normalizujemy osobno dla M i -M?
      Maska -M nie może zmienić pikseli przy granicy 255 (255+1=256→clip=255).
      W jasnych zdjęciach to tworzy wiele bloków 'Unusable'.
      Normalizacja rm/(rm+sm) ignoruje Unusable → algorytm działa mimo to.
    """

    def __init__(self, threshold: float = 0.01, block_size: int = 4,
                 saturation_threshold: float = 5.0):
        self.threshold            = threshold
        self.block_size           = block_size
        # Próg nasycenia: jeśli mean std między kanałami RGB < progu → obraz traktowany jako grayscale
        self.saturation_threshold = saturation_threshold

    def analyze(self, filepath: str, pil_image=None) -> dict:
        result = {
            "method":        "rs_analysis",
            "detected":      False,
            "rs_difference": None,
            "confidence":    0.0,
            "timestamp":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "details":       {}
        }

        try:
            src      = pil_image if pil_image is not None else Image.open(filepath)
            use_rgb  = self._is_rgb_mode(src)

            if use_rgb:
                # ── Tryb RGB: analizuj R, G, B osobno, uśrednij rs_diff ──────
                rgb      = np.array(src.convert("RGB"), dtype=int)
                n_blocks = (rgb.shape[0] * rgb.shape[1]) // self.block_size
                ch_diffs   = []
                ch_details = {}

                for idx, ch in enumerate(("R", "G", "B")):
                    flat = rgb[:, :, idx].flatten()
                    rm, sm, r_m, s_m = self._compute_rs_groups(flat)

                    m_cl  = rm + sm
                    nm_cl = r_m + s_m
                    if m_cl == 0 or nm_cl == 0:
                        raise ValueError(f"Za mało sklasyfikowanych bloków w kanale {ch}")

                    rm_rate  = rm  / m_cl
                    r_m_rate = r_m / nm_cl
                    diff_ch  = rm_rate - r_m_rate
                    ch_diffs.append(diff_ch)

                    ch_details[ch] = {
                        "R_M":               round(float(rm),  4),
                        "S_M":               round(float(sm),  4),
                        "R_-M":              round(float(r_m), 4),
                        "S_-M":              round(float(s_m), 4),
                        "rm_rate":           round(rm_rate,    4),
                        "r_m_rate":          round(r_m_rate,   4),
                        "rs_diff":           round(diff_ch,    4),
                        "unusable_M_pct":    round(1 - m_cl  / n_blocks, 4),
                        "unusable_negM_pct": round(1 - nm_cl / n_blocks, 4),
                    }

                rs_diff = float(np.mean(ch_diffs))
                result["details"] = {
                    "analysis_mode":       "RGB",
                    "rs_diff_per_channel": {c: ch_details[c]["rs_diff"] for c in ("R", "G", "B")},
                    "channels":            ch_details,
                }

            else:
                # ── Tryb L: analiza kanału grayscale (oryginalne zachowanie) ──
                pixels = np.array(src.convert("L"), dtype=int)
                rm, sm, r_m, s_m = self._compute_rs_groups(pixels)

                m_cl  = rm + sm
                nm_cl = r_m + s_m
                if m_cl == 0 or nm_cl == 0:
                    raise ValueError("Za mało sklasyfikowanych bloków")

                rm_rate  = rm  / m_cl
                r_m_rate = r_m / nm_cl
                rs_diff  = float(rm_rate - r_m_rate)

                n_blocks = len(pixels.flatten()) // self.block_size
                result["details"] = {
                    "analysis_mode":     "L",
                    "R_M":               round(float(rm),  4),
                    "S_M":               round(float(sm),  4),
                    "R_-M":              round(float(r_m), 4),
                    "S_-M":              round(float(s_m), 4),
                    "rm_rate":           round(rm_rate,    4),
                    "r_m_rate":          round(r_m_rate,   4),
                    "unusable_M_pct":    round(1 - m_cl  / n_blocks, 4),
                    "unusable_negM_pct": round(1 - nm_cl / n_blocks, 4),
                }

            result["rs_difference"] = round(float(rs_diff), 4)

            # ── Detekcja — ta sama logika niezależnie od trybu ───────────────
            # rs_diff PODPISANY:
            #   > 0 → M reguluje więcej niż -M → obraz naturalny → CZYSTY
            #   < 0 → -M reguluje więcej niż M → LSB zaburzone   → STEGO
            if rs_diff < -self.threshold:
                result["detected"]   = True
                result["confidence"] = round(min(1.0, abs(rs_diff)), 4)
                logger.debug("[WYKRYTO]  rs_diff=%.4f (mode=%s) — steganografia LSB",
                             rs_diff, "RGB" if use_rgb else "L")
            else:
                result["confidence"] = 0.0
                logger.debug("[CZYSTE]   rs_diff=%.4f (mode=%s) — brak detekcji",
                             rs_diff, "RGB" if use_rgb else "L")

        except Exception as e:
            result["error"] = str(e)
            logger.error("[BŁĄD] rs_analysis: %s", e)

        return result

    def _is_rgb_mode(self, img: Image.Image) -> bool:
        """
        Decyduje czy analizować per-kanał RGB czy kanał L.

        Logika:
          1. Jeśli img.mode nie jest RGB/RGBA → False (grayscale)
          2. Jeśli RGB ale mean std między kanałami < saturation_threshold → False
             (obraz jest technicznie RGB ale praktycznie jednobarwny, np. B&W JPEG)
          3. W pozostałych przypadkach → True (analiza RGB)

        saturation_threshold domyślnie 5.0 (skala 0-255).
        """
        if img.mode not in ("RGB", "RGBA"):
            return False
        rgb = np.array(img.convert("RGB"), dtype=np.float32)
        mean_channel_std = float(np.std(rgb, axis=2).mean())
        return mean_channel_std >= self.saturation_threshold

    def _noise_measure(self, block: np.ndarray) -> float:
        """Suma różnic bezwzględnych sąsiednich pikseli."""
        return float(np.sum(np.abs(np.diff(block))))

    def _apply_mask(self, block: np.ndarray, negative: bool = False) -> np.ndarray:
        """
        Maska M  (negative=False): XOR 1 na pozycjach 0, 2
          → 255 XOR 1 = 254  (brak problemu granicy!)
          → 0   XOR 1 = 1    (brak problemu granicy!)

        Maska -M (negative=True): odwrotność M
          Even → -1 (z clippingiem: 0 → zostaje 0, Unusable)
          Odd  → +1 (z clippingiem: 255 → zostaje 255, Unusable)

        Unusable bloki są pomijane w klasyfikacji i wykluczane z normalizacji.
        """
        result = block.copy()
        for i in range(0, len(result), 2):
            if not negative:
                result[i] = result[i] ^ 1        # flip LSB — zawsze bezpieczne
            else:
                if result[i] % 2 == 0:
                    result[i] = max(0,   result[i] - 1)
                else:
                    result[i] = min(255, result[i] + 1)
        return result

    def _compute_rs_groups(self, pixels: np.ndarray):
        """Wektoryzowana klasyfikacja bloków jako R, S lub U (Unusable)."""
        flat    = pixels.flatten()
        n_blocks = len(flat) // self.block_size

        blocks = flat[:n_blocks * self.block_size].reshape(n_blocks, self.block_size)

        f0 = np.sum(np.abs(np.diff(blocks, axis=1)), axis=1)

        masked_M = blocks.copy()
        masked_M[:, 0::2] ^= 1
        fM = np.sum(np.abs(np.diff(masked_M, axis=1)), axis=1)

        masked_N = blocks.copy()
        masked_N[:, 0::2] = np.where(
            masked_N[:, 0::2] % 2 == 0,
            np.maximum(masked_N[:, 0::2] - 1, 0),
            np.minimum(masked_N[:, 0::2] + 1, 255)
        )
        fN = np.sum(np.abs(np.diff(masked_N, axis=1)), axis=1)

        rm = np.sum(fM > f0)
        sm = np.sum(fM < f0)
        r_m = np.sum(fN > f0)
        s_m = np.sum(fN < f0)

        return rm, sm, r_m, s_m


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Użycie: python rs_analysis.py obraz.png")
        sys.exit(1)
    detector = RSAnalysisDetector(threshold=0.01)
    wynik = detector.analyze(sys.argv[1])
    print(wynik)