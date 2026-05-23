"""
network_stego_detector.py — detektor steganografii sieciowej dla SIEM
Wypisuje JSON na stdout.

Użycie:
  python network_stego_detector.py --mode dns  --file queries.json
  python network_stego_detector.py --mode icmp --file packets.json
  python network_stego_detector.py --mode iat  --timestamps 1.0 1.1 1.2 1.5
  python network_stego_detector.py --mode combined --file traffic.json
"""

import sys
import os
import re
import json
import math
import datetime
import argparse
import logging
from collections import Counter

import numpy as np
from scipy import stats

logger = logging.getLogger(__name__)

# ── stałe ─────────────────────────────────────────────────────────────────────
WEIGHTS = {"dns": 0.45, "icmp": 0.35, "iat": 0.20}

VERDICT_CLEAN      = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_DETECTED   = "DETECTED"

STANDARD_ICMP_SIZES = {32, 48, 56, 64}


# ── pomocnicza funkcja entropii ────────────────────────────────────────────────
def _shannon_entropy(text: str) -> float:
    """Entropia Shannona ciągu znaków (bity)."""
    if not text:
        return 0.0
    counts = Counter(text)
    total  = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _extract_subdomain(query_name: str) -> str:
    """
    Wyodrębnia subdomenę z pełnej nazwy DNS.
    Zakłada, że dwie ostatnie etykiety to domena zarejestrowana (np. evil.com).
    Przykład: 'aB3xYz1.evil.com' → 'aB3xYz1'
    """
    parts = query_name.rstrip(".").split(".")
    if len(parts) <= 2:
        return parts[0] if parts else ""
    return ".".join(parts[:-2])


# ── wzorce alfabetów kodowania używanych przez narzędzia tunelujące ───────────
_RE_BASE32 = re.compile(r'^[a-z2-7]+=*$',          re.IGNORECASE)
_RE_HEX    = re.compile(r'^[a-f0-9]+$',             re.IGNORECASE)
_RE_BASE64 = re.compile(r'^[a-zA-Z0-9+/=]+$')


def _classify_alphabet(subdomain: str) -> str:
    """
    Klasyfikuje alfabet subdomeny.
    Nie strippujemy myślników — normalne hosty często je mają (api-v2, cdn-eu),
    a narzędzia tunelujące (iodine, dnscat2) używają surowych bajtów bez myślników.
    Kolejność: base32 przed hex (base32 ⊂ hex dla liter a-f).
    """
    if not subdomain:
        return "normal"
    # myślnik w subdomenie → prawie na pewno normalny hostname
    if "-" in subdomain:
        return "normal"
    s = subdomain.rstrip("=")   # usuń tylko padding base32/64
    if _RE_BASE32.fullmatch(s):
        return "base32"
    if _RE_HEX.fullmatch(s):
        return "hex"
    if _RE_BASE64.fullmatch(s):
        return "base64"
    ent = _shannon_entropy(s)
    return "mixed" if ent > 3.2 else "normal"


def _domain_concentration(queries: list, top_ip: str) -> float:
    """
    Jaki % zapytań tego IP idzie do jednej base-domeny (ostatnie 2 etykiety).
    Tunel DNS: 1.0 (wszystko do evil.com).
    Resolver korporacyjny: ~0.001 (tysiące różnych domen).
    """
    ip_queries = [q for q in queries if q.get("source_ip") == top_ip]
    if not ip_queries:
        return 0.0
    base_counter = Counter()
    for q in ip_queries:
        parts = q.get("query_name", "").rstrip(".").split(".")
        base  = ".".join(parts[-2:]) if len(parts) >= 2 else q.get("query_name", "")
        base_counter[base] += 1
    top_count = base_counter.most_common(1)[0][1]
    return top_count / len(ip_queries)


# ══════════════════════════════════════════════════════════════════════════════
class DnsTunnelingDetector:
    """
    Wykrywa tunelowanie DNS: ukrywanie danych w subdomenach zapytań DNS.

    Wykrywane narzędzia: iodine, dnscat2, DNSExfiltrator, dns2tcp
    Użycie przez APT: APT34/OilRig (Iran) — kanał C&C, opisany przez Cisco Talos 2017

    Podstawa akademicka:
      Drzymała, Szczypiorski, Urbański (2016) — "Network Steganography in the DNS Protocol"

    Ulepszenia względem wersji v1 (na podstawie testów na pcap iodine):
      - Częściowy credit dla entropii 2.0–3.5 i długości 10–30 (nie tylko binary próg)
      - Stopniowany rate_conf (0.35/0.55/0.75) zamiast binarnego 0/1
      - Detekcja alfabetu base32 (iodine celowo obniża entropię przez RFC 4648)
      - Pole subdomain_alphabet i base32_matches w outputcie

    Progi (parametry __init__):
      entropy_threshold (3.5) — entropia hard-flag; częściowy credit od 2.0
      length_threshold  (30)  — długość hard-flag; częściowy credit od 10
      rate_threshold    (50)  — próg pierwszego stopnia rate_conf
    """

    def __init__(self, entropy_threshold: float = 3.5,
                 length_threshold: int = 30,
                 rate_threshold: int = 50):
        self.entropy_threshold = entropy_threshold
        self.length_threshold  = length_threshold
        self.rate_threshold    = rate_threshold

    def analyze(self, queries: list) -> dict:
        """
        queries: lista słowników z kluczami:
          query_name  (str)   — pełna nazwa DNS
          timestamp   (float) — unix timestamp
          source_ip   (str)   — adres źródłowy
        """
        result = {
            "method":               "dns_tunneling",
            "detected":             False,
            "confidence":           0.0,
            "entropy":              None,
            "subdomain_length":     None,
            "subdomain_alphabet":   "normal",
            "base32_matches":       0,
            "domain_concentration": None,
            "flagged_queries":      [],
            "query_rate":           0,
        }

        if not queries:
            result["error"] = "Brak zapytań DNS"
            return result

        flagged        = []
        entropies      = []
        lengths        = []
        base32_count   = 0
        alphabet_votes = Counter()
        ip_counter     = Counter(q.get("source_ip", "") for q in queries)

        for q in queries:
            name      = q.get("query_name", "")
            subdomain = _extract_subdomain(name)
            if not subdomain:
                continue

            ent   = _shannon_entropy(subdomain)
            ln    = len(subdomain)
            alpha = _classify_alphabet(subdomain)

            entropies.append(ent)
            lengths.append(ln)
            alphabet_votes[alpha] += 1

            # ln>=12: eliminuje normalne krótkie hosty (mail, static, imap ≤ 11 znaków)
            if alpha == "base32" and ln >= 12:
                base32_count += 1

            if ent > self.entropy_threshold or ln > self.length_threshold:
                flagged.append(name)

        mean_ent = round(float(np.mean(entropies)), 4) if entropies else 0.0
        mean_len = round(float(np.mean(lengths)),   2) if lengths   else 0.0

        result["flagged_queries"]    = flagged
        result["entropy"]            = mean_ent
        result["subdomain_length"]   = mean_len
        result["base32_matches"]     = base32_count
        result["subdomain_alphabet"] = (alphabet_votes.most_common(1)[0][0]
                                        if alphabet_votes else "normal")

        max_rate = max(ip_counter.values()) if ip_counter else 0
        result["query_rate"] = int(max_rate)

        # Koncentracja domeny: tunel → 1 IP pyta zawsze o 1 domenę C2
        #   resolver → 1 IP (forwarder) pyta o tysiące różnych domen
        top_ip      = ip_counter.most_common(1)[0][0] if ip_counter else ""
        conc        = _domain_concentration(queries, top_ip)
        result["domain_concentration"] = round(conc, 4)

        # ── składowe pewności (v2) ────────────────────────────────────────────
        # Entropia: partial credit 2.0–3.5, hard 1.0 powyżej 3.5
        if mean_ent >= self.entropy_threshold:
            entropy_conf = 1.0
        else:
            entropy_conf = max(0.0, (mean_ent - 2.0) / 1.5)

        # Długość: partial credit 10–30, hard 1.0 powyżej 30
        if mean_len >= self.length_threshold:
            length_conf = 1.0
        else:
            length_conf = max(0.0, (mean_len - 10.0) / 20.0)

        # Rate skalowany przez koncentrację domeny:
        #   iodine (rate=181, conc=1.0) → pełna waga
        #   resolver (rate=15000, conc=0.001) → spada do ~0
        if max_rate > 200:
            base_rate = 0.75
        elif max_rate > 100:
            base_rate = 0.55
        elif max_rate > self.rate_threshold:
            base_rate = 0.35
        else:
            base_rate = 0.0
        rate_conf = base_rate * conc

        # Base32: sygnał specyficzny dla iodine (RFC 4648, małe znaki + 2-7)
        n_sub = len(entropies)
        base32_conf = min(0.30, (base32_count / n_sub) * 1.5 * 0.30) if n_sub > 0 else 0.0

        raw_conf   = (entropy_conf * 0.30 +
                      length_conf  * 0.25 +
                      rate_conf    * 0.30 +
                      base32_conf)          # max 0.30 wliczone w skalowanie

        confidence = round(min(1.0, raw_conf), 4)

        result["confidence"] = confidence
        result["detected"]   = (len(flagged) > 0 or
                                 max_rate > self.rate_threshold or
                                 confidence >= 0.25)

        return result


# ══════════════════════════════════════════════════════════════════════════════
class IcmpTunnelingDetector:
    """
    Wykrywa tunelowanie ICMP: ukrywanie danych w polu payload pakietów ICMP Echo.

    Wykrywane narzędzia: ptunnel, icmptunnel, Hans, PingTunnel
    Użycie przez APT: udokumentowane przypadki APT eksfiltracji przez ICMP (MITRE ATT&CK T1095)

    Podstawa akademicka:
      Mazurczyk, Szczypiorski (2014) — "Principles and Overview of Network Steganography"

    Progi (parametry __init__):
      cv_threshold      (0.05) — współczynnik zmienności (CV = std/mean) payload_size;
                                  legitymalne pingi mają stałe rozmiary → CV≈0,
                                  ale jeśli CV jest podejrzanie małe przy dużej liczbie pakietów
                                  (i rozmiary niestandardowe) → tunelowanie
      rr_threshold      (3.0)  — stosunek request/reply > 3 wskazuje narzędzia tunelujące
                                  (wysyłają wiele żądań, mało odpowiedzi)
    """

    def __init__(self, cv_threshold: float = 0.05,
                 rr_threshold: float = 3.0):
        self.cv_threshold = cv_threshold
        self.rr_threshold = rr_threshold

    def analyze(self, packets: list) -> dict:
        """
        packets: lista słowników z kluczami:
          payload_size (int)   — rozmiar payloadu ICMP w bajtach
          timestamp    (float) — unix timestamp
          source_ip    (str)   — adres źródłowy
          icmp_type    (int)   — 0=echo reply, 8=echo request
        """
        result = {
            "method":             "icmp_tunneling",
            "detected":           False,
            "confidence":         0.0,
            "mean_payload":       None,
            "payload_cv":         None,
            "non_standard_ratio": None,
            "request_reply_ratio": None,
        }

        if not packets:
            result["error"] = "Brak pakietów ICMP"
            return result

        sizes    = np.array([p.get("payload_size", 0) for p in packets], dtype=float)
        types    = [p.get("icmp_type", 0) for p in packets]

        mean_size = float(np.mean(sizes))
        std_size  = float(np.std(sizes))
        cv        = std_size / mean_size if mean_size > 0 else 0.0

        non_standard = sum(1 for s in sizes if int(s) not in STANDARD_ICMP_SIZES)
        ns_ratio     = non_standard / len(sizes)

        requests = sum(1 for t in types if t == 8)
        replies  = sum(1 for t in types if t == 0)
        rr_ratio = requests / replies if replies > 0 else float(requests)

        result["mean_payload"]        = round(mean_size, 2)
        result["payload_cv"]          = round(cv,        4)
        result["non_standard_ratio"]  = round(ns_ratio,  4)
        result["request_reply_ratio"] = round(rr_ratio,  4)

        # ── składowe wykrycia ─────────────────────────────────────────────────
        ns_flag    = ns_ratio > 0.5
        rr_flag    = rr_ratio > self.rr_threshold
        # stały, niestandardowy rozmiar = dane wbudowane o stałej ramce
        cv_flag    = (cv < self.cv_threshold) and ns_ratio > 0.3

        flags = [ns_flag, rr_flag, cv_flag]
        n_flags   = sum(flags)

        ns_score  = min(1.0, ns_ratio * 1.5)
        rr_score  = min(1.0, (rr_ratio - 1.0) / (self.rr_threshold * 2)) if rr_ratio > 1 else 0.0
        cv_score  = min(1.0, 1.0 - cv) if cv_flag else 0.0
        confidence = round(0.5 * ns_score + 0.35 * rr_score + 0.15 * cv_score, 4)

        result["confidence"] = min(1.0, confidence)
        result["detected"]   = n_flags >= 1

        return result


# ══════════════════════════════════════════════════════════════════════════════
class IATStegoDetector:
    """
    Wykrywa kanały czasowe (timing covert channels) oparte na Inter-Arrival Times (IAT).

    Atakujący moduluje opóźnienie między pakietami, aby zakodować bity danych.
    Technika używana przez zaawansowane APT w ruchu strumieniowym (VoIP, media).

    Wykrywane narzędzia/techniki: MoveSteg, Jitterbug, TRIDENT
    Użycie przez APT: dokumentowane w akademickich badaniach kanałów ukrytych

    Podstawa akademicka:
      Szczypiorski & Tyl (2016) — "MoveSteg: A Method of Network Steganography Detection"

    Progi (parametry __init__):
      cv_threshold   (0.15) — CV < progu → ruch podejrzanie regularny → kanał czasowy
                               Normalny ruch sieciowy ma CV > 0.5 (rozłożony wykładniczo)
      ks_alpha       (0.05) — poziom istotności testu KS vs ruch referencyjny
    """

    def __init__(self, cv_threshold: float = 0.15, ks_alpha: float = 0.05):
        self.cv_threshold = cv_threshold
        self.ks_alpha     = ks_alpha

    def analyze(self, timestamps: list,
                reference_iats=None) -> dict:
        """
        timestamps:     posortowane uniksowe znaczniki czasu pakietów
        reference_iats: opcjonalne IAT czystego ruchu do testu KS
        """
        result = {
            "method":    "iat_timing",
            "detected":  False,
            "confidence": 0.0,
            "mean_iat":  None,
            "std_iat":   None,
            "cv":        None,
            "ks_pvalue": None,
        }

        if len(timestamps) < 3:
            result["error"] = "Za mało znaczników czasu (minimum 3)"
            return result

        ts   = np.sort(np.array(timestamps, dtype=float))
        iats = np.diff(ts)

        if len(iats) == 0:
            result["error"] = "Nie można obliczyć IAT"
            return result

        mean_iat = float(np.mean(iats))
        std_iat  = float(np.std(iats))
        cv       = std_iat / mean_iat if mean_iat > 0 else 0.0

        result["mean_iat"] = round(mean_iat, 6)
        result["std_iat"]  = round(std_iat,  6)
        result["cv"]       = round(cv,       4)

        cv_flag  = cv < self.cv_threshold
        ks_flag  = False
        ks_pval  = None

        if reference_iats is not None and len(reference_iats) >= 3:
            ks_stat, ks_pval = stats.ks_2samp(iats, reference_iats)
            result["ks_pvalue"] = round(float(ks_pval), 6)
            ks_flag = ks_pval < self.ks_alpha

        # ── pewność ───────────────────────────────────────────────────────────
        # im mniejsze CV poniżej progu, tym większa pewność
        cv_score  = min(1.0, max(0.0, (self.cv_threshold - cv) / self.cv_threshold)) if cv_flag else 0.0
        ks_score  = min(1.0, 1.0 - ks_pval) if (ks_flag and ks_pval is not None) else 0.0

        if ks_pval is not None:
            confidence = round(0.6 * cv_score + 0.4 * ks_score, 4)
        else:
            confidence = round(cv_score, 4)

        result["confidence"] = min(1.0, confidence)
        result["detected"]   = cv_flag or ks_flag

        return result


# ══════════════════════════════════════════════════════════════════════════════
class SteganographicCostAggregator:
    """
    Agreguje wyniki wielu detektorów sieciowych w jeden wynik ryzyka.

    Wagi oparte na skuteczności wykrywania w literaturze:
      DNS=0.45 (najczęstszy kanał eksfiltracji danych, wysoka precyzja detekcji)
      ICMP=0.35 (łatwo dostrzegalny w ruchu sieciowym, ale często ignorowany)
      IAT=0.20 (trudniejszy do detekcji, mniej pewny)

    Podstawa akademicka:
      Mazurczyk & Wendzel (2014) — "On importance of steganographic cost for network
      steganography"
    """

    def __init__(self, weights=None):
        self.weights = weights if weights is not None else WEIGHTS.copy()

    def aggregate(self, detector_results: dict) -> dict:
        """
        detector_results: słownik z wynikami detektorów:
          {"dns": <wynik DnsTunnelingDetector>, "icmp": ..., "iat": ...}
          Każdy klucz jest opcjonalny — agregacja działa na dostępnych detektorach.
        """
        weighted_sum    = 0.0
        total_weight    = 0.0
        triggered_count = 0
        channel_names   = []

        for channel, res in detector_results.items():
            if "error" in res:
                continue
            w = self.weights.get(channel, 0.0)
            weighted_sum  += res.get("confidence", 0.0) * w
            total_weight  += w
            if res.get("detected", False):
                triggered_count += 1
                channel_names.append(channel)

        if total_weight > 0:
            normalized_score = weighted_sum / total_weight
        else:
            normalized_score = 0.0

        risk_score = int(round(normalized_score * 100))

        if risk_score < 20:
            verdict = VERDICT_CLEAN
        elif risk_score < 60:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_DETECTED

        channel_label = "+".join(sorted(detector_results.keys())) if len(detector_results) > 1 else \
                        (next(iter(detector_results.keys())) if detector_results else "combined")

        warnings = []
        if any("error" in r for r in detector_results.values()):
            warnings.append("Niektóre detektory zwróciły błędy i zostały pominięte w agregacji")

        return {
            "timestamp":           datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type":          "network_stego_scan",
            "channel":             channel_label,
            "verdict":             verdict,
            "risk_score":          risk_score,
            "detectors_triggered": triggered_count,
            "detectors":           detector_results,
            "warnings":            warnings,
        }


# ── CLI ────────────────────────────────────────────────────────────────────────
def _load_json_file(path: str):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def _run_dns(args) -> dict:
    data    = _load_json_file(args.file)
    queries = data if isinstance(data, list) else data.get("queries", [])
    det     = DnsTunnelingDetector()
    result  = det.analyze(queries)
    agg     = SteganographicCostAggregator()
    return agg.aggregate({"dns": result})


def _run_icmp(args) -> dict:
    data    = _load_json_file(args.file)
    packets = data if isinstance(data, list) else data.get("packets", [])
    det     = IcmpTunnelingDetector()
    result  = det.analyze(packets)
    agg     = SteganographicCostAggregator()
    return agg.aggregate({"icmp": result})


def _run_iat(args) -> dict:
    if args.timestamps:
        timestamps = [float(t) for t in args.timestamps]
    elif args.file:
        data       = _load_json_file(args.file)
        timestamps = data if isinstance(data, list) else data.get("timestamps", [])
    else:
        return {"error": "Podaj --timestamps lub --file dla trybu iat"}

    ref = None
    if args.reference:
        ref_data = _load_json_file(args.reference)
        ref      = ref_data if isinstance(ref_data, list) else ref_data.get("timestamps", [])

    det    = IATStegoDetector()
    result = det.analyze(timestamps, reference_iats=ref)
    agg    = SteganographicCostAggregator()
    return agg.aggregate({"iat": result})


def _run_combined(args) -> dict:
    data = _load_json_file(args.file)

    results = {}

    if "queries" in data or (isinstance(data, list) and data and "query_name" in data[0]):
        queries    = data if isinstance(data, list) else data.get("queries", [])
        results["dns"] = DnsTunnelingDetector().analyze(queries)

    if "packets" in data or (isinstance(data, list) and data and "payload_size" in data[0]):
        packets     = data if isinstance(data, list) else data.get("packets", [])
        results["icmp"] = IcmpTunnelingDetector().analyze(packets)

    if "timestamps" in data:
        timestamps   = data["timestamps"]
        ref_iats     = data.get("reference_iats")
        results["iat"] = IATStegoDetector().analyze(timestamps, reference_iats=ref_iats)

    if not results:
        return {"error": "Nie rozpoznano struktury danych — brak kluczy 'queries', 'packets', 'timestamps'"}

    return SteganographicCostAggregator().aggregate(results)


def _run_pcap(args) -> dict:
    from pcap_parser import PcapParser

    parsed   = PcapParser().parse(args.pcap)
    results  = {}
    warnings = list(parsed.get("warnings", []))

    if parsed["dns_queries"]:
        results["dns"] = DnsTunnelingDetector().analyze(parsed["dns_queries"])
    else:
        warnings.append("Brak zapytan DNS w pliku PCAP — pominieto detektor DNS")

    if parsed["icmp_packets"]:
        results["icmp"] = IcmpTunnelingDetector().analyze(parsed["icmp_packets"])
    else:
        warnings.append("Brak pakietow ICMP w pliku PCAP — pominieto detektor ICMP")

    if len(parsed["all_timestamps"]) >= 3:
        results["iat"] = IATStegoDetector().analyze(parsed["all_timestamps"])
    else:
        warnings.append("Za malo pakietow do analizy IAT (wymagane minimum 3)")

    pcap_meta = {
        "file":            os.path.basename(args.pcap),
        "packet_count":    parsed["packet_count"],
        "duration_sec":    parsed["duration_sec"],
        "protocols_seen":  parsed["protocols_seen"],
        "skipped_packets": parsed["skipped_packets"],
    }

    if not results:
        return {
            "timestamp":           datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type":          "network_stego_scan",
            "channel":             "pcap",
            "verdict":             VERDICT_CLEAN,
            "risk_score":          0,
            "detectors_triggered": 0,
            "detectors":           {},
            "warnings":            warnings + ["Brak rozpoznanych protokolow — zwracam CLEAN"],
            "pcap_meta":           pcap_meta,
        }

    report = SteganographicCostAggregator().aggregate(results)
    report["warnings"].extend(warnings)
    report["pcap_meta"] = pcap_meta
    return report


def _print_pcap_summary(report: dict):
    """Czytelne podsumowanie analizy PCAP wypisywane na stderr."""
    if "error" in report:
        print(f"  BLAD: {report['error']}", file=sys.stderr)
        return

    v      = report.get("verdict", "?")
    risk   = report.get("risk_score", "?")
    trg    = report.get("detectors_triggered", 0)
    meta   = report.get("pcap_meta", {})
    colors = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m", "DETECTED": "\033[91m"}
    reset  = "\033[0m"
    color  = colors.get(v, "")

    print(f"\n=== Analiza PCAP: {meta.get('file', '?')} ===", file=sys.stderr)
    print(f"  Wynik:       {color}{v}{reset}  (risk_score={risk}, triggered={trg})",
          file=sys.stderr)
    print(f"  Pakiety:     {meta.get('packet_count', '?')}  "
          f"czas={meta.get('duration_sec', '?')}s  "
          f"protokoly={meta.get('protocols_seen', [])}",
          file=sys.stderr)
    if meta.get("skipped_packets", 0):
        print(f"  Pominieto:   {meta['skipped_packets']} pakietow (znieksztalcone)",
              file=sys.stderr)
    for w in report.get("warnings", []):
        print(f"  [!] {w}", file=sys.stderr)
    print("", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Detektor steganografii sieciowej — modul SIEM"
    )
    parser.add_argument("--mode", choices=["dns", "icmp", "iat", "combined"],
                        default=None,
                        help="Tryb detekcji (wymagany gdy brak --pcap)")
    parser.add_argument("--file",       help="Sciezka do pliku JSON z danymi")
    parser.add_argument("--pcap",       help="Sciezka do pliku PCAP (Wireshark/tcpdump)")
    parser.add_argument("--timestamps", nargs="+",
                        help="Lista znacznikow czasu (tylko dla --mode iat)")
    parser.add_argument("--reference",  help="Plik JSON z referencyjnymi IAT (tylko --mode iat)")
    parser.add_argument("--indent",     type=int, default=2, help="Wciecie JSON (0 = brak)")
    args = parser.parse_args()

    if not args.pcap and not args.mode:
        parser.error("Podaj --mode lub --pcap")

    dispatch = {
        "dns":      _run_dns,
        "icmp":     _run_icmp,
        "iat":      _run_iat,
        "combined": _run_combined,
    }

    try:
        if args.pcap:
            report = _run_pcap(args)
            _print_pcap_summary(report)
        else:
            report = dispatch[args.mode](args)
    except FileNotFoundError as e:
        report = {"error": f"Nie znaleziono pliku: {e}"}
    except json.JSONDecodeError as e:
        report = {"error": f"Blad parsowania JSON: {e}"}
    except Exception as e:
        report = {"error": str(e)}

    indent = args.indent if args.indent > 0 else None
    print(json.dumps(report, indent=indent, ensure_ascii=False))


if __name__ == "__main__":
    main()
