"""
generate_network_samples.py — generator syntetycznych próbek sieciowych dla testów
Tworzy pliki JSON w katalogu ./network_samples/ i uruchamia detektory na każdym.

Użycie:
  python generate_network_samples.py
"""

import json
import math
import os
import random
import string
import subprocess
import sys
import time

import numpy as np

OUTDIR   = os.path.join(os.path.dirname(__file__), "network_samples")
DETECTOR = os.path.join(os.path.dirname(__file__), "network_stego_detector.py")
RNG      = np.random.default_rng(42)


# ── pomocnicze ─────────────────────────────────────────────────────────────────
def _save(filename: str, data) -> str:
    path = os.path.join(OUTDIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  zapisano: {path}  ({len(data) if isinstance(data, list) else '—'} rekordów)")
    return path


def _run_detector(mode: str, filepath: str, extra=None) -> dict:
    cmd  = [sys.executable, DETECTOR, "--mode", mode, "--file", filepath, "--indent", "2"]
    if extra:
        cmd.extend(extra)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=30)
        if out.returncode != 0:
            return {"error": out.stderr.strip()}
        return json.loads(out.stdout)
    except Exception as e:
        return {"error": str(e)}


def _print_result(label: str, report: dict):
    if "error" in report:
        print(f"  [{label}]  BŁĄD: {report['error']}")
        return
    v      = report.get("verdict", "?")
    risk   = report.get("risk_score", "?")
    trg    = report.get("detectors_triggered", 0)
    colors = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m", "DETECTED": "\033[91m"}
    reset  = "\033[0m"
    color  = colors.get(v, "")
    print(f"  [{label}]  {color}{v}{reset}  risk={risk}  triggered={trg}")


# ── 1. dns_clean.json ──────────────────────────────────────────────────────────
CLEAN_SUBDOMAINS = [
    "mail", "www", "cdn", "api", "static", "smtp", "pop", "imap",
    "news", "ftp", "dev", "img", "assets", "dl", "files", "m",
]
CLEAN_DOMAINS = [
    "google.com", "facebook.com", "microsoft.com", "amazon.com",
    "example.com", "cloudflare.com", "akamai.net", "fastly.net",
]
CLEAN_IPS = ["192.168.1.10", "192.168.1.11", "10.0.0.5"]


def _gen_dns_clean(n: int = 100) -> list[dict]:
    base_ts  = 1_700_000_000.0
    queries  = []
    for i in range(n):
        sub  = random.choice(CLEAN_SUBDOMAINS)
        dom  = random.choice(CLEAN_DOMAINS)
        name = f"{sub}.{dom}"
        queries.append({
            "query_name": name,
            "timestamp":  round(base_ts + RNG.uniform(0, 60), 3),
            "source_ip":  random.choice(CLEAN_IPS),
        })
    return queries


# ── 2. dns_stego.json ──────────────────────────────────────────────────────────
BASE64_CHARS = string.ascii_letters + string.digits + "+/="
STEGO_IP     = "10.10.0.99"
STEGO_DOMAIN = "c2server.net"

def _rand_b64_subdomain(min_len: int = 30, max_len: int = 60) -> str:
    length = random.randint(min_len, max_len)
    return "".join(random.choices(BASE64_CHARS, k=length))


def _gen_dns_stego(n: int = 100) -> list[dict]:
    base_ts = 1_700_000_000.0
    queries = []
    stego_count = int(n * 0.70)
    clean_count = n - stego_count

    for i in range(stego_count):
        sub  = _rand_b64_subdomain()
        name = f"{sub}.{STEGO_DOMAIN}"
        queries.append({
            "query_name": name,
            "timestamp":  round(base_ts + i * 0.6, 3),
            "source_ip":  STEGO_IP,
        })
    for i in range(clean_count):
        sub  = random.choice(CLEAN_SUBDOMAINS)
        dom  = random.choice(CLEAN_DOMAINS)
        queries.append({
            "query_name": f"{sub}.{dom}",
            "timestamp":  round(base_ts + i * 2.0, 3),
            "source_ip":  random.choice(CLEAN_IPS),
        })
    random.shuffle(queries)
    return queries


# ── 3. icmp_clean.json ─────────────────────────────────────────────────────────
ICMP_IPS_CLEAN = ["172.16.0.1", "172.16.0.2"]

def _gen_icmp_clean(n: int = 50) -> list[dict]:
    base_ts = 1_700_000_000.0
    packets = []
    for i in range(n):
        # równy stosunek request/reply
        icmp_type   = 8 if i % 2 == 0 else 0
        payload_size = 32 if RNG.random() < 0.55 else 56
        packets.append({
            "payload_size": payload_size,
            "timestamp":    round(base_ts + i * 0.5 + float(RNG.uniform(0, 0.1)), 3),
            "source_ip":    random.choice(ICMP_IPS_CLEAN),
            "icmp_type":    icmp_type,
        })
    return packets


# ── 4. icmp_stego.json ─────────────────────────────────────────────────────────
STEGO_ICMP_IP = "172.16.99.1"

def _gen_icmp_stego(n: int = 50) -> list[dict]:
    base_ts  = 1_700_000_000.0
    packets  = []
    requests = int(n * 0.80)   # ~4:1 request/reply
    replies  = n - requests

    for i in range(requests):
        packets.append({
            "payload_size": int(RNG.integers(200, 1401)),
            "timestamp":    round(base_ts + i * 0.2, 3),
            "source_ip":    STEGO_ICMP_IP,
            "icmp_type":    8,
        })
    for i in range(replies):
        packets.append({
            "payload_size": int(RNG.integers(200, 1401)),
            "timestamp":    round(base_ts + i * 0.8 + 0.1, 3),
            "source_ip":    STEGO_ICMP_IP,
            "icmp_type":    0,
        })
    random.shuffle(packets)
    return packets


# ── 5. iat_clean.json ──────────────────────────────────────────────────────────
def _gen_iat_clean(n: int = 200) -> list[float]:
    """
    Ruch sieciowy w normalnych warunkach: IAT mają rozkład wykładniczy.
    CV rozkładu wykładniczego = 1.0 — idealnie różne od regularnych kanałów.
    """
    mean_iat = 0.05  # 50 ms między pakietami
    iats     = RNG.exponential(scale=mean_iat, size=n)
    ts       = [0.0]
    for iat in iats:
        ts.append(ts[-1] + float(iat))
    return [round(t, 6) for t in ts]


# ── 6. iat_stego.json ──────────────────────────────────────────────────────────
def _gen_iat_stego(n: int = 200) -> list[float]:
    """
    Kanał czasowy MoveSteg: base_interval ± tiny_jitter.
    CV ≈ tiny_jitter/base_interval  (np. 0.001/0.05 = 0.02 << 0.15)
    Bity zakodowane: bit=0 → opóźnienie = base, bit=1 → opóźnienie = base + delta
    """
    base_interval = 0.050    # 50 ms
    jitter_sigma  = 0.0003   # szum 0.3 ms imitujący jitter sieci
    bit_delta     = 0.005    # 5 ms delta dla bitu '1'

    ts  = [0.0]
    for i in range(n):
        bit = RNG.integers(0, 2)
        iat = base_interval + bit * bit_delta + float(RNG.normal(0, jitter_sigma))
        iat = max(0.001, iat)
        ts.append(ts[-1] + iat)
    return [round(t, 6) for t in ts]


# ── główna funkcja generowania i testowania ────────────────────────────────────
def main():
    os.makedirs(OUTDIR, exist_ok=True)
    print(f"\n=== Generowanie probek sieciowych -> {OUTDIR} ===\n")

    samples = [
        ("dns_clean.json",  _gen_dns_clean()),
        ("dns_stego.json",  _gen_dns_stego()),
        ("icmp_clean.json", _gen_icmp_clean()),
        ("icmp_stego.json", _gen_icmp_stego()),
        ("iat_clean.json",  _gen_iat_clean()),
        ("iat_stego.json",  _gen_iat_stego()),
    ]

    paths = {}
    for fname, data in samples:
        paths[fname] = _save(fname, data)

    print(f"\n=== Uruchamianie detektorów ===\n")

    tests = [
        ("dns",  "dns_clean.json",  "DNS-clean"),
        ("dns",  "dns_stego.json",  "DNS-stego"),
        ("icmp", "icmp_clean.json", "ICMP-clean"),
        ("icmp", "icmp_stego.json", "ICMP-stego"),
        ("iat",  "iat_clean.json",  "IAT-clean"),
        ("iat",  "iat_stego.json",  "IAT-stego"),
    ]

    for mode, fname, label in tests:
        report = _run_detector(mode, paths[fname])
        _print_result(label, report)

    print("\nGotowe.\n")


if __name__ == "__main__":
    main()
