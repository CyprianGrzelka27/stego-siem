"""
network.py — NetworkDetector opakowujący network_stego_detector z steg-lab/
"""

import sys
import os
import json
from pathlib import Path

from .common import SharedResult, now_iso

# Add steg-lab to path for imports
_STEG_LAB = Path(__file__).parent.parent / "steg-lab"
if str(_STEG_LAB) not in sys.path:
    sys.path.insert(0, str(_STEG_LAB))

from network_stego_detector import (
    DnsTunnelingDetector,
    IcmpTunnelingDetector,
    IATStegoDetector,
    SteganographicCostAggregator,
)


class NetworkDetector:
    """Unified detector for network traffic (DNS, ICMP, IAT steganography)."""

    SUPPORTED_FORMATS = {".json", ".pcap", ".pcapng"}

    def __init__(self):
        self.dns_detector = DnsTunnelingDetector()
        self.icmp_detector = IcmpTunnelingDetector()
        self.iat_detector = IATStegoDetector()

    def analyze_dns_json(self, filepath: str) -> SharedResult:
        """
        Analyze DNS queries from JSON file.

        Expected JSON format: list of dicts with keys:
          - query_name (str)
          - timestamp (float, unix)
          - source_ip (str)
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                queries = json.load(f)

            if not isinstance(queries, list):
                queries = [queries]

            dns_result = self.dns_detector.analyze(queries)
            aggregated = SteganographicCostAggregator().aggregate({"dns": dns_result})
            triggered_rules = self._build_dns_triggered_rules(dns_result)

            return SharedResult(
                timestamp=now_iso(),
                source_module="network",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=os.path.getsize(filepath),
                file_format="JSON",
                verdict=aggregated.get("verdict", "CLEAN"),
                risk_score=int(aggregated.get("risk_score", 0)),
                detectors_triggered=aggregated.get("detectors_triggered", 0),
                detectors_total=1,
                triggered_rules=triggered_rules,
                detectors={
                    "dns_tunneling": {
                        "confidence": dns_result.get("confidence", 0.0),
                        "detected": dns_result.get("detected", False),
                        "entropy": dns_result.get("entropy"),
                        "subdomain_length": dns_result.get("subdomain_length"),
                        "subdomain_alphabet": dns_result.get("subdomain_alphabet"),
                        "base32_matches": dns_result.get("base32_matches", 0),
                        "query_rate": dns_result.get("query_rate", 0),
                        "domain_concentration": dns_result.get("domain_concentration"),
                    },
                },
                network_channel="dns",
            )

        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"DNS analysis failed: {str(e)}",
                source_module="network",
            )

    def _build_dns_reason(self, dns_result: dict) -> str:
        parts = []
        entropy = dns_result.get("entropy")
        if entropy is not None and entropy > 3.5:
            parts.append(f"entropia subdomeny {entropy:.2f} > 3.5")
        subdomain_length = dns_result.get("subdomain_length")
        if subdomain_length is not None and subdomain_length > 30:
            parts.append(f"śr. długość {subdomain_length:.1f} > 30")
        base32_matches = dns_result.get("base32_matches", 0)
        if base32_matches and base32_matches > 0:
            parts.append(f"wzorce base32: {base32_matches}")
        query_rate = dns_result.get("query_rate", 0)
        if query_rate and query_rate > 10:
            parts.append(f"częstotliwość zapytań {query_rate:.1f} > 10")
        return "; ".join(parts) if parts else "brak przekroczonych progów"

    def _build_dns_triggered_rules(self, dns_result: dict) -> list:
        rules = []
        entropy = dns_result.get("entropy")
        if entropy is not None and entropy > 3.5:
            rules.append({
                "rule": "dns_entropy",
                "metric": "subdomain_entropy",
                "value": round(float(entropy), 4),
                "threshold": 3.5,
                "direction": "above",
                "message": f"Entropia subdomeny {entropy:.4f} > 3.5 — wysoka losowość nazw DNS",
            })
        subdomain_length = dns_result.get("subdomain_length")
        if subdomain_length is not None and subdomain_length > 30:
            rules.append({
                "rule": "dns_subdomain_length",
                "metric": "subdomain_length",
                "value": round(float(subdomain_length), 4),
                "threshold": 30,
                "direction": "above",
                "message": f"Śr. długość subdomeny {subdomain_length:.1f} > 30 — podejrzanie długie nazwy",
            })
        base32_matches = dns_result.get("base32_matches") or 0
        if base32_matches > 0:
            rules.append({
                "rule": "dns_base32",
                "metric": "base32_matches",
                "value": round(float(base32_matches), 4),
                "threshold": 0,
                "direction": "above",
                "message": f"Wzorce base32: {base32_matches} — kodowanie danych w subdomenach",
            })
        query_rate = dns_result.get("query_rate") or 0
        if query_rate > 10:
            rules.append({
                "rule": "dns_query_rate",
                "metric": "query_rate",
                "value": round(float(query_rate), 4),
                "threshold": 10,
                "direction": "above",
                "message": f"Częstotliwość zapytań {query_rate:.2f}/s > 10 — podejrzanie wysoka",
            })
        return rules

    def analyze_icmp_json(self, filepath: str) -> SharedResult:
        """Analyze ICMP packets from JSON file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                packets = json.load(f)
            if not isinstance(packets, list):
                packets = [packets]

            icmp_result = self.icmp_detector.analyze(packets)
            aggregated = SteganographicCostAggregator().aggregate({"icmp": icmp_result})

            triggered_rules = []
            if icmp_result.get("detected"):
                payload_variance = icmp_result.get("payload_variance")
                if payload_variance is not None:
                    triggered_rules.append({
                        "rule": "icmp_payload",
                        "metric": "payload_variance",
                        "value": round(float(payload_variance), 4),
                        "threshold": 0.0,
                        "direction": "above",
                        "message": f"ICMP payload_variance={payload_variance:.4f} — podejrzana zawartość pola payload",
                    })
                else:
                    conf = icmp_result.get("confidence", 0.0)
                    triggered_rules.append({
                        "rule": "icmp_tunneling",
                        "metric": "confidence",
                        "value": round(float(conf), 4),
                        "threshold": 0.5,
                        "direction": "above",
                        "message": f"ICMP tunelowanie: confidence={conf:.4f} > 0.5",
                    })

            return SharedResult(
                timestamp=now_iso(),
                source_module="network",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=os.path.getsize(filepath),
                file_format="JSON",
                verdict=aggregated.get("verdict", "CLEAN"),
                risk_score=int(aggregated.get("risk_score", 0)),
                detectors_triggered=aggregated.get("detectors_triggered", 0),
                detectors_total=1,
                triggered_rules=triggered_rules,
                detectors={
                    "icmp_tunneling": {
                        "confidence": icmp_result.get("confidence", 0.0),
                        "detected": icmp_result.get("detected", False),
                        "payload_variance": icmp_result.get("payload_variance"),
                        "packet_count": icmp_result.get("packet_count"),
                    },
                },
                network_channel="icmp",
            )

        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"ICMP analysis failed: {str(e)}",
                source_module="network",
            )

    def analyze_iat_json(self, filepath: str) -> SharedResult:
        """Analyze inter-arrival times from JSON file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                records = json.load(f)
            if not isinstance(records, list):
                records = [records]

            # Accept flat list of floats OR list of dicts with timestamp/inter_arrival_time
            timestamps = []
            for r in records:
                if isinstance(r, (int, float)):
                    timestamps.append(float(r))
                elif isinstance(r, dict):
                    if "timestamp" in r:
                        timestamps.append(float(r["timestamp"]))
                    elif "inter_arrival_time" in r:
                        timestamps.append(float(r["inter_arrival_time"]))

            iat_result = self.iat_detector.analyze(timestamps)
            aggregated = SteganographicCostAggregator().aggregate({"iat": iat_result})

            triggered_rules = []
            if iat_result.get("detected"):
                periodicity_score = iat_result.get("periodicity_score")
                if periodicity_score is not None:
                    triggered_rules.append({
                        "rule": "iat_periodicity",
                        "metric": "periodicity_score",
                        "value": round(float(periodicity_score), 4),
                        "threshold": 0.5,
                        "direction": "above",
                        "message": f"IAT periodicity_score={periodicity_score:.4f} > 0.5 — regularne odstępy między pakietami",
                    })
                else:
                    conf = iat_result.get("confidence", 0.0)
                    triggered_rules.append({
                        "rule": "iat_steganography",
                        "metric": "confidence",
                        "value": round(float(conf), 4),
                        "threshold": 0.5,
                        "direction": "above",
                        "message": f"IAT steganografia: confidence={conf:.4f} > 0.5",
                    })

            return SharedResult(
                timestamp=now_iso(),
                source_module="network",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=os.path.getsize(filepath),
                file_format="JSON",
                verdict=aggregated.get("verdict", "CLEAN"),
                risk_score=int(aggregated.get("risk_score", 0)),
                detectors_triggered=aggregated.get("detectors_triggered", 0),
                detectors_total=1,
                triggered_rules=triggered_rules,
                detectors={
                    "iat_steganography": {
                        "confidence": iat_result.get("confidence", 0.0),
                        "detected": iat_result.get("detected", False),
                        "periodicity_score": iat_result.get("periodicity_score"),
                        "samples_analyzed": len(timestamps),
                    },
                },
                network_channel="iat",
            )

        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"IAT analysis failed: {str(e)}",
                source_module="network",
            )

    def analyze_pcap(self, filepath: str) -> SharedResult:
        """Analyze PCAP/PCAPng capture for DNS tunneling, ICMP tunneling, and IAT channels."""
        # Lazy import: PcapParser requires dpkt or scapy; avoid breaking JSON analysis
        # if neither library is installed.
        try:
            from pcap_parser import PcapParser
        except ImportError as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"PCAP library missing (install dpkt or scapy): {e}",
                source_module="network",
            )

        try:
            parsed = PcapParser().parse(filepath)
        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"PCAP parse failed: {e}",
                source_module="network",
            )

        detector_results = {}
        warnings = list(parsed.get("warnings", []))

        if parsed["dns_queries"]:
            detector_results["dns"] = self.dns_detector.analyze(parsed["dns_queries"])
        else:
            warnings.append("No DNS queries in PCAP — DNS detector skipped")

        if parsed["icmp_packets"]:
            detector_results["icmp"] = self.icmp_detector.analyze(parsed["icmp_packets"])
        else:
            warnings.append("No ICMP packets in PCAP — ICMP detector skipped")

        if len(parsed["all_timestamps"]) >= 3:
            detector_results["iat"] = self.iat_detector.analyze(parsed["all_timestamps"])
        else:
            warnings.append("Too few packets for IAT analysis (minimum 3 required)")

        ext = os.path.splitext(filepath)[1].lower()
        file_size = os.path.getsize(filepath)

        pcap_summary = (
            f"PCAP: {parsed['packet_count']} packets, "
            f"{parsed['duration_sec']}s, "
            f"protocols={parsed['protocols_seen']}"
        )
        warnings.insert(0, pcap_summary)
        if parsed.get("skipped_packets", 0):
            warnings.append(f"Skipped {parsed['skipped_packets']} malformed packets")

        if not detector_results:
            return SharedResult(
                timestamp=now_iso(),
                source_module="network",
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                file_size_bytes=file_size,
                file_format=ext.upper().lstrip("."),
                verdict="CLEAN",
                risk_score=0,
                detectors_triggered=0,
                detectors_total=0,
                warnings=warnings + ["No recognized protocols — returning CLEAN"],
                network_channel="pcap",
            )

        aggregated = SteganographicCostAggregator().aggregate(detector_results)

        triggered_rules = []
        if "dns" in detector_results:
            triggered_rules.extend(self._build_dns_triggered_rules(detector_results["dns"]))
        icmp_result = detector_results.get("icmp", {})
        if icmp_result.get("detected"):
            payload_variance = icmp_result.get("payload_variance")
            if payload_variance is not None:
                triggered_rules.append({
                    "rule": "icmp_payload",
                    "metric": "payload_variance",
                    "value": round(float(payload_variance), 4),
                    "threshold": 0.0,
                    "direction": "above",
                    "message": f"ICMP payload_variance={payload_variance:.4f} — podejrzana zawartość pola payload",
                })
            else:
                conf = icmp_result.get("confidence", 0.0)
                triggered_rules.append({
                    "rule": "icmp_tunneling",
                    "metric": "confidence",
                    "value": round(float(conf), 4),
                    "threshold": 0.5,
                    "direction": "above",
                    "message": f"ICMP tunelowanie: confidence={conf:.4f} > 0.5",
                })
        iat_result = detector_results.get("iat", {})
        if iat_result.get("detected"):
            periodicity_score = iat_result.get("periodicity_score")
            if periodicity_score is not None:
                triggered_rules.append({
                    "rule": "iat_periodicity",
                    "metric": "periodicity_score",
                    "value": round(float(periodicity_score), 4),
                    "threshold": 0.5,
                    "direction": "above",
                    "message": f"IAT periodicity_score={periodicity_score:.4f} > 0.5 — regularne odstępy między pakietami",
                })
            else:
                conf = iat_result.get("confidence", 0.0)
                triggered_rules.append({
                    "rule": "iat_steganography",
                    "metric": "confidence",
                    "value": round(float(conf), 4),
                    "threshold": 0.5,
                    "direction": "above",
                    "message": f"IAT steganografia: confidence={conf:.4f} > 0.5",
                })

        for _det in detector_results.values():
            _det.pop("flagged_queries", None)
            _det.pop("suspicious_packets", None)
            _det.pop("raw_packets", None)

        return SharedResult(
            timestamp=now_iso(),
            source_module="network",
            file_name=os.path.basename(filepath),
            file_path=os.path.abspath(filepath),
            file_size_bytes=file_size,
            file_format=ext.upper().lstrip("."),
            verdict=aggregated.get("verdict", "CLEAN"),
            risk_score=int(aggregated.get("risk_score", 0)),
            detectors_triggered=aggregated.get("detectors_triggered", 0),
            detectors_total=len(detector_results),
            warnings=warnings,
            triggered_rules=triggered_rules,
            detectors={
                **aggregated.get("detectors", {}),
                **(
                    {"dns_tunneling": {
                        "confidence":           detector_results["dns"].get("confidence", 0.0),
                        "detected":             detector_results["dns"].get("detected", False),
                        "entropy":              detector_results["dns"].get("entropy"),
                        "subdomain_length":     detector_results["dns"].get("subdomain_length"),
                        "subdomain_alphabet":   detector_results["dns"].get("subdomain_alphabet"),
                        "base32_matches":       detector_results["dns"].get("base32_matches", 0),
                        "query_rate":           detector_results["dns"].get("query_rate", 0),
                        "domain_concentration": detector_results["dns"].get("domain_concentration"),
                        "reason":               self._build_dns_reason(detector_results["dns"]),
                    }}
                    if "dns" in detector_results else {}
                ),
            },
            network_channel="pcap",
        )

    def analyze(self, filepath: str, mode: str = "auto") -> SharedResult:
        """
        Analyze network traffic file.

        Args:
            filepath: path to network traffic file (JSON, PCAP, etc.)
            mode: detection mode ("dns", "icmp", "iat", or "auto")

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
                    source_module="network",
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
                    source_module="network",
                )

            if ext == ".json":
                try:
                    with open(filepath, "r", encoding="utf-8") as _f:
                        _data = json.load(_f)
                    _first = _data[0] if isinstance(_data, list) and _data else _data
                except Exception:
                    _first = None
                if _first is None:
                    _first = {}
                if isinstance(_first, (int, float)):
                    return self.analyze_iat_json(filepath)
                if "icmp_type" in _first or "payload_size" in _first:
                    return self.analyze_icmp_json(filepath)
                if "inter_arrival_time" in _first or "iat" in _first:
                    return self.analyze_iat_json(filepath)
                return self.analyze_dns_json(filepath)

            if ext in (".pcap", ".pcapng"):
                return self.analyze_pcap(filepath)

            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"Unsupported format: {ext}",
                source_module="network",
            )

        except Exception as e:
            return SharedResult(
                timestamp=now_iso(),
                file_name=os.path.basename(filepath),
                file_path=os.path.abspath(filepath),
                verdict="CLEAN",
                risk_score=0,
                errors=f"Analysis failed: {str(e)}",
                source_module="network",
            )
