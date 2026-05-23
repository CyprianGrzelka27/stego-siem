"""
pcap_parser.py — parser plikow PCAP dla detektora steganografii sieciowej

Uzycie (jako modul):
  from pcap_parser import PcapParser
  parsed = PcapParser().parse("capture.pcap")

Uzycie (CLI — przez network_stego_detector.py):
  python network_stego_detector.py --mode combined --pcap capture.pcap
"""

import os
import socket
import logging

logger = logging.getLogger(__name__)

# ── dynamiczny import backendu ────────────────────────────────────────────────
try:
    import dpkt
    _BACKEND = "dpkt"
    logger.debug("Backend PCAP: dpkt")
except ImportError:
    try:
        from scapy.all import rdpcap as _scapy_rdpcap
        from scapy.layers.inet import IP as _ScapyIP, ICMP as _ScapyICMP
        from scapy.layers.dns  import DNS as _ScapyDNS, DNSQR as _ScapyDNSQR
        _BACKEND = "scapy"
        logger.debug("Backend PCAP: scapy (dpkt niedostepny)")
    except ImportError:
        raise ImportError(
            "Brak biblioteki do parsowania PCAP.\n"
            "Zainstaluj dpkt (zalecane):  pip install dpkt\n"
            "lub scapy (alternatywa):     pip install scapy"
        )

# Numeryczne stalej DLT (link layer type) z libpcap — uzywamy liczb,
# zeby nie polegac na konkretnej wersji dpkt.
_DLT_EN10MB = 1    # Ethernet (dominujacy typ w sieciach korporacyjnych)
_DLT_NULL   = 0    # BSD loopback (macOS, tcpdump -i lo0)
_DLT_LOOP   = 108  # OpenBSD loopback
_DLT_RAW    = 101  # surowe IP (Linux cooked, niektore sniffer-y)


# ══════════════════════════════════════════════════════════════════════════════
class PcapParser:
    """
    Parser plikow PCAP dla modulu detekcji steganografii sieciowej w SIEM.

    Format PCAP (Packet CAPture) to binarny standard zapisu ruchu sieciowego
    stosowany przez Wireshark, tcpdump, Zeek/Bro i sensory IDS/IPS.

    Dlaczego analiza offline PCAP jest uzasadniona w kontekscie SIEM?
      - Sensory sieciowe (TAP, SPAN) zapisuja ruch na dysk w sposob ciagly;
        SIEM przetwarza te pliki asynchronicznie (po fakcie lub w trybie live).
      - Retrospektywny "threat hunting": analiza archiwalnych pcap po uzyskaniu
        nowego IOC (Indicator of Compromise) jest standardowa praktyka SOC.
      - Integracja z Zeek/Bro, Suricata, ntopng — eksportuja PCAP automatycznie.

    Narzedzia generujace wykrywalny ruch steganograficzny:
      DNS:  iodine, dnscat2, DNSExfiltrator — wysoka entropia subdomen
      ICMP: ptunnel, icmptunnel, Hans       — niestandardowe rozmiary payload
      IAT:  MoveSteg, Jitterbug, TRIDENT    — regularne odstepy miedzy pakietami

    Podstawa akademicka:
      Mazurczyk & Szczypiorski (2014) — "Principles and Overview of Network
      Steganography", IEEE Communications Surveys & Tutorials

    Backendy (wybor automatyczny):
      dpkt  (preferowany) — czysty Python, szybki, bez zaleznosci systemowych
      scapy (fallback)    — bardziej rozbudowany, wolniejszy przy duzych plikach
    """

    def parse(self, filepath: str) -> dict:
        """
        Parsuje plik PCAP i zwraca dane gotowe do podania trzem detektorom.

        Zwracany slownik:
          dns_queries:     lista dict {query_name, timestamp, source_ip}
          icmp_packets:    lista dict {payload_size, timestamp, source_ip, icmp_type}
          all_timestamps:  lista float (unix ts kazdego pakietu — do IAT)
          packet_count:    int
          duration_sec:    float
          protocols_seen:  list[str]
          skipped_packets: int
          warnings:        list[str]
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Nie znaleziono pliku PCAP: {filepath}")

        if _BACKEND == "dpkt":
            return self._parse_dpkt(filepath)
        return self._parse_scapy(filepath)

    # ── backend dpkt ───────────────────────────────────────────────────────────
    def _parse_dpkt(self, filepath: str) -> dict:
        dns_queries    = []
        icmp_packets   = []
        all_timestamps = []
        skipped        = 0
        protocols      = set()

        with open(filepath, "rb") as f:
            try:
                pcap     = dpkt.pcap.Reader(f)
                datalink = pcap.datalink()
            except Exception:
                # pcapng ma magic 0x0A0D0D0A — dpkt ma osobny Reader
                f.seek(0)
                try:
                    pcap     = dpkt.pcapng.Reader(f)
                    datalink = _DLT_EN10MB  # pcapng koduje DLT per-blok; domyslnie Ethernet
                except Exception as e:
                    raise ValueError(f"Nie mozna odczytac naglowka PCAP/PCAPng: {e}")

            for ts, buf in pcap:
                all_timestamps.append(float(ts))
                try:
                    ip = self._extract_ip_dpkt(buf, datalink)
                    if ip is None:
                        continue

                    src_ip = socket.inet_ntoa(ip.src)

                    # ── DNS — UDP port 53 ─────────────────────────────────────
                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        if udp.dport == 53:
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                # qr=0 → zapytanie; qr=1 → odpowiedz (pomijamy)
                                if dns.qr == 0:
                                    protocols.add("DNS")
                                    for q in dns.qd:
                                        dns_queries.append({
                                            "query_name": q.name,
                                            "timestamp":  float(ts),
                                            "source_ip":  src_ip,
                                        })
                            except Exception:
                                skipped += 1
                        else:
                            protocols.add("UDP")

                    # ── ICMP ──────────────────────────────────────────────────
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        icmp = ip.data
                        protocols.add("ICMP")
                        icmp_packets.append({
                            "payload_size": len(icmp.data),
                            "timestamp":    float(ts),
                            "source_ip":    src_ip,
                            "icmp_type":    icmp.type,
                        })

                    elif isinstance(ip.data, dpkt.tcp.TCP):
                        protocols.add("TCP")

                except Exception:
                    skipped += 1

        return self._build_result(dns_queries, icmp_packets, all_timestamps,
                                  skipped, protocols)

    def _extract_ip_dpkt(self, buf: bytes, datalink: int):
        """
        Wydobywa warstwe IP z ramki zgodnie z typem lacza (DLT).
        Zwraca obiekt dpkt.ip.IP lub None dla nie-IPv4.
        """
        try:
            if datalink == _DLT_EN10MB:
                eth = dpkt.ethernet.Ethernet(buf)
                return eth.data if isinstance(eth.data, dpkt.ip.IP) else None

            if datalink in (_DLT_NULL, _DLT_LOOP):
                # 4-bajtowy naglowek rodziny adresow (AF_INET=2), potem raw IP
                return dpkt.ip.IP(buf[4:])

            if datalink == _DLT_RAW:
                return dpkt.ip.IP(buf)

            # nieznany typ — probujemy kolejno Ethernet i raw IP
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    return eth.data
            except Exception:
                pass
            return dpkt.ip.IP(buf)

        except Exception:
            return None

    # ── backend scapy ──────────────────────────────────────────────────────────
    def _parse_scapy(self, filepath: str) -> dict:
        dns_queries    = []
        icmp_packets   = []
        all_timestamps = []
        skipped        = 0
        protocols      = set()

        try:
            packets = _scapy_rdpcap(filepath)
        except Exception as e:
            raise ValueError(f"Scapy nie moze odczytac pliku PCAP: {e}")

        for pkt in packets:
            try:
                ts = float(pkt.time)
                all_timestamps.append(ts)

                if _ScapyIP not in pkt:
                    continue

                src_ip = pkt[_ScapyIP].src

                # ── DNS ───────────────────────────────────────────────────────
                if _ScapyDNS in pkt and pkt[_ScapyDNS].qr == 0:
                    protocols.add("DNS")
                    try:
                        if _ScapyDNSQR in pkt:
                            raw = pkt[_ScapyDNSQR].qname
                            name = (raw.decode("utf-8", errors="replace")
                                    if isinstance(raw, bytes) else str(raw)).rstrip(".")
                            dns_queries.append({
                                "query_name": name,
                                "timestamp":  ts,
                                "source_ip":  src_ip,
                            })
                    except Exception:
                        skipped += 1

                # ── ICMP ──────────────────────────────────────────────────────
                if _ScapyICMP in pkt:
                    protocols.add("ICMP")
                    icmp_packets.append({
                        "payload_size": len(bytes(pkt[_ScapyICMP].payload)),
                        "timestamp":    ts,
                        "source_ip":    src_ip,
                        "icmp_type":    pkt[_ScapyICMP].type,
                    })

                # protokoly pomocnicze (do protocols_seen)
                proto = pkt[_ScapyIP].proto
                if proto == 6:
                    protocols.add("TCP")
                elif proto == 17 and _ScapyDNS not in pkt:
                    protocols.add("UDP")

            except Exception:
                skipped += 1

        return self._build_result(dns_queries, icmp_packets, all_timestamps,
                                  skipped, protocols)

    # ── wspolna budowa wyniku ──────────────────────────────────────────────────
    def _build_result(self, dns_queries, icmp_packets, all_timestamps,
                      skipped, protocols) -> dict:
        warnings = []
        n        = len(all_timestamps)

        if n == 0:
            warnings.append("Pusty plik PCAP — brak pakietow")
            duration = 0.0
        elif n == 1:
            duration = 0.0
        else:
            duration = round(all_timestamps[-1] - all_timestamps[0], 6)

        if skipped > 0:
            warnings.append(
                f"Pominieto {skipped} znieksztalconych/nieobslugiwanych pakietow"
            )

        return {
            "dns_queries":    dns_queries,
            "icmp_packets":   icmp_packets,
            "all_timestamps": all_timestamps,
            "packet_count":   n,
            "duration_sec":   duration,
            "protocols_seen": sorted(protocols),
            "skipped_packets": skipped,
            "warnings":        warnings,
        }
