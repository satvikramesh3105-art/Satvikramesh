"""Passive packet/PCAP signal analyzer. It never crafts, transmits, or blocks packets."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class PacketWindow:
    packets: int = 0
    bytes_seen: int = 0
    sources: set[str] = field(default_factory=set)
    syn_sources: set[str] = field(default_factory=set)
    syn_packets: int = 0
    udp_packets: int = 0


class PacketAnalyzer:
    """Find high SYN/UDP volume and source-diversity indicators in packet captures."""

    def __init__(
        self,
        *,
        window_seconds: int = 10,
        syn_packet_threshold: int = 100,
        udp_packet_threshold: int = 200,
        distributed_source_threshold: int = 25,
    ) -> None:
        self.window_seconds = max(1, int(window_seconds))
        self.syn_packet_threshold = max(1, int(syn_packet_threshold))
        self.udp_packet_threshold = max(1, int(udp_packet_threshold))
        self.distributed_source_threshold = max(2, int(distributed_source_threshold))

    def analyze(self, packets: Iterable[Any]) -> dict[str, Any]:
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError as error:
            raise RuntimeError("Install optional packet dependencies with: pip install -r requirements-packet-sensor.txt") from error

        windows: dict[tuple[int, str], PacketWindow] = defaultdict(PacketWindow)
        packets_seen = 0
        for packet in packets:
            if IP not in packet:
                continue
            ip_layer = packet[IP]
            timestamp = float(getattr(packet, "time", 0.0))
            bucket = int(timestamp // self.window_seconds)
            destination = str(ip_layer.dst)
            source = str(ip_layer.src)
            window = windows[(bucket, destination)]
            window.packets += 1
            window.bytes_seen += len(packet)
            window.sources.add(source)
            packets_seen += 1
            if TCP in packet:
                flags = int(packet[TCP].flags)
                if flags & 0x02 and not flags & 0x10:  # SYN set, ACK clear
                    window.syn_packets += 1
                    window.syn_sources.add(source)
            elif UDP in packet:
                window.udp_packets += 1

        findings: list[dict[str, Any]] = []
        for (bucket, destination), window in sorted(windows.items()):
            start = bucket * self.window_seconds
            if window.syn_packets >= self.syn_packet_threshold:
                findings.append({
                    "type": "high-syn-rate",
                    "destination": destination,
                    "window_start": start,
                    "window_seconds": self.window_seconds,
                    "packet_count": window.syn_packets,
                    "distinct_sources": len(window.syn_sources),
                    "severity": "high" if window.syn_packets >= self.syn_packet_threshold * 3 else "medium",
                    "action": "alert-only",
                })
            if window.udp_packets >= self.udp_packet_threshold:
                findings.append({
                    "type": "high-udp-rate",
                    "destination": destination,
                    "window_start": start,
                    "window_seconds": self.window_seconds,
                    "packet_count": window.udp_packets,
                    "distinct_sources": len(window.sources),
                    "severity": "high" if window.udp_packets >= self.udp_packet_threshold * 3 else "medium",
                    "action": "alert-only",
                })
            if len(window.sources) >= self.distributed_source_threshold and window.packets >= self.syn_packet_threshold:
                findings.append({
                    "type": "distributed-source-fan-in",
                    "destination": destination,
                    "window_start": start,
                    "window_seconds": self.window_seconds,
                    "packet_count": window.packets,
                    "distinct_sources": len(window.sources),
                    "severity": "high",
                    "action": "alert-only",
                })

        return {
            "mode": "passive-packet-analysis",
            "packets_seen": packets_seen,
            "window_seconds": self.window_seconds,
            "findings": findings,
            "limitations": "Threshold indicators only; no packet injection, blocking, or guarantee of attack attribution.",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Passively analyze an authorized PCAP or capture interface for L4 rate indicators.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path, help="Read an existing PCAP/PCAPNG file; does not transmit traffic.")
    source.add_argument("--interface", help="Capture passively on a local interface (may require Npcap/admin privileges).")
    parser.add_argument("--seconds", type=int, default=30, help="Capture duration for --interface (default: 30).")
    parser.add_argument("--window", type=int, default=10, help="Aggregation window in seconds (default: 10).")
    parser.add_argument("--syn-threshold", type=int, default=100)
    parser.add_argument("--udp-threshold", type=int, default=200)
    parser.add_argument("--source-threshold", type=int, default=25)
    args = parser.parse_args()

    if args.seconds < 1 or args.seconds > 3600:
        parser.error("--seconds must be between 1 and 3600")
    if args.window < 1:
        parser.error("--window must be positive")
    if min(args.syn_threshold, args.udp_threshold, args.source_threshold) < 1:
        parser.error("packet and source thresholds must be positive")
    try:
        from scapy.all import PcapReader, sniff
    except ImportError:
        print("Scapy is required. Install it with: pip install -r requirements-packet-sensor.txt", file=sys.stderr)
        return 2

    analyzer = PacketAnalyzer(
        window_seconds=args.window,
        syn_packet_threshold=args.syn_threshold,
        udp_packet_threshold=args.udp_threshold,
        distributed_source_threshold=args.source_threshold,
    )
    try:
        if args.pcap:
            packets: Iterable[Any] = PcapReader(str(args.pcap))
            try:
                report = analyzer.analyze(packets)
            finally:
                packets.close()  # type: ignore[attr-defined]
        else:
            print("Passive capture only; no packets will be transmitted.", file=sys.stderr)
            # A fixed cap prevents an accidental long capture from consuming unbounded memory.
            packets = sniff(iface=args.interface, timeout=args.seconds, store=True, count=100_000)
            report = analyzer.analyze(packets)
    except (OSError, PermissionError, RuntimeError) as error:
        print(f"Packet monitor error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
