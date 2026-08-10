#!/usr/bin/env python3
"""Test passive traffic signature analysis."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCANNER_PATH = Path(__file__).parents[1] / "traffic_signature_scan.py"
SPEC = importlib.util.spec_from_file_location("traffic_signature_scan", SCANNER_PATH)
assert SPEC is not None
assert SPEC.loader is not None
SCANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCANNER)


class TrafficSignatureScanTest(unittest.TestCase):
    def test_extracts_udp_ports_and_payload(self) -> None:
        payload = b"wire payload"
        udp_length = 8 + len(payload)
        ipv4_length = 20 + udp_length
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ipv4 = bytes.fromhex("4500") + ipv4_length.to_bytes(2, "big") + bytes.fromhex(
            "0000000040110000c0000201c0000202"
        )
        udp = (11010).to_bytes(2, "big") + (42000).to_bytes(2, "big")
        udp += udp_length.to_bytes(2, "big") + b"\x00\x00"

        datagram = SCANNER.udp_datagram_from_ethernet(ethernet + ipv4 + udp + payload)

        self.assertEqual(datagram, (11010, 42000, payload))

    def test_reports_forbidden_values_and_repeated_edges(self) -> None:
        packets = [
            b"AB" + bytes([value]) + b"easytier" + b"ZZ" for value in range(8)
        ]

        report = SCANNER.scan_packets(packets, [b"easytier"])

        self.assertEqual(report["packet_count"], 8)
        self.assertEqual(report["common_prefix_bytes"], 2)
        self.assertEqual(report["common_suffix_bytes"], 10)
        self.assertEqual(report["forbidden_hits"]["easytier"], 8)

    def test_varied_ciphertext_has_no_repeated_edge(self) -> None:
        packets = [bytes((index * 31 + position * 17) & 0xFF for position in range(64))
                   for index in range(32)]

        report = SCANNER.scan_packets(packets, [b"easytier"])

        self.assertEqual(report["common_prefix_bytes"], 0)
        self.assertEqual(report["common_suffix_bytes"], 0)
        self.assertEqual(report["forbidden_hits"]["easytier"], 0)
        self.assertEqual(report["unique_packet_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
