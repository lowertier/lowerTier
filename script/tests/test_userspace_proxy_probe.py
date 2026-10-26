#!/usr/bin/env python3
"""Tests for the userspace proxy probe protocol helpers."""

from __future__ import annotations

import importlib.util
import socket
import unittest
from unittest.mock import Mock, patch
from pathlib import Path


PROBE_PATH = Path(__file__).with_name("userspace_proxy_probe.py")
SPEC = importlib.util.spec_from_file_location("userspace_proxy_probe", PROBE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class Socks5AddressEncodingTests(unittest.TestCase):
    def test_encodes_ipv4_address(self) -> None:
        address = "192.0.2.7"

        encoded = PROBE.encode_socks5_address(address)

        self.assertEqual(encoded, b"\x01" + socket.inet_pton(socket.AF_INET, address))

    def test_encodes_ipv6_address(self) -> None:
        address = "2001:db8::7"

        encoded = PROBE.encode_socks5_address(address)

        self.assertEqual(encoded, b"\x04" + socket.inet_pton(socket.AF_INET6, address))

    def test_encodes_idna_domain(self) -> None:
        address = "münich.example"
        encoded_address = address.encode("idna")

        encoded = PROBE.encode_socks5_address(address)

        self.assertEqual(
            encoded,
            b"\x03" + bytes((len(encoded_address),)) + encoded_address,
        )


class TransferDeadlineTests(unittest.TestCase):
    def test_progress_does_not_extend_the_deadline(self) -> None:
        stream = Mock(spec=socket.socket)
        stream.gettimeout.return_value = 15
        stream.recv.return_value = b"x"

        with patch.object(PROBE.time, "monotonic", side_effect=[0.0, 0.4, 0.8, 1.2]):
            with self.assertRaises(TimeoutError):
                PROBE.recv_exact(stream, 100, deadline=1.0)

        self.assertEqual(stream.recv.call_count, 3)
        stream.settimeout.assert_called_with(15)

    def test_complete_payload_restores_socket_timeout(self) -> None:
        stream = Mock(spec=socket.socket)
        stream.gettimeout.return_value = 15
        stream.recv.return_value = b"payload"

        with patch.object(PROBE.time, "monotonic", return_value=0.1):
            self.assertEqual(PROBE.recv_exact(stream, 7, deadline=1.0), b"payload")

        stream.settimeout.assert_called_with(15)


if __name__ == "__main__":
    unittest.main()
