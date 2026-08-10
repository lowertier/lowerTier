#!/usr/bin/env python3
"""Test exact Ethernet frame reconstruction."""

from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path


PROBE_PATH = Path(__file__).parents[1] / "colima-l2" / "frame_probe.py"
SPEC = importlib.util.spec_from_file_location("frame_probe", PROBE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
FRAME_PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FRAME_PROBE)


class RestoreVlanTagTest(unittest.TestCase):
    def test_restores_8021q_tag_from_packet_auxdata(self) -> None:
        frame = bytes.fromhex("00112233445566778899aabb88b57061796c6f6164")
        auxdata = struct.pack("=IIIHHHH", 1 << 4, len(frame), len(frame), 0, 0, 42, 0)

        restored = FRAME_PROBE.restore_vlan_tag(frame, auxdata)

        self.assertEqual(
            restored,
            bytes.fromhex("00112233445566778899aabb8100002a88b57061796c6f6164"),
        )

    def test_uses_valid_outer_tpid(self) -> None:
        frame = bytes.fromhex("00112233445566778899aabb8100002a88b57061796c6f6164")
        status = (1 << 4) | (1 << 6)
        auxdata = struct.pack(
            "=IIIHHHH", status, len(frame), len(frame), 0, 0, 100, 0x88A8
        )

        restored = FRAME_PROBE.restore_vlan_tag(frame, auxdata)

        self.assertEqual(
            restored,
            bytes.fromhex(
                "00112233445566778899aabb88a800648100002a88b57061796c6f6164"
            ),
        )

    def test_leaves_frame_without_vlan_metadata_unchanged(self) -> None:
        frame = bytes.fromhex("00112233445566778899aabb88b57061796c6f6164")
        auxdata = struct.pack("=IIIHHHH", 0, len(frame), len(frame), 0, 0, 0, 0)

        self.assertEqual(FRAME_PROBE.restore_vlan_tag(frame, auxdata), frame)


if __name__ == "__main__":
    unittest.main()
