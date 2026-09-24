import importlib.util
import pathlib
import struct
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / 'mesh-stun.py'
spec = importlib.util.spec_from_file_location('mesh_stun', PATH)
stun = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stun)


def request(body=b''):
    return struct.pack('!HHI', 1, len(body), stun.COOKIE) + b'0123456789ab' + body


class StunTests(unittest.TestCase):
    def test_xor_mapped_and_transaction(self):
        reply, change = stun.binding_response(request(), ('192.0.2.17', 34567))
        self.assertEqual(len(reply), 32)
        self.assertEqual(reply[8:20], b'0123456789ab')
        self.assertEqual(struct.unpack_from('!H', reply, 26)[0] ^ 0x2112, 34567)
        self.assertEqual(bytes(a ^ b for a, b in zip(reply[28:32], b'\x21\x12\xa4\x42')), b'\xc0\x00\x02\x11')
        self.assertFalse(change)

    def test_change_port_only(self):
        for flags in (0, 2, 4, 6, 8):
            response = stun.binding_response(request(struct.pack('!HHI', 3, 4, flags)), ('192.0.2.1', 10000))
            if flags in (0, 2):
                self.assertEqual(response[1], bool(flags))
            else:
                self.assertIsNone(response)

    def test_rejects_malformed_and_other_methods(self):
        good = request()
        for bad in (b'', good[:-1], good + b'x', b'\x00\x03' + good[2:], good[:4] + b'bad!' + good[8:], request(b'x' * 516), request(b'\x00\x03\x00\x08' + b'\x00' * 4)):
            self.assertIsNone(stun.binding_response(bad, ('192.0.2.1', 10000)))

    def test_optional_attributes_and_padding(self):
        self.assertIsNotNone(stun.binding_response(request(struct.pack('!HH', 0x8022, 1) + b'x\0\0\0'), ('192.0.2.1', 10000)))
        self.assertIsNone(stun.binding_response(request(struct.pack('!HH', 0x1234, 0)), ('192.0.2.1', 10000)))

    def test_rate_and_memory_bounds(self):
        limiter = stun.RateLimit()
        for _ in range(128):
            self.assertTrue(limiter.allow('one', now=10))
        self.assertFalse(limiter.allow('one', now=10))
        self.assertTrue(limiter.allow('one', now=11))
        for n in range(255):
            self.assertTrue(limiter.allow(str(n), now=11))
        self.assertFalse(limiter.allow('new', now=11))
        self.assertEqual(len(limiter.counts), 256)
        self.assertTrue(limiter.allow('new', now=12))
        self.assertEqual(len(limiter.counts), 1)


if __name__ == '__main__':
    unittest.main()
