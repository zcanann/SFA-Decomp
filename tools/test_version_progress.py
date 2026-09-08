"""Exercise packed data boundaries in cross-version binary context matching."""
from pathlib import Path
import hashlib
import struct
import tempfile
from types import SimpleNamespace
import unittest

from orig.dol_xrefs import DolSection
from version_progress import SymbolSpan, build_boundary_map, symbol_span_index, verified_dol


def dol(data, address):
    return SimpleNamespace(path=Path('synthetic.dol'), data=data,
                           sections=[DolSection(13, 0, address, len(data))])


class PackedBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.data = b''.join(struct.pack('>I', 0x10203040 + i * 0x01020304) for i in range(24))
        self.source = dol(self.data, 0x80010000)
        self.target = dol(b'\xEE' * 16 + self.data + b'\xCC' * 16, 0x80020000)

    def match(self, offset, spans=()):
        return build_boundary_map('sdata', {0x80010000 + offset}, self.source, self.target,
                                  [], {}, symbol_span_index({'sdata': tuple(spans)}))

    def test_word_context_preserves_every_byte_phase(self):
        # Beginning/end cases exercise forward-only and backward-only contexts.
        for word_offset in (0, 32, 92):
            for phase in range(4):
                offset = word_offset + phase
                if offset == 0:  # The section origin is an independent anchor.
                    continue
                with self.subTest(offset=offset):
                    direct, inferred = self.match(offset)
                    expected = 0x80020010 + offset
                    self.assertEqual(direct[0x80010000 + offset], expected)
                    self.assertEqual(inferred[0x80010000 + offset], expected)

    def test_symbol_edge_check_uses_byte_phase(self):
        for phase in (1, 2, 3):
            expected = 0x80020030 + phase
            spans = (SymbolSpan('before', 'sdata', expected - 8, expected),
                     SymbolSpan('after', 'sdata', expected, expected + 8))
            with self.subTest(phase=phase):
                direct, _ = self.match(32 + phase, spans)
                self.assertEqual(direct[0x80010020 + phase], expected)

    def test_packed_boundary_inside_symbol_is_not_a_direct_anchor(self):
        expected = 0x80020032
        direct, _ = self.match(34, (SymbolSpan('cover', 'sdata', expected - 1, expected + 3),))
        self.assertNotIn(0x80010022, direct)

    def test_repeated_context_remains_ambiguous(self):
        self.source = dol(bytes(96), 0x80010000)
        self.target = dol(bytes(128), 0x80020000)
        direct, _ = self.match(34)
        self.assertNotIn(0x80010022, direct)


class RetailIdentityTests(unittest.TestCase):
    def test_configured_identity_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path, config = directory / 'main.dol', directory / 'config.yml'
            path.write_bytes(bytes(0x100))
            digest = hashlib.sha1(path.read_bytes()).hexdigest()
            for quote in ('', "'", '"'):
                config.write_text(f'hash: {quote}{digest}{quote} # retail\n')
                self.assertEqual(verified_dol(path, config).data, path.read_bytes())
            path.write_bytes(bytes(0x100) + b'changed')
            with self.assertRaisesRegex(ValueError, 'Retail hash mismatch'):
                verified_dol(path, config)
            config.write_text('hash: unknown\n')
            with self.assertRaisesRegex(ValueError, 'Missing or unsupported'):
                verified_dol(path, config)


if __name__ == '__main__':
    unittest.main()
