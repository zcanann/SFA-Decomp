"""Exercise packed data boundaries in cross-version binary context matching."""
from pathlib import Path
import hashlib
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr
from io import StringIO

from orig.dol_xrefs import DolSection
from version_progress import (SymbolSpan, SplitRange, VersionProjection, build_boundary_map,
                              symbol_span_index, verified_dol, project_symbol_snapshot,
                              project_version, build_symbol_mappings, main)


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


class ProjectionRefinementTests(unittest.TestCase):
    def setUp(self):
        code = struct.pack('>8I', *([0x38600001] * 7 + [0x4E800020]))
        other = struct.pack('>8I', *([0x4E800020] * 8))

        def image(address, text):
            data = text + bytes(8)
            section = DolSection(1, 0, address, len(text))
            return SimpleNamespace(path=Path('synthetic.dol'), data=data,
                                   text_sections=[section], sections=[section,
                                   DolSection(12, len(text), address + 0x1000, 4),
                                   DolSection(13, len(text) + 4, address + 0x2000, 4)] +
                                   [DolSection(i, len(data), address + 0x3000 + i * 0x100, 0)
                                    for i in (0, 7, 8, 9, 10, 11, 14)])

        self.source = image(0x80010000, code)
        self.target = image(0x80020000, code + other)
        self.splits = [SplitRange('example.c', 'text', 0x80010000, 0x80010020)]
        self.source_symbols = 'canonical = .text:0x80010000; // type:function size:0x20\n'
        self.target_symbols = 'legacy = .text:0x80020000; // type:function size:0x20\n'

    def project(self, target_symbols=None):
        return project_version(self.source, self.splits, self.source_symbols,
                               self.target, self.target_symbols if target_symbols is None else target_symbols)

    def test_renames_and_fallbacks_describe_the_same_snapshot(self):
        first = project_symbol_snapshot(self.source, self.splits, self.source_symbols,
                                        self.target, self.target_symbols)
        self.assertEqual(build_symbol_mappings(first.ported, first.matches),
                         {'example.c': {'legacy': 'canonical'}})
        result = self.project()
        self.assertIn('canonical = .text:0x80020000;', result.symbols)
        self.assertEqual(build_symbol_mappings(result.ported, result.matches), {})
        self.assertEqual(result.renamed, 1)
        self.assertGreater(result.passes, 1)
        repeated = self.project(result.symbols)
        self.assertEqual(repeated.passes, 1)
        self.assertEqual(repeated.symbols, result.symbols)
        self.assertEqual(repeated.ported, result.ported)

    def test_unclaimed_name_conflict_keeps_a_real_fallback(self):
        result = self.project(self.target_symbols +
                              'canonical = .text:0x80020020; // type:function size:0x20\n')
        self.assertIn('legacy = .text:0x80020000;', result.symbols)
        self.assertEqual(build_symbol_mappings(result.ported, result.matches),
                         {'example.c': {'legacy': 'canonical'}})
        self.assertEqual(result.conflicts, 1)

    @staticmethod
    def snapshot(symbols):
        return VersionProjection([], {}, {}, 0, 0, {}, {}, 0, symbols, 0, 0, 0)

    def test_cycle_and_pass_limit_are_rejected(self):
        with patch('version_progress.project_symbol_snapshot',
                   side_effect=[self.snapshot('changed'), self.snapshot(self.target_symbols)]):
            with self.assertRaisesRegex(ValueError, 'cycles'):
                self.project()
        with patch('version_progress.project_symbol_snapshot',
                   side_effect=[self.snapshot('first'), self.snapshot('second')]):
            with self.assertRaisesRegex(ValueError, 'did not stabilize in 2 passes'):
                project_version(self.source, self.splits, self.source_symbols,
                                self.target, self.target_symbols, max_passes=2)

    def test_failed_projection_does_not_publish_partial_configuration(self):
        args = SimpleNamespace(source='EN', target='JP', write=True, write_matching=False, verbose=False)
        with patch('argparse.ArgumentParser.parse_args', return_value=args), \
                patch('version_progress.verified_dol'), \
                patch('version_progress.load_splits', return_value=([], [])), \
                patch('pathlib.Path.read_text', return_value=''), \
                patch('version_progress.project_version', side_effect=ValueError('unstable')), \
                patch('version_progress.write_lf_text') as write, redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
