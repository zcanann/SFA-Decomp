"""Exercise cross-version boundaries, function pairing, and stable projection."""
from pathlib import Path
import hashlib
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr
from io import StringIO

from orig.dol_xrefs import DolSection, FunctionSymbol
from version_progress import (SymbolSpan, SplitRange, VersionProjection, build_boundary_map,
                              symbol_span_index, verified_dol, project_symbol_snapshot,
                              project_version, build_symbol_mappings, paired_functions,
                              PortedRange, render_projected_symbol_texts, main)
from version_progress import source_data_identifiers


def dol(data, address):
    return SimpleNamespace(path=Path('synthetic.dol'), data=data,
                           sections=[DolSection(13, 0, address, len(data))])


class CanonicalDataNameTests(unittest.TestCase):
    source = ('lbl_80300000 = .bss:0x80300000; // type:object size:0x4\n'
              'lbl_80300004 = .bss:0x80300004; // type:object size:0x4\n')
    target = ('lbl_80400000 = .bss:0x80400000; // type:object size:0x4\n'
              'lbl_80400004 = .bss:0x80400004; // type:object size:0x4\n')

    def ranges(self, size=8):
        return [PortedRange(SplitRange('example.c', 'bss', 0x80300000, 0x80300008),
                            0x80400000, 0x80400000 + size, (), ())]

    def test_shared_identifier_keeps_its_name_and_projected_address(self):
        result, *_ = render_projected_symbol_texts(
            self.source, self.target, self.ranges(), {}, {'lbl_80300000'})
        self.assertIn('lbl_80300000 = .bss:0x80400000;', result)
        self.assertIn('lbl_80400004 = .bss:0x80400004;', result)
        repeated, *_ = render_projected_symbol_texts(
            self.source, result, self.ranges(), {}, {'lbl_80300000'})
        self.assertEqual(result, repeated)

    def test_unequal_range_does_not_infer_data_identity(self):
        result, *_ = render_projected_symbol_texts(
            self.source, self.target, self.ranges(12), {}, {'lbl_80300000'})
        self.assertEqual(result, self.target)

    def test_conflicting_existing_owner_keeps_both_regional_names(self):
        target = self.target + 'lbl_80300000 = .bss:0x80300000; // type:object size:0x4\n'
        result, _, conflicts, _ = render_projected_symbol_texts(
            self.source, target, self.ranges(), {}, {'lbl_80300000'})
        self.assertIn('lbl_80300000 = .bss:0x80300000;', result)
        self.assertIn('lbl_80400000 = .bss:0x80400000;', result)
        self.assertEqual(conflicts, 1)

    def test_identifier_scan_ignores_comments_and_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'example.c').write_text(
                'int lbl_80300000;\n/* lbl_80300004 */\n// lbl_80300008\n'
                'char* message = "lbl_8030000C \\\" lbl_80300010";\n'
                'void f(void) { lbl_80300000 = lbl_80300014; }\n')
            splits = [self.ranges()[0].source, SplitRange('missing.c', 'data', 0, 4)]
            self.assertEqual(source_data_identifiers(splits, root), {'lbl_80300000', 'lbl_80300014'})

    def test_name_conflicts_propagate_without_duplicate_owners(self):
        ranges = [PortedRange(self.ranges()[0].source, 0x80300004, 0x8030000C, (), ())]
        target = ('lbl_80300000 = .bss:0x80300000; // type:object size:0x4\n'
                  'lbl_80300004 = .bss:0x80300004; // type:object size:0x4\n'
                  'lbl_80300008 = .bss:0x80300008; // type:object size:0x4\n')
        result, _, conflicts, _ = render_projected_symbol_texts(
            self.source, target, ranges, {}, {'lbl_80300000', 'lbl_80300004'})
        self.assertEqual(result, target)
        self.assertEqual(conflicts, 2)


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


class AnchoredFunctionPairTests(unittest.TestCase):
    def make_range(self):
        source = tuple(FunctionSymbol(f's{i}', 'text', 0x1000 + i * 8, 8) for i in range(8))
        target = tuple(FunctionSymbol(f't{i}', 'text', 0x2000 + i * 8, 8) for i in range(9))
        return PortedRange(SplitRange('example.c', 'text', 0x1000, 0x1040),
                           0x2000, 0x2048, source, target)

    def test_insertion_only_blocks_its_own_anchor_interval(self):
        split = self.make_range()
        # Prefix/suffix are unanchored; t4 is inserted between s3 and s4.
        anchors = {split.source_functions[i].address: split.target_functions[j]
                   for i, j in [(1, 1), (3, 3), (4, 5), (6, 7)]}
        pairs = [(a.name, b.name) for a, b in paired_functions(split, anchors)]
        self.assertEqual(pairs, [('s1', 't1'), ('s2', 't2'), ('s3', 't3'),
                                 ('s4', 't5'), ('s5', 't6'), ('s6', 't7')])
        self.assertEqual(build_symbol_mappings([split], anchors),
                         {'example.c': {target: source for source, target in pairs}})

    def test_unequal_interior_run_stays_unpaired_in_both_directions(self):
        split = self.make_range()
        for reverse in (False, True):
            with self.subTest(deletion=reverse):
                source, target = split.source_functions, split.target_functions
                indices = [(1, 1), (4, 5)]
                if reverse:
                    source, target = target, source
                    indices = [(b, a) for a, b in indices]
                source_range = SplitRange(
                    "example.c", "text", source[0].address, source[-1].address + 8
                )
                window = PortedRange(source_range, target[0].address,
                                     target[-1].address + 8, source, target)
                anchors = {source[a].address: target[b] for a, b in indices}
                self.assertEqual(paired_functions(window, anchors),
                                 [(source[a], target[b]) for a, b in indices])

    def test_rendering_and_fallbacks_use_the_same_anchored_pairs(self):
        split = self.make_range()
        anchors = {split.source_functions[i].address: split.target_functions[j]
                   for i, j in [(1, 1), (3, 3), (4, 5), (6, 7)]}
        text = ''.join(f'{f.name} = .text:0x{f.address:08X}; // type:function size:0x8\n'
                       for f in split.target_functions)
        rendered, renamed, conflicts, _ = render_projected_symbol_texts('', text, [split], anchors)
        self.assertEqual(renamed, 6)
        self.assertEqual(conflicts, 0)
        for old, new in build_symbol_mappings([split], anchors)['example.c'].items():
            self.assertNotIn(f'{old} =', rendered)
            self.assertIn(f'{new} =', rendered)
        for name in ('t0', 't4', 't8'):
            self.assertIn(f'{name} =', rendered)

    def test_reordered_anchors_do_not_infer_ordinal_pairs(self):
        split = self.make_range()
        anchors = {split.source_functions[i].address: split.target_functions[j]
                   for i, j in [(1, 1), (3, 3), (4, 2), (6, 4)]}
        self.assertEqual([(a.name, b.name) for a, b in paired_functions(split, anchors)],
                         [('s1', 't1'), ('s3', 't3'), ('s4', 't2'), ('s6', 't4')])

    def test_no_or_single_anchor_cannot_infer_neighbors(self):
        split = self.make_range()
        self.assertEqual(paired_functions(split, {}), [])
        anchor = {split.source_functions[3].address: split.target_functions[4]}
        self.assertEqual(paired_functions(split, anchor),
                         [(split.source_functions[3], split.target_functions[4])])


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
