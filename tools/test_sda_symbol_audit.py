"""Retail SDA operand evidence must survive relocation normalization."""
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from orig.dol_xrefs import DolSection, FunctionSymbol
from orig.sda_symbol_audit import reference_pairs, retail_sda_base
from version_progress import (SplitRange, PortedRange, recover_sbss_layout,
                              parse_symbol_spans, render_projected_symbol_texts)


def image(base, bodies):
    startup = [0x3DA00000 | (base >> 16), 0x61AD0000 | (base & 0xFFFF), 0x4E800020]
    words = startup + [word for body in bodies for word in body]
    blob = struct.pack(f">{len(words)}I", *words)
    functions = []
    address = 0x80010000
    for index, body in enumerate(bodies):
        functions.append(FunctionSymbol(f"function_{index}", "text", address, len(body) * 4))
        address += len(body) * 4
    return SimpleNamespace(path=Path("synthetic.dol"), data=blob, sections=[
        DolSection(0, 0, 0x80003100, 12),
        DolSection(1, 12, 0x80010000, len(blob) - 12),
    ]), functions


class SdaAuditTests(unittest.TestCase):
    def test_negative_displacements_use_each_retail_startup_base(self):
        source, sf = image(0x80308000, [[0x806DA480, 0x4E800020]])
        target, tf = image(0x80318000, [[0x806DA478, 0x4E800020]])
        refs = reference_pairs(source, sf, target, tf)
        self.assertEqual(list(refs), [0x80302480])
        self.assertEqual(list(refs[0x80302480]), [0x80312478])
        self.assertEqual(refs[0x80302480][0x80312478][0]["target_instruction"], 0x80010000)

    def test_duplicate_function_shapes_are_not_rescued_by_equal_names(self):
        source, sf = image(0x80308000, [[0x806DA480, 0x4E800020], [0x806DA484, 0x4E800020]])
        target, tf = image(0x80318000, [[0x806DA478, 0x4E800020], [0x806DA480, 0x4E800020]])
        self.assertEqual(reference_pairs(source, sf, target, tf), {})

    def test_contradictory_operands_are_reported_without_majority_voting(self):
        source, sf = image(0x80308000, [[0x806DA480, 0x908DA480, 0x4E800020]])
        target, tf = image(0x80318000, [[0x806DA478, 0x908DA480, 0x4E800020]])
        self.assertEqual(set(reference_pairs(source, sf, target, tf)[0x80302480]),
                         {0x80312478, 0x80312480})

    def test_repeated_setters_need_two_unique_enclosing_functions(self):
        # Different register shapes make the enclosing functions unique; the
        # two interior getters intentionally have the same normalized shape.
        source, sf = image(0x80308000, [[0x808DA400, 0x4E800020],
            [0x806DA480, 0x4E800020], [0x806DA484, 0x4E800020], [0x80ADA500, 0x4E800020]])
        target, tf = image(0x80318000, [[0x808DA400, 0x4E800020],
            [0x806DA478, 0x4E800020], [0x806DA47C, 0x4E800020], [0x80ADA500, 0x4E800020]])
        refs = reference_pairs(source, sf, target, tf)
        self.assertEqual(list(refs[0x80302480]), [0x80312478])
        self.assertEqual(refs[0x80302480][0x80312478][0]["match_evidence"],
                         "unique enclosing functions")
        self.assertNotIn(0x80302480, reference_pairs(source, sf[:-1], target, tf[:-1]))

    def test_other_base_registers_and_updating_loads_are_not_sda_anchors(self):
        source, sf = image(0x80308000, [[0x806CA480, 0x846DA480, 0x4E800020]])
        target, tf = image(0x80318000, [[0x806CA478, 0x846DA478, 0x4E800020]])
        self.assertEqual(reference_pairs(source, sf, target, tf), {})

    def test_missing_or_repeated_startup_pair_is_rejected(self):
        source, _ = image(0x80308000, [])
        source.data = bytes(12)
        with self.assertRaisesRegex(ValueError, "one retail r13"):
            retail_sda_base(source)
        source, _ = image(0x80308000, [])
        source.data *= 2
        source.sections[0] = DolSection(0, 0, 0x80003100, 24)
        with self.assertRaisesRegex(ValueError, "one retail r13"):
            retail_sda_base(source)


class SdaLayoutTests(unittest.TestCase):
    def setUp(self):
        self.source = SimpleNamespace(sections=[DolSection(13, 0, 0x80, 0x80),
                                               DolSection(14, 0, 0x200, 4)])
        self.target = SimpleNamespace(sections=[DolSection(13, 0, 0xF80, 0x80),
                                               DolSection(14, 0, 0x1100, 4)])

    @staticmethod
    def symbols(entries):
        return "".join(f"{name} = .sbss:0x{address:08X}; // type:object size:0x4\n"
                       for name, address in entries)

    def project(self, splits, source_entries, target_entries, pairs):
        return recover_sbss_layout(self.source, self.target, splits,
            self.symbols(source_entries), self.symbols(target_entries),
            {a: {b: [{}]} for a, b in pairs}, {name for name, _ in source_entries})

    def test_equal_section_sizes_do_not_imply_constant_internal_delta(self):
        boundaries, symbols = self.project(
            [SplitRange("first.c", "sbss", 0x110, 0x114),
             SplitRange("second.c", "sbss", 0x120, 0x124)],
            [("first", 0x110), ("second", 0x120)],
            [("first", 0x1010), ("second", 0x1020)],
            [(0x110, 0x1010), (0x120, 0x1018)])
        self.assertEqual(boundaries, {0x110: 0x1010, 0x114: 0x1014,
                                      0x120: 0x1018, 0x124: 0x101C})
        self.assertEqual(parse_symbol_spans(symbols)["sbss"][1].start, 0x1018)

    def test_removed_leading_global_does_not_shift_surviving_symbols_back(self):
        boundaries, symbols = self.project(
            [SplitRange("walkgroups.c", "sbss", 0x110, 0x120),
             SplitRange("curves.c", "sbss", 0x120, 0x124)],
            [("removedChecksum", 0x110), ("index", 0x114), ("count", 0x118), ("next", 0x120)],
            [("removedChecksum", 0x1010), ("index", 0x1014), ("count", 0x1018), ("next", 0x1020)],
            [(0x108, 0x1008), (0x114, 0x1010), (0x118, 0x1014), (0x120, 0x1018)])
        self.assertEqual((boundaries[0x110], boundaries[0x120]), (0x1010, 0x1018))
        spans = parse_symbol_spans(symbols)["sbss"]
        self.assertEqual([(s.name, s.start) for s in spans],
                         [("index", 0x1010), ("count", 0x1014), ("next", 0x1018)])

    def test_conflicting_addresses_and_reordered_globals_fail_closed(self):
        for references in ({0x110: {0x1010: [{}], 0x1014: [{}]}},
                           {0x110: {0x1014: [{}]}, 0x114: {0x1010: [{}]}}):
            with self.subTest(references=references), self.assertRaises(ValueError):
                recover_sbss_layout(self.source, self.target, [], "", "", references, set())

    def test_changed_width_unit_keeps_a_source_used_address_label(self):
        name = "lbl_00000110"
        result, *_ = render_projected_symbol_texts(
            self.symbols([(name, 0x110)]), self.symbols([(name, 0x1010)]),
            [PortedRange(SplitRange("flags.c", "sbss", 0x110, 0x120),
                         0x1010, 0x1018, (), ())], {}, {name})
        self.assertEqual([(s.name, s.start) for s in parse_symbol_spans(result)["sbss"]],
                         [(name, 0x1010)])


if __name__ == "__main__":
    unittest.main()
