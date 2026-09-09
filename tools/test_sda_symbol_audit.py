"""Retail SDA operand evidence must survive relocation normalization."""
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from orig.dol_xrefs import DolSection, FunctionSymbol
from orig.sda_symbol_audit import reference_pairs, retail_sda_base
from version_progress import (SplitRange, PortedRange, recover_sbss_layout,
                              recover_sdata_layout, parse_symbol_spans,
                              render_projected_symbol_texts, replace_projected_section_symbols, preserves_sda_base,
                              port_coherent_units, symbol_span_index, SECTION_INDEX)


def image(base, bodies, register=13):
    startup = [0x3C000000 | register << 21 | (base >> 16),
               0x60000000 | register << 21 | register << 16 | (base & 0xFFFF), 0x4E800020]
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

    def test_r2_constants_use_their_own_base_and_ignore_r13_operands(self):
        source, sf = image(0x80310000, [[0xC022FFFC, 0x806DFFFC, 0x4E800020]], register=2)
        target, tf = image(0x80320000, [[0xC022FFF8, 0x806DFFF0, 0x4E800020]], register=2)
        refs = reference_pairs(source, sf, target, tf, register=2)
        self.assertEqual(list(refs), [0x8030FFFC])
        self.assertEqual(list(refs[0x8030FFFC]), [0x8031FFF8])
        self.assertEqual(retail_sda_base(target, 2), 0x80320000)

    def test_updating_r2_is_not_a_constant_pool_access(self):
        source, sf = image(0x80310000, [[0xC422FFFC, 0x4E800020]], register=2)
        target, tf = image(0x80320000, [[0xC422FFF8, 0x4E800020]], register=2)
        self.assertEqual(reference_pairs(source, sf, target, tf, register=2), {})

    def test_context_restore_pointer_is_not_the_abi_r2_base(self):
        body = [0x3C40803D, 0x604283A0, 0xC022FFFC, 0x4E800020]
        source, sf = image(0x80310000, [body], register=2)
        target, tf = image(0x80320000, [body], register=2)
        self.assertEqual(reference_pairs(source, sf, target, tf, register=2), {})

    def test_base_writes_are_rejected_but_fpr2_is_a_different_register(self):
        # li, ori, rlwinm, lwz, lmw, mr, mflr, lwzux, lfsu, psq_lu.
        for word in [0x38400000, 0x60420000, 0x5462003E, 0x80430000,
                     0xB8030000, 0x7C621B78, 0x7C4802A6, 0x7C62006E,
                     0xC4220004, 0xE4220004]:
            with self.subTest(instruction=hex(word)):
                self.assertFalse(preserves_sda_base([word], 2))
        # lfs f2,0(r3), lfsx f2,r3,r0, and mflr r0 preserve GPR r2.
        self.assertTrue(preserves_sda_base([0xC0430000, 0x7C43042E, 0x7C0802A6], 2))

    def test_non_sda_base_register_is_rejected(self):
        source, _ = image(0x80310000, [])
        with self.assertRaisesRegex(ValueError, "r2 or r13"):
            retail_sda_base(source, 3)

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


class InitializedSdaLayoutTests(unittest.TestCase):
    def setUp(self):
        self.values = struct.pack(">4I", 0x3DCCCCCD, 0x3E99999A, 0x3DCCCCCD, 0x3E99999A)
        self.source = SimpleNamespace(path=Path("source.dol"), data=self.values,
                                      sections=[DolSection(13, 0, 0x1000, 16)])
        self.target = SimpleNamespace(path=Path("target.dol"), data=self.values + b"next",
                                      sections=[DolSection(13, 0, 0x2000, 20)])
        self.source_symbols = "".join(
            f"phase{i} = .sdata:0x{0x1000 + i * 4:08X}; // type:object size:0x4\n"
            for i in range(4))
        self.target_symbols = "lbl_00002000 = .sdata:0x00002000; // type:object size:0x14\n"
        self.references = {0x1000 + i * 4: {0x2000 + i * 4: [{}]} for i in range(4)}
        self.splits = [SplitRange("effect.c", "sdata", 0x1000, 0x1010)]

    def project(self):
        return recover_sdata_layout(self.source, self.target, self.splits,
            self.source_symbols, self.target_symbols, self.references, set())

    def test_operand_and_complete_bytes_recover_four_float_boundary(self):
        boundaries, symbols, ranges = self.project()
        self.assertEqual(boundaries, {0x1000: 0x2000, 0x1010: 0x2010})
        self.assertEqual(ranges, {self.splits[0]: (0x2000, 0x2010)})
        self.assertEqual([(s.name, s.start) for s in parse_symbol_spans(symbols)["sdata"]],
                         [(f"phase{i}", 0x2000 + i * 4) for i in range(4)])

    def test_initialized_r2_section_uses_the_same_operand_and_byte_gate(self):
        self.source.sections = [DolSection(14, 0, 0x1000, 16)]
        self.target.sections = [DolSection(14, 0, 0x2000, 20)]
        boundaries, symbols, ranges = recover_sdata_layout(
            self.source, self.target, [SplitRange("effect.c", "sdata2", 0x1000, 0x1010)],
            self.source_symbols.replace(".sdata:", ".sdata2:"),
            self.target_symbols.replace(".sdata:", ".sdata2:"), self.references, set(),
            section_name="sdata2")
        self.assertEqual(boundaries, {0x1000: 0x2000, 0x1010: 0x2010})
        self.assertEqual(len(parse_symbol_spans(symbols)["sdata2"]), 4)
        self.assertEqual(ranges, {SplitRange("effect.c", "sdata2", 0x1000, 0x1010): (0x2000, 0x2010)})

    def test_repeated_initializers_without_operand_evidence_prove_nothing(self):
        self.references = {}
        self.assertEqual(self.project(), ({}, self.target_symbols, {}))

    def test_changed_initializer_blocks_whole_range_but_not_other_names(self):
        self.target.data = b"diff" + self.target.data[4:]
        boundaries, symbols, ranges = self.project()
        self.assertFalse(boundaries)
        self.assertFalse(ranges)
        self.assertNotIn("phase0", symbols)
        self.assertIn("phase1", symbols)

    def test_interior_operand_shift_cannot_be_hidden_by_repeated_float_values(self):
        self.references[0x1008] = {0x2000: [{}]}
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.project()

    def test_conflicting_reference_does_not_choose_a_matching_value(self):
        self.references[0x1000][0x2008] = [{}]
        boundaries, symbols, ranges = self.project()
        self.assertFalse(boundaries)
        self.assertFalse(ranges)
        self.assertNotIn("phase0", symbols)

    def test_touching_source_pools_keep_separate_edges_around_target_insertions(self):
        for section in ("sdata", "sdata2"):
            for gap in (b"new!", b"new pool"):
                with self.subTest(section=section, gap_size=len(gap)):
                    self.source.sections = [
                        DolSection(i, 0, 0x1000 if i == SECTION_INDEX[section] else 0,
                                   16 if i == SECTION_INDEX[section] else 0)
                        for i in SECTION_INDEX.values()]
                    self.target.data = self.values[:8] + gap + self.values[8:]
                    self.target.sections = [
                        DolSection(i, 0, 0x2000 if i == SECTION_INDEX[section] else 0,
                                   len(self.target.data) if i == SECTION_INDEX[section] else 0)
                        for i in SECTION_INDEX.values()]
                    splits = [SplitRange("a.c", section, 0x1000, 0x1008),
                              SplitRange("b.c", section, 0x1008, 0x1010)]
                    refs = {0x1000 + i * 4: {0x2000 + i * 4 + (len(gap) if i >= 2 else 0): [{}]}
                            for i in range(4)}
                    source_symbols = self.source_symbols.replace(".sdata:", f".{section}:")
                    boundaries, symbols, ranges = recover_sdata_layout(
                        self.source, self.target, splits, source_symbols, "", refs, set(),
                        section_name=section)
                    self.assertNotIn(0x1008, boundaries)
                    self.assertEqual(ranges, {splits[0]: (0x2000, 0x2008),
                                             splits[1]: (0x2008 + len(gap), 0x2010 + len(gap))})
                    # A global edge map chooses the following pool's start and
                    # would wrongly widen the preceding pool across the insertion.
                    boundaries[0x1008] = 0x2008 + len(gap)
                    spans = parse_symbol_spans(symbols)
                    index = symbol_span_index(spans)
                    ported, rejected, *_ = port_coherent_units(
                        splits, [], [], {section: boundaries}, index, index,
                        self.source, self.target, parse_symbol_spans(source_symbols), spans, ranges)
                    self.assertFalse(rejected)
                    self.assertEqual([(p.target_start, p.target_end) for p in ported],
                                     [(0x2000, 0x2008), (0x2008 + len(gap), 0x2010 + len(gap))])

    def test_changed_code_keeps_a_regionally_extended_pool(self):
        self.source.data = self.values + struct.pack(">I", 0x4E800020)
        self.target.data = self.values[:8] + b"new!" + self.values[8:] + struct.pack(">II", 0x38600000, 0x4E800020)
        self.source.sections = [DolSection(i, 0, 0x1000 if i == 13 else 0, 16 if i == 13 else 0)
                                for i in SECTION_INDEX.values() if i != 1]
        self.source.sections.append(DolSection(1, 16, 0x80001000, 4))
        self.target.sections = [DolSection(i, 0, 0x2000 if i == 13 else 0, 20 if i == 13 else 0)
                                for i in SECTION_INDEX.values() if i != 1]
        self.target.sections.append(DolSection(1, 20, 0x80002000, 8))
        splits = [SplitRange("a.c", "sdata", 0x1000, 0x1008),
                  SplitRange("b.c", "sdata", 0x1008, 0x1010),
                  SplitRange("a.c", "text", 0x80001000, 0x80001004)]
        refs = {0x1000 + i * 4: {0x2000 + i * 4 + (4 if i >= 2 else 0): [{}]} for i in range(4)}
        boundaries, symbols, ranges = recover_sdata_layout(
            self.source, self.target, splits, self.source_symbols, "", refs, set())
        self.assertEqual(ranges[splits[0]], (0x2000, 0x2008))
        boundaries[0x1008] = 0x200C
        spans = parse_symbol_spans(symbols)
        index = symbol_span_index(spans)
        ported, rejected, *_ = port_coherent_units(
            splits, [], [], {"sdata": boundaries, "text": {0x80001000: 0x80002000, 0x80001004: 0x80002008}},
            index, index, self.source, self.target, parse_symbol_spans(self.source_symbols), spans, ranges)
        self.assertFalse(rejected)
        pool = next(p for p in ported if p.source == splits[0])
        self.assertEqual((pool.target_start, pool.target_end), (0x2000, 0x200C))

    def test_equal_width_does_not_override_an_independently_moved_global(self):
        source = "active = .sdata:0x00001000; // type:object size:0x1\n"
        target = "active = .sdata:0x00002005; // type:object size:0x1\n"
        result, *_ = render_projected_symbol_texts(source, target,
            [PortedRange(SplitRange("options.c", "sdata", 0x1000, 0x1008),
                         0x2000, 0x2008, (), ())], {}, set(), {0x1000: {0x2005: [{}]}})
        self.assertEqual(parse_symbol_spans(result)["sdata"][0].start, 0x2005)

    def test_replacing_old_storage_does_not_free_its_unchanged_address_name(self):
        old = "lbl_00001000 = .sdata2:0x00001000; // type:object size:0x4"
        imported = "lbl_00001000 = .sdata2:0x00002000; // type:object size:0x4"
        result = replace_projected_section_symbols(old + "\n", "sdata2", [
            (0x1000, 0x1004, "lbl_00001000", old),
            (0x2000, 0x2004, "lbl_00001000", imported)])
        self.assertEqual([(s.name, s.start) for s in parse_symbol_spans(result)["sdata2"]],
                         [("lbl_00001000", 0x1000), ("lbl_00002000", 0x2000)])

    def test_source_used_address_name_does_not_erase_unrelated_regional_label(self):
        target = "lbl_00001000 = .sdata:0x00001000; // type:object size:0x4\n"
        line = "lbl_00001000 = .sdata:0x00002000; // type:object size:0x4\n"
        result = replace_projected_section_symbols(target, "sdata", [
            (0x2000, 0x2004, "lbl_00001000", line.rstrip())])
        self.assertEqual([(s.name, s.start) for s in parse_symbol_spans(result)["sdata"]],
                         [("lbl_00001000", 0x1000), ("lbl_00002000", 0x2000)])


if __name__ == "__main__":
    unittest.main()
