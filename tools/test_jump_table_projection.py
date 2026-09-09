"""Case destinations must establish regional jump-table identity and extent."""
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from orig.dol_xrefs import DolSection
from version_progress import SplitRange, parse_function_symbols, recover_jump_table_layout


def image(address, words):
    raw = struct.pack(f">{len(words)}I", *words)
    return SimpleNamespace(path=Path("synthetic.dol"), data=raw,
                           sections=[DolSection(12, 0, address, len(raw))])


class JumpTableProjectionTests(unittest.TestCase):
    def setUp(self):
        self.source = image(0x80300000, [0x80010010, 0x80010020, 0x80010010, 0])
        self.target = image(0x80310000, [0x80020010, 0x80020020, 0x80020010, 0])
        self.source_symbols = ("dispatch = .text:0x80010000; // type:function size:0x40\n"
                               "@12 = .data:0x80300000; // type:object size:0xC scope:local\n")
        self.target_symbols = ("dispatch = .text:0x80020000; // type:function size:0x40\n"
                               "lbl_80310000 = .data:0x80310000; // type:object size:0x10\n")
        self.matches = {0x80010000: parse_function_symbols(self.target_symbols)[0]}
        self.splits = [SplitRange("dispatch.c", "data", 0x80300000, 0x80300010)]

    def project(self):
        return recover_jump_table_layout(self.source, self.target, self.splits,
                                         self.source_symbols, self.target_symbols, self.matches)

    def test_exact_case_offsets_and_alignment_recover_complete_range(self):
        boundaries, symbols = self.project()
        self.assertEqual(boundaries, {0x80300000: 0x80310000, 0x80300010: 0x80310010})
        self.assertIn("@12 = .data:0x80310000", symbols)

    def test_matching_pointer_count_does_not_hide_wrong_case_order(self):
        self.target = image(0x80310000, [0x80020020, 0x80020010, 0x80020010, 0])
        self.assertEqual(self.project(), ({}, self.target_symbols))

    def test_repeated_table_is_ambiguous_even_with_same_symbol_name(self):
        self.target.data *= 2
        self.target.sections = [DolSection(12, 0, 0x80310000, len(self.target.data))]
        self.assertEqual(self.project(), ({}, self.target_symbols))

    def test_unmatched_function_does_not_gain_identity_from_name(self):
        self.matches.clear()
        self.assertEqual(self.project(), ({}, self.target_symbols))

    def test_function_entry_callbacks_are_not_switch_cases(self):
        self.source = image(0x80300000, [0x80010000] * 3 + [0])
        self.target = image(0x80310000, [0x80020000] * 3 + [0])
        self.assertEqual(self.project(), ({}, self.target_symbols))

    def test_nonzero_tail_cannot_be_claimed_as_alignment(self):
        self.target = image(0x80310000, [0x80020010, 0x80020020, 0x80020010, 0x1234])
        boundaries, symbols = self.project()
        self.assertFalse(boundaries)
        self.assertIn("@12 = .data:0x80310000", symbols)

    def test_repeated_anonymous_name_does_not_erase_unrelated_target_storage(self):
        self.source_symbols += "@12 = .data:0x8030000C; // type:object size:0x4 scope:local\n"
        self.target_symbols += "@12 = .data:0x8031000C; // type:object size:0x4 scope:local\n"
        boundaries, symbols = self.project()
        self.assertTrue(boundaries)
        self.assertIn("jumptable_80310000 = .data:0x80310000", symbols)
        self.assertIn("@12 = .data:0x8031000C", symbols)

    def test_long_unexplained_zero_tail_does_not_establish_ownership(self):
        self.splits = [SplitRange("dispatch.c", "data", 0x80300000, 0x80300020)]
        self.assertFalse(self.project()[0])


if __name__ == "__main__":
    unittest.main()
