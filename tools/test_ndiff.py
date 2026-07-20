"""Paired controls for ndiff.normalize's branch-target handling.

Positive control models synthGetNextChannelEvent: two streams whose bytes differ
in exactly one branch target. Negative controls model OSGetConsoleType and a
cross-function call: byte-identical code disassembled at a different .text
offset, where every absolute address in the listing shifts.

Each positive control also asserts that the pre-fix normalization (mask every
label) reports NO difference, so a control cannot pass with the fix disabled.

Run: python3 tools/test_ndiff.py
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ndiff import normalize, regions

SYM = "fn"


def listing(base: int, body: list[tuple[str, str]]) -> list[str]:
    """Build objdump -drz lines. body entries are (bytes, disassembly text)."""
    out = []
    for i, (raw, text) in enumerate(body):
        out.append(f"  {base + 4 * i:x}:\t{raw} \t{text}")
    return out


def target(base: int, off: int, sym: str = SYM) -> str:
    return f"{base + off:x} <{sym}+0x{off:x}>"


def naive(lines: list[str]) -> list[str]:
    """Pre-fix normalization: mask every 'addr <sym+0xN>' label wholesale."""
    return [re.sub(r"\b[0-9a-f]+ <[^>]+>", "LBL", s) for s in normalize(lines)]


class BranchTargetVisibility(unittest.TestCase):
    def build(self, base: int, skip: int) -> list[str]:
        return listing(base, [
            ("2c 03 00 00", "cmpwi   r3,0"),
            ("41 82 00 00", "beq-    " + target(base, 4 * skip)),
            ("38 00 00 01", "li      r0,1"),
            ("48 00 00 00", "b       " + target(base, 24)),
            ("38 00 00 00", "li      r0,0"),
            ("4e 80 00 20", "blr"),
        ])

    def test_positive_retargeted_branch_is_visible(self):
        t = normalize(self.build(0x0, 4), SYM)
        c = normalize(self.build(0x0, 2), SYM)
        self.assertTrue(regions(t, c), "a retargeted branch must produce a region")

    def test_positive_control_is_discriminating(self):
        # The same pair under the pre-fix normalization: silently clean.
        self.assertEqual(naive(self.build(0x0, 4)), naive(self.build(0x0, 2)))

    def test_positive_survives_an_offset_shift(self):
        t = normalize(self.build(0x0, 4), SYM)
        c = normalize(self.build(0x19c00, 2), SYM)
        self.assertTrue(regions(t, c), "a retargeted branch must stay visible")

    def test_negative_identical_code_at_a_different_offset(self):
        t = normalize(self.build(0x0, 4), SYM)
        c = normalize(self.build(0x19c00, 4), SYM)
        self.assertEqual(regions(t, c), [], "an offset shift alone must be silent")

    def test_negative_offset_shift_is_a_real_shift(self):
        # Guard: the two listings really do carry different absolute addresses.
        self.assertNotEqual(self.build(0x0, 4), self.build(0x19c00, 4))


class CrossFunctionTargets(unittest.TestCase):
    def call(self, base: int, callee_at: int) -> list[str]:
        lines = listing(base, [
            ("48 00 00 01", f"bl      {callee_at:x} <other>"),
            ("4e 80 00 20", "blr"),
        ])
        lines.insert(1, f"\t\t\t{base:x}: R_PPC_REL24\tother")
        return lines

    def test_negative_call_target_address_is_not_compared(self):
        # .text order moves an intra-object callee; identity is the reloc.
        t = normalize(self.call(0x0, 0x400), SYM)
        c = normalize(self.call(0x0, 0x9000), SYM)
        self.assertEqual(regions(t, c), [], "callee address must not be compared")
        self.assertIn("RELOC other", t)

    def test_positive_call_target_symbol_is_compared(self):
        t = normalize(self.call(0x0, 0x400), SYM)
        c = normalize([s.replace("other", "elsewhere") for s in self.call(0x0, 0x400)], SYM)
        self.assertTrue(regions(t, c), "a different callee must produce a region")


if __name__ == "__main__":
    unittest.main(verbosity=2)
