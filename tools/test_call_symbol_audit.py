"""Direct-call identity needs independent callers and consistent retail targets."""
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from orig.call_symbol_audit import call_candidates, call_destination
from orig.dol_xrefs import DolSection, FunctionSymbol


def image(base, bodies):
    blob = bytearray(0x300)
    functions = []
    for name, offset, words in bodies:
        struct.pack_into(f">{len(words)}I", blob, offset, *words)
        functions.append(FunctionSymbol(name, "text", base + offset, len(words) * 4))
    return SimpleNamespace(path=Path("synthetic.dol"), data=bytes(blob),
                           sections=[DolSection(1, 0, base, len(blob))]), functions


def call(site, destination):
    return 0x48000001 | ((destination - site) & 0x03FFFFFC)


class CallAuditTests(unittest.TestCase):
    def setUp(self):
        self.source = [("first", 0, [0x7C0802A6, call(4, 0x100), 0x4E800020]),
                       ("second", 0x40, [0x7C6802A6, call(0x44, 0x100), 0x4E800020]),
                       ("getter", 0x100, [0x806D1000, 0x4E800020]),
                       ("otherGetter", 0x140, [0x806D1004, 0x4E800020])]
        self.target = [(name, offset, list(words)) for name, offset, words in self.source]
        self.target[2] = ("regionalGetter", 0x100, [0x806D1010, 0x4E800020])

    def rows(self):
        a, af = image(0x80010000, self.source)
        b, bf = image(0x80020000, self.target)
        return call_candidates(a, af, b, bf)

    def getter(self):
        return next(r for r in self.rows() if r["source"] == "getter")

    def test_two_unique_callers_resolve_a_repeated_getter_shape(self):
        row = self.getter()
        self.assertEqual(row["status"], "candidate")
        self.assertEqual(row["target_address"], 0x80020100)
        self.assertEqual(len(row["targets"][0]["references"]), 2)

    def test_equal_caller_names_do_not_rescue_repeated_instruction_shapes(self):
        self.source[1][2][0] = self.target[1][2][0] = 0x7C0802A6
        self.assertEqual(self.rows(), [])

    def test_multiple_calls_from_one_function_are_not_independent(self):
        self.source.pop(1)
        self.target.pop(1)
        for bodies in (self.source, self.target):
            bodies[0][2].insert(2, call(8, 0x100))
        self.assertEqual(self.getter()["status"], "single-caller")

    def test_conflicting_destinations_are_not_resolved_by_voting(self):
        self.target[1][2][1] = call(0x44, 0x140)
        self.assertEqual(self.getter()["status"], "conflicting-targets")

    def test_shared_target_cannot_take_two_source_identities(self):
        self.source[1][2][1] = call(0x44, 0x140)
        self.assertEqual(self.getter()["status"], "shared-target")

    def test_callee_body_change_blocks_identity_promotion(self):
        self.target[2][2][0] = 0x886D1010
        self.assertEqual(self.getter()["status"], "changed-callee")

    def test_interior_target_is_not_a_function_boundary(self):
        for offset, index in ((4, 0), (0x44, 1)):
            self.target[index][2][1] = call(offset, 0x104)
        self.assertEqual(self.getter()["status"], "missing-target-boundary")

    def test_calls_decode_signed_relative_and_absolute_destinations(self):
        self.assertEqual(call_destination(call(0x80010100, 0x80010000), 0x80010100), 0x80010000)
        self.assertEqual(call_destination(0x48000103, 0x80010100), 0x100)
        self.assertIsNone(call_destination(0x48000100, 0x80010100))
        self.assertIsNone(call_destination(0x4E800421, 0x80010100))


if __name__ == "__main__":
    unittest.main()
