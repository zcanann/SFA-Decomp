import copy
import struct
import unittest
from unittest.mock import Mock

from tricky_debug_locations import (
    Entry, function_entries, location, parse_entries, parse_lines,
    relocated_section, require_production_equivalence, source_line,
)
from tricky_object_compare import ObjectSnapshot


def entry(tag, attributes=b""):
    return struct.pack(">IH", len(attributes) + 6, tag) + attributes


def attribute(code, payload):
    return struct.pack(">H", code) + payload


def line_table(rows, base=0):
    return struct.pack(">II", 8 + len(rows) * 10, base) + b"".join(
        struct.pack(">IHI", line, 0xFFFF, offset) for offset, line in rows
    )


class EntriesTest(unittest.TestCase):
    def test_standard_forms(self):
        attributes = b"".join([
            attribute(0x111, struct.pack(">I", 12)),
            attribute(0x12, struct.pack(">I", 90)),
            attribute(0x55, struct.pack(">H", 7)),
            attribute(0xB6, struct.pack(">I", 4)),
            attribute(0x1C7, struct.pack(">Q", 0x123456789)),
            attribute(0x23, b"\0\x05\x01\0\0\0\x1c"),
            attribute(0xF4, b"\0\0\0\x02ab"),
            attribute(0x38, b"local\0"),
        ])
        result, = parse_entries(entry(12, attributes))
        self.assertEqual(result.name, "local")
        self.assertEqual(result.attributes[0x110], 12)
        self.assertEqual(result.attributes[0x10], 90)
        self.assertEqual(result.attributes[0x50], 7)
        self.assertEqual(result.attributes[0xB0], 4)
        self.assertEqual(result.attributes[0x1C0], 0x123456789)
        self.assertEqual(result.attributes[0xF0], b"ab")
        self.assertEqual(location(result.attributes[0x20]), "reg(28)")

    def test_null_and_padding(self):
        records = parse_entries(struct.pack(">I", 4) + entry(0, b"padding") + b"\0\0")
        self.assertEqual([record.tag for record in records], [0, 0])
        self.assertEqual(parse_entries(b"\0" * 8), [])

    def test_repeated_vendor_attributes_are_preserved(self):
        data = entry(6, attribute(0x2022, struct.pack(">I", 12)) * 2)
        record, = parse_entries(data)
        self.assertEqual(record.extensions, [(0x2022, 12), (0x2022, 12)])
        self.assertNotIn(0x2020, record.attributes)

    def test_unresolved_attribute(self):
        data = entry(12, attribute(0x23, b"\0\x05\x03\0\0\0\0"))
        record, = parse_entries(data, {11})
        self.assertEqual(record.unresolved, {0x20})

    def test_malformed_entries(self):
        cases = [
            b"\x01", struct.pack(">I", 99), struct.pack(">I", 3),
            b"\0\0\0\0bad", entry(12, attribute(0x38, b"no terminator")),
            entry(12, attribute(0x23, b"\0\x05ab")),
            entry(12, attribute(0x39, b"")),
            entry(12, attribute(0x55, b"\0\x01") * 2),
        ]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_entries(data)

    def test_scope_children_and_following_function(self):
        records = [
            Entry(0, 20, 6, {0x30: "f", 0x10: 100}),
            Entry(20, 40, 11, {0x10: 80}),
            Entry(40, 60, 12, {0x30: "x", 0x10: 60}),
            Entry(60, 80, 12, {0x30: "y", 0x10: 80}),
            Entry(80, 100, 12, {0x30: "z", 0x10: 100}),
            Entry(100, 120, 6, {0x30: "g", 0x10: 120}),
        ]
        self.assertEqual([(d, e.name) for d, e in function_entries(records, "f")],
                         [(0, "f"), (1, ""), (2, "x"), (2, "y"), (1, "z")])
        with self.assertRaises(ValueError):
            function_entries(records, "missing")
        records[1].attributes[0x10] = 120
        with self.assertRaises(ValueError):
            function_entries(records, "f")


class LocationsTest(unittest.TestCase):
    def test_stack_location(self):
        expression = b"\x02" + struct.pack(">I", 1) + b"\x04" + struct.pack(">i", -12) + b"\x07"
        self.assertEqual(location(expression), "base(1) const(-12) add")
        self.assertEqual(location(b""), "optimized out")
        self.assertEqual(location(b"\x05\x06"), "deref2 deref")
        self.assertEqual(location(b"\xe0\x01"), "opaque location e001")
        with self.assertRaises(ValueError):
            location(b"\x01\0")

    def test_lines_and_interior_unknown_span(self):
        lines = parse_lines(line_table([(0, 10), (4, 0), (8, 20), (12, 0)], base=100))
        self.assertIsNone(source_line(lines, 99))
        self.assertEqual(source_line(lines, 103), 10)
        self.assertIsNone(source_line(lines, 107))
        self.assertEqual(source_line(lines, 111), 20)
        self.assertIsNone(source_line(lines, 112))

    def test_unsorted_and_duplicate_line_addresses(self):
        lines = parse_lines(line_table([(4, 12), (0, 10), (4, 14), (8, 0)]))
        self.assertEqual(source_line(lines, 4), 14)

    def test_bad_line_tables(self):
        for data in (b"\0", struct.pack(">II", 8, 0), line_table([(0, 1)]), line_table([(0, 0)])[:-1]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_lines(data)


class RelocationsTest(unittest.TestCase):
    def elf(self, relocations, symbol):
        section = Mock()
        section.data.return_value = b"\0" * 12
        table = Mock()
        table.get_symbol.return_value = symbol

        class Relocations(dict):
            def iter_relocations(self):
                return iter(relocations)

        elf = Mock()
        elf.get_section_by_name.side_effect = [section, Relocations(sh_link=7, sh_info=3)]
        elf.get_section_index.return_value = 3
        elf.get_section.return_value = table
        return elf

    def test_defined_unaligned_and_undefined_relocations(self):
        relocation = {"r_info_type": 24, "r_info_sym": 1, "r_offset": 1, "r_addend": 4}
        data, unresolved = relocated_section(self.elf([relocation], {"st_shndx": 1, "st_value": 8}), ".debug")
        self.assertEqual(data[1:5], struct.pack(">I", 12))
        self.assertEqual(unresolved, set())
        _, unresolved = relocated_section(self.elf([relocation], {"st_shndx": "SHN_UNDEF"}), ".debug")
        self.assertEqual(unresolved, {1})

    def test_relocation_bounds_and_kind(self):
        for kind, offset in ((1, 10), (2, 0)):
            relocation = {"r_info_type": kind, "r_info_sym": 1, "r_offset": offset, "r_addend": 0}
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                relocated_section(self.elf([relocation], {"st_shndx": 1, "st_value": 0}), ".debug")


class EquivalenceTest(unittest.TestCase):
    def test_debug_digest_can_differ_but_production_fields_cannot(self):
        before = ObjectSnapshot("before", {}, {}, {}, {})
        after = ObjectSnapshot("after", {}, {}, {}, {})
        require_production_equivalence(before, after)
        for field in ("functions", "sections", "symbols", "relocations"):
            changed = copy.deepcopy(after)
            getattr(changed, field)["changed"] = 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                require_production_equivalence(before, changed)


if __name__ == "__main__":
    unittest.main()
