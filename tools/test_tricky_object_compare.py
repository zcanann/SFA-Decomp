import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tricky_object_compare import ObjectSnapshot, compare_objects, comparison_summary, read_object


def snapshot(**kwargs):
    values = {
        "digest": "before",
        "functions": {"turn": b"\x7c\x7d\x1b\x78"},
        "sections": {".text": ("SHT_PROGBITS", 6, 4, 4, b"\x7c\x7d\x1b\x78"),
                     ".sbss": ("SHT_NOBITS", 3, 4, 8, bytes(8))},
        "symbols": {"turn": (".text", 0, 4, "STT_FUNC", "STB_GLOBAL", "STV_DEFAULT"),
                    "state": (".sbss", 0, 4, "STT_OBJECT", "STB_GLOBAL", "STV_DEFAULT")},
        "relocations": {".rela.text -> .text": ((0, 10, 0, "callee", "SHN_UNDEF", 0),)},
    }
    values.update(kwargs)
    return ObjectSnapshot(**values)


def object_fixture():
    """Minimal big-endian ELF32 object with code, BSS, and one relocation."""
    names = b"\0.text\0.sbss\0.symtab\0.strtab\0.shstrtab\0.rela.text\0"
    strings = b"\0turn\0state\0callee\0"
    code = b"\x48\x00\x00\x01"
    symbols = bytes(16)
    symbols += struct.pack(">IIIBBH", 1, 0, 4, 0x12, 0, 1)
    symbols += struct.pack(">IIIBBH", 6, 0, 4, 0x11, 0, 2)
    symbols += struct.pack(">IIIBBH", 12, 0, 0, 0x12, 0, 0)
    relocation = struct.pack(">IIi", 0, (3 << 8) | 10, -4)
    data = bytearray(52)
    headers = [(0,) * 10]
    for name, kind, flags, contents, size, link, info, alignment, entry in [
        (".text", 1, 6, code, 4, 0, 0, 4, 0),
        (".sbss", 8, 3, b"", 8, 0, 0, 4, 0),
        (".symtab", 2, 0, symbols, len(symbols), 4, 1, 4, 16),
        (".strtab", 3, 0, strings, len(strings), 0, 0, 1, 0),
        (".shstrtab", 3, 0, names, len(names), 0, 0, 1, 0),
        (".rela.text", 4, 0, relocation, len(relocation), 3, 1, 4, 12),
    ]:
        data.extend(bytes((-len(data)) % alignment))
        headers.append((names.index(name.encode()), kind, flags, 0, len(data), size, link, info, alignment, entry))
        data.extend(contents)
    data.extend(bytes((-len(data)) % 4))
    header_offset = len(data)
    for header in headers:
        data.extend(struct.pack(">10I", *header))
    ident = b"\x7fELF\x01\x02\x01" + bytes(9)
    data[:52] = struct.pack(">16sHHIIIIIHHHHHH", ident, 1, 20, 1, 0, 0, header_offset, 0,
                            52, 0, 0, 40, len(headers), 5)
    return bytes(data)


class TrickyObjectCompareTests(unittest.TestCase):
    def test_identical_object(self):
        result = compare_objects(snapshot(), snapshot())
        self.assertTrue(result["byte_identical"])
        for key in ("function_byte_changes", "allocated_section_changes", "named_symbol_changes", "relocation_changes"):
            self.assertEqual(result[key], {})

    def test_one_register_byte_is_not_neutral(self):
        after = snapshot(digest="after", functions={"turn": b"\x7c\x7c\x1b\x78"})
        result = compare_objects(snapshot(), after)
        self.assertFalse(result["byte_identical"])
        self.assertEqual(result["function_byte_changes"]["turn"]["changed_bytes"], 1)

    def test_missing_and_resized_functions(self):
        after = snapshot(digest="after", functions={"new": b"\0", "turn": bytes(8)})
        result = compare_objects(snapshot(functions={"gone": b"\0", "turn": bytes(4)}), after)
        self.assertEqual(result["function_byte_changes"]["turn"]["changed_bytes"], 4)
        self.assertEqual(result["function_byte_changes"]["gone"], {"missing_from": "current"})
        self.assertEqual(result["function_byte_changes"]["new"], {"missing_from": "baseline"})

    def test_zero_filled_data_does_not_hide_symbol_repacking(self):
        before = snapshot()
        symbols = dict(before.symbols, state=(".sbss", 4, 4, "STT_OBJECT", "STB_GLOBAL", "STV_DEFAULT"))
        result = compare_objects(before, replace(before, digest="after", symbols=symbols))
        self.assertEqual(result["allocated_section_changes"], {})
        self.assertIn("state", result["named_symbol_changes"])

    def test_section_alignment_and_missing_section(self):
        before = snapshot()
        result = compare_objects(before, snapshot(digest="after", sections={
            ".text": ("SHT_PROGBITS", 6, 8, 4, before.sections[".text"][-1]),
        }))
        self.assertEqual(result["allocated_section_changes"][".text"]["changed_bytes"], 0)
        self.assertEqual(result["allocated_section_changes"][".sbss"]["missing_from"], "current")
        self.assertIn("layout:", comparison_summary(result))

    def test_relocation_only_changes_are_visible(self):
        before = snapshot()
        key = ".rela.text -> .text"
        for record in ((0, 10, 4, "callee", "SHN_UNDEF", 0),
                       (0, 11, 0, "callee", "SHN_UNDEF", 0),
                       (0, 10, 0, "different", "SHN_UNDEF", 0)):
            with self.subTest(record=record):
                result = compare_objects(before, replace(before, digest="after", relocations={key: (record,)}))
                self.assertEqual(result["function_byte_changes"], {})
                self.assertEqual(result["relocation_changes"][key]["added"], [record])

    def test_duplicate_relocations_are_not_collapsed(self):
        before = snapshot()
        key = ".rela.text -> .text"
        after = replace(before, digest="after", relocations={key: before.relocations[key] * 2})
        result = compare_objects(before, after)
        self.assertEqual(len(result["relocation_changes"][key]["added"]), 1)

    def test_anonymous_renaming_is_distinguished_from_moving_its_target(self):
        key = ".rela.text -> .text"
        before = snapshot(relocations={key: ((0, 109, 0, "@42", ".sdata2", 4),)})
        for offset, count in ((4, 0), (8, 1)):
            with self.subTest(offset=offset):
                after = snapshot(digest="after", relocations={key: ((0, 109, 0, "@43", ".sdata2", offset),)})
                result = compare_objects(before, after)
                self.assertFalse(result["byte_identical"])
                self.assertEqual(result["relocation_changes"][key]["ignoring_anonymous_names"],
                                 {"removed_count": count, "added_count": count})

    def test_undefined_anonymous_symbol_names_are_still_link_identities(self):
        key = ".rela.text -> .text"
        before = snapshot(relocations={key: ((0, 10, 0, "@42", "SHN_UNDEF", 0),)})
        after = snapshot(digest="after", relocations={key: ((0, 10, 0, "@43", "SHN_UNDEF", 0),)})
        result = compare_objects(before, after)
        self.assertEqual(result["relocation_changes"][key]["ignoring_anonymous_names"]["added_count"], 1)

    def test_summary_is_bounded_but_counts_all_changes(self):
        before = snapshot(functions={})
        after = snapshot(digest="after", functions={f"function{i:02}": b"\0" for i in range(20)})
        report = comparison_summary(compare_objects(before, after))
        self.assertIn("Function byte changes: 20", report)
        self.assertIn("8 more", report)
        self.assertNotIn("function19", report)

    def test_unclassified_metadata_change_is_not_byte_identical(self):
        self.assertFalse(compare_objects(snapshot(), snapshot(digest="metadata-changed"))["byte_identical"])

    def test_read_real_elf_structure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tricky.o"
            path.write_bytes(object_fixture())
            result = read_object(path)
        self.assertEqual(result.functions, {"turn": b"\x48\x00\x00\x01"})
        self.assertEqual(result.sections[".sbss"][-1], bytes(8))
        self.assertEqual(result.symbols["state"][0:3], (".sbss", 0, 4))
        self.assertEqual(result.relocations[".rela.text -> .text"], ((0, 10, -4, "callee", "SHN_UNDEF", 0),))
        self.assertEqual(len(result.digest), 64)

    def test_executable_is_rejected(self):
        data = bytearray(object_fixture())
        struct.pack_into(">H", data, 16, 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tricky.elf"
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "relocatable object"):
                read_object(path)


if __name__ == "__main__":
    unittest.main()
