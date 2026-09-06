import unittest

from tricky_link_probe import link_inputs, replace_object, section_differences


class LinkInputsTests(unittest.TestCase):
    def test_explicit_inputs_only(self):
        query = """build/game.elf:
  input: link
    build\\first.o
    build/second.a
    | script.lcf
    || linker.exe
  outputs:
    build/game.dol
"""
        self.assertEqual(link_inputs(query), ["build/first.o", "build/second.a"])

    def test_missing_inputs_rejected(self):
        with self.assertRaises(ValueError):
            link_inputs("build/game.elf:\n  outputs:\n    game.dol\n")

    def test_replacement_preserves_order_and_input(self):
        inputs = ["a.o", "b.o", "c.o"]
        self.assertEqual(replace_object(inputs, "b.o", "new.o"), ["a.o", "new.o", "c.o"])
        self.assertEqual(inputs, ["a.o", "b.o", "c.o"])

    def test_ambiguous_replacement_rejected(self):
        for inputs in [["a.o"], ["b.o", "b.o"]]:
            with self.assertRaises(ValueError):
                replace_object(inputs, "b.o", "new.o")


class SectionDifferencesTests(unittest.TestCase):
    def test_identical_sections(self):
        sections = {".text": (0x80000000, b"code"), ".data": (0x80001000, b"data")}
        self.assertEqual(section_differences(sections, dict(sections)), {})

    def test_same_size_byte_changes(self):
        result = section_differences({".text": (0x1000, b"abcd")}, {".text": (0x1000, b"axcy")})
        self.assertEqual(result[".text"]["changed_bytes"], 2)
        self.assertEqual(result[".text"]["baseline_size"], 4)
        self.assertEqual(result[".text"]["linked_size"], 4)

    def test_alignment_bytes_are_not_ignored(self):
        for before, after in [(b"a", b"a\0\0"), (b"a\0\0", b"a")]:
            result = section_differences({".data": (0x1000, before)}, {".data": (0x1000, after)})
            self.assertEqual(result[".data"]["changed_bytes"], 2)
            self.assertEqual(result[".data"]["baseline_size"], len(before))
            self.assertEqual(result[".data"]["linked_size"], len(after))

    def test_address_change_with_identical_bytes(self):
        result = section_differences({".data": (0x1000, b"a")}, {".data": (0x2000, b"a")})
        self.assertEqual(result[".data"]["changed_bytes"], 0)
        self.assertEqual(result[".data"]["baseline_address"], "0x1000")
        self.assertEqual(result[".data"]["linked_address"], "0x2000")

    def test_missing_and_extra_sections(self):
        result = section_differences({".data": (0x1000, b"a")}, {".rodata": (0x1000, b"a")})
        self.assertEqual(result, {
            ".data": {"missing_from": "linked"}, ".rodata": {"missing_from": "baseline"},
        })


if __name__ == "__main__":
    unittest.main()
