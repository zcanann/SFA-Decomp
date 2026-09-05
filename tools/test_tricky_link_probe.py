import unittest

from tricky_link_probe import link_inputs, replace_object


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


if __name__ == "__main__":
    unittest.main()
