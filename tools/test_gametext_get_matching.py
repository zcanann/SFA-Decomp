"""Relocate exact gametext functions at retail addresses and compare every instruction.

This validates the function and its actual data destinations. The containing
code TU still has other nonmatching functions and is not a complete source link.
"""

from pathlib import Path
import re
import struct
import unittest

from tricky_object_compare import read_object
from version_progress import load_splits, read_dol_range, retail_sda_base, verified_dol


ROOT = Path(__file__).resolve().parents[1]


class GameTextGetMatchingTests(unittest.TestCase):
    def test_relocated_function_matches_retail(self):
        self.assert_relocated_function("gameTextGet", 0x294)

    def test_relocated_runner_matches_retail(self):
        self.assert_relocated_function("gameTextRun", 0x5E0)

    def assert_relocated_function(self, function, expected_size):
        config = ROOT / "config/GSAE01"
        dol_path = ROOT / "orig/GSAE01/sys/main.dol"
        object_path = ROOT / "build/GSAE01/src/main/gametext.o"
        if not dol_path.is_file() or not object_path.is_file():
            self.skipTest("build the EN gametext object first")
        dol = verified_dol(dol_path, config / "config.yml")
        obj = read_object(object_path)
        symbols = {
            name: (section, int(address, 16))
            for name, section, address in re.findall(
                r"^(\S+) = \.(\w+):0x([0-9A-Fa-f]+);", (config / "symbols.txt").read_text(), re.M)
        }
        _, splits = load_splits(config / "splits.txt")
        bases = {"." + span.section: span.start for span in splits if span.unit == "main/gametext.c"}
        sda = {"sdata": (13, retail_sda_base(dol, 13)),
               "sbss": (13, retail_sda_base(dol, 13)),
               "sdata2": (2, retail_sda_base(dol, 2))}
        _, offset, size, *_ = obj.symbols[function]
        address = symbols[function][1]
        image = bytearray(obj.functions[function])
        self.assertEqual(size, expected_size)
        count = 0
        for relative, kind, addend, name, section, value in obj.relocations[".rela.text -> .text"]:
            if not offset <= relative < offset + size:
                continue
            count += 1
            position = relative - offset
            # Each named callee uses its retail address: other functions in this
            # nonmatching TU can still have different compiled sizes.
            if section == "SHN_UNDEF" or (section == ".text" and name in symbols):
                destination_section, destination = symbols[name]
            else:
                destination_section = section.removeprefix(".")
                destination = bases[section] + value
            destination += addend
            if kind == 4:  # R_PPC_ADDR16_LO
                struct.pack_into(">H", image, position, destination & 0xFFFF)
            elif kind == 6:  # R_PPC_ADDR16_HA
                struct.pack_into(">H", image, position, ((destination + 0x8000) >> 16) & 0xFFFF)
            elif kind == 10:  # R_PPC_REL24
                displacement = destination - (address + position)
                self.assertEqual(displacement & 3, 0)
                self.assertTrue(-0x2000000 <= displacement < 0x2000000)
                word = struct.unpack_from(">I", image, position)[0]
                struct.pack_into(">I", image, position, (word & 0xFC000003) | (displacement & 0x3FFFFFC))
            elif kind == 109:  # R_PPC_EMB_SDA21
                register, base = sda[destination_section]
                displacement = destination - base
                self.assertTrue(-0x8000 <= displacement < 0x8000)
                word = struct.unpack_from(">I", image, position)[0]
                struct.pack_into(">I", image, position,
                                 (word & 0xFFE00000) | (register << 16) | (displacement & 0xFFFF))
            else:
                self.fail(f"unsupported relocation {kind} to {name}")
        self.assertGreater(count, 0)
        self.assertEqual(bytes(image), read_dol_range(dol, address, size))


if __name__ == "__main__":
    unittest.main()
