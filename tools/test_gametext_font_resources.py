"""Check compiled built-in font resources against the retail EN DOL.

Build `ninja all_source` first. These tests validate resource bytes, relocated
pointers, layout, and character coverage, not execution of the atlas renderer.
"""
from pathlib import Path
import struct
import unittest

from orig.dol_xrefs import DolFile
from tricky_object_compare import read_object


ROOT = Path(__file__).resolve().parents[1]
BASES = {".data": 0x802C6E98, ".sdata": 0x803DB2B0}
RESOURCES = {
    "sJpDiscStatusGlyphs": (0x802C8F40, 85 * 16),
    "sJpDiscLoadingMessage": (0x802C981C, 16),
    "sJpDiscStatusMessageTable": (0x802C982C, 7 * 12),
    "sDiscStatusGlyphs": (0x802C9880, 43 * 16),
    "sDiscLoadingMessage": (0x802C9D58, 11),
    "sDiscStatusMessageTable": (0x802C9D64, 7 * 12),
}


class GameTextFontResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dol_path = ROOT / "orig/GSAE01/sys/main.dol"
        object_path = ROOT / "build/GSAE01/src/main/gametext.o"
        data_path = ROOT / "build/GSAE01/src/main/gametext_data.o"
        if not all(path.exists() for path in (dol_path, object_path, data_path)):
            raise unittest.SkipTest("retail EN DOL and both built gametext objects are required")
        cls.dol = DolFile(dol_path)
        cls.obj = read_object(object_path)
        data_obj = read_object(data_path)
        objects = ((data_obj, BASES), (cls.obj, {".data": 0x802C8F40}))
        cls.images = {
            ".data": bytearray(data_obj.sections[".data"][4] + cls.obj.sections[".data"][4]),
            ".sdata": bytearray(data_obj.sections[".sdata"][4]),
        }
        cls.locations = {
            name: (bases[section] + offset, size)
            for obj, bases in objects
            for name, (section, offset, size, *_) in obj.symbols.items()
            if section in bases and not name.startswith(".")
        }
        for obj, bases in objects:
            for key, relocations in obj.relocations.items():
                section = key.split(" -> ", 1)[1]
                if section not in bases:
                    continue
                for offset, kind, addend, name, destination, value in relocations:
                    if destination == ".text":
                        continue
                    if kind != 1:
                        raise ValueError(f"unsupported resource relocation: {key}, {name}, {kind}")
                    if destination == "SHN_UNDEF":
                        address = cls.locations[name][0] + addend
                    else:
                        address = bases[destination] + value + addend
                    output_offset = bases[section] - BASES[section] + offset
                    struct.pack_into(">I", cls.images[section], output_offset, address)

    def retail_read(self, address, size):
        section = next(section for section in self.dol.sections
                       if section.address <= address and address + size <= section.address + section.size)
        offset = section.offset + address - section.address
        return self.dol.data[offset:offset + size]

    def source_read(self, address, size):
        section = next(name for name, base in BASES.items()
                       if base <= address and address + size <= base + len(self.images[name]))
        offset = address - BASES[section]
        return bytes(self.images[section][offset:offset + size])

    def read_string(self, read, address):
        text = bytearray()
        for offset in range(1024):
            value = read(address + offset, 1)
            if value == b"\0":
                return text.decode("utf-8")
            text.extend(value)
        self.fail(f"unterminated resource string at {address:08X}")

    def test_native_layout_and_relocated_bytes(self):
        for name, (address, size) in RESOURCES.items():
            with self.subTest(resource=name):
                self.assertEqual(self.locations[name], (address, size))
                self.assertEqual(self.source_read(address, size), self.retail_read(address, size))

    def test_each_font_covers_exactly_its_localized_messages(self):
        for prefix, language, glyph_count in (("Jp", 4, 85), ("", 0, 43)):
            with self.subTest(language=language):
                glyph_address, glyph_size = RESOURCES[f"s{prefix}DiscStatusGlyphs"]
                message_address, _ = RESOURCES[f"s{prefix}DiscStatusMessageTable"]
                glyphs = list(struct.iter_unpack(">IHHbbbbBBBB", self.source_read(glyph_address, glyph_size)))
                keys = [glyph[0] for glyph in glyphs]
                self.assertEqual(len(set(keys)), glyph_count)
                characters = {}
                for index, identifier in enumerate((0x339, 0x33A, 0x33B, 0x33C, 0x33D, 0x33E, 0x565)):
                    record = self.source_read(message_address + index * 12, 12)
                    entry_id, count, _, _, _, entry_language, strings = struct.unpack(">HHBBBBI", record)
                    self.assertEqual((entry_id, entry_language), (identifier, language))
                    for line in range(count):
                        pointer = struct.unpack(">I", self.source_read(strings + line * 4, 4))[0]
                        text = self.read_string(self.source_read, pointer)
                        self.assertEqual(text, self.read_string(self.retail_read, pointer))
                        for character in text:
                            characters.setdefault(ord(character), None)
                self.assertEqual(keys, list(characters))

    def test_loading_messages_have_native_string_extents(self):
        for name in ("sJpDiscLoadingMessage", "sDiscLoadingMessage"):
            address, size = RESOURCES[name]
            data = self.source_read(address, size)
            self.assertEqual(data[-1:], b"\0")
            self.assertNotIn(0, data[:-1])

    def test_parser_and_path_literal_positions(self):
        # These literals are interleaved with compiler-generated jump tables.
        # Verify their complete retail spans without requiring named C arrays.
        for address, size in ((0x802C9E04, 108), (0x802C9E70, 20), (0x802C9EC4, 29)):
            with self.subTest(address=f"{address:08X}"):
                self.assertEqual(self.source_read(address, size), self.retail_read(address, size))


if __name__ == "__main__":
    unittest.main()
