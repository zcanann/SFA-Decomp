"""Integration checks for anonymous shader color templates in built PPC objects."""

import copy
from pathlib import Path
import struct
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

from map_render_data_audit import ROOT, audit_zero_colors
from tricky_object_compare import read_object


SOURCE = ROOT / "build/GSAE01/src/main/shader.o"
RETAIL = ROOT / "build/GSAE01/obj/main/shader.o"


@unittest.skipUnless(SOURCE.is_file() and RETAIL.is_file(), "build shader.o first")
class ZeroColorAuditTests(unittest.TestCase):
    def test_anonymous_source_and_named_retail_templates(self):
        for path in (SOURCE, RETAIL):
            audit_zero_colors(read_object(path), path)

    def changed_relocation(self, change):
        snapshot = copy.deepcopy(read_object(SOURCE))
        key = ".rela.text -> .text"
        records = list(snapshot.relocations[key])
        index = next(i for i, r in enumerate(records) if r[4] == ".sbss2")
        records[index] = change(records[index])
        snapshot.relocations[key] = tuple(records)
        return snapshot

    def test_equal_zero_bytes_do_not_hide_wrong_template(self):
        snapshot = self.changed_relocation(lambda r: (*r[:5], (r[5] + 4) % 12))
        with self.assertRaisesRegex(AssertionError, "load destinations differ"):
            audit_zero_colors(snapshot, SOURCE)

    def test_correct_template_at_wrong_instruction_is_rejected(self):
        snapshot = self.changed_relocation(lambda r: (r[0] + 4, *r[1:]))
        with self.assertRaisesRegex(AssertionError, "load destinations differ"):
            audit_zero_colors(snapshot, SOURCE)

    def test_nonzero_addend_is_rejected(self):
        snapshot = self.changed_relocation(lambda r: (*r[:2], 4, *r[3:]))
        with self.assertRaisesRegex(AssertionError, "load destinations differ"):
            audit_zero_colors(snapshot, SOURCE)

    def test_additional_consumer_is_rejected(self):
        snapshot = copy.deepcopy(read_object(SOURCE))
        key = ".rela.text -> .text"
        record = next(r for r in snapshot.relocations[key] if r[4] == ".sbss2")
        snapshot.relocations[key] += (record,)
        with self.assertRaisesRegex(AssertionError, "load destinations differ"):
            audit_zero_colors(snapshot, SOURCE)

    def test_widened_template_is_rejected(self):
        with SOURCE.open("rb") as stream:
            elf = ELFFile(stream)
            table = elf.get_section_by_name(".symtab")
            section = elf.get_section_index(".sbss2")
            index = next(i for i, s in enumerate(table.iter_symbols())
                         if s["st_shndx"] == section and s["st_info"]["type"] == "STT_OBJECT")
            size_offset = table["sh_offset"] + index * table["sh_entsize"] + 8
        data = bytearray(SOURCE.read_bytes())
        struct.pack_into(">I", data, size_offset, 8)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "widened.o"
            path.write_bytes(data)
            with self.assertRaisesRegex(AssertionError, "template layout differs"):
                audit_zero_colors(read_object(path), path)


if __name__ == "__main__":
    unittest.main()
