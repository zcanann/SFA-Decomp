"""Patch integrity/ISO extent tests using retail DOL + synthetic disc metadata."""
import copy
from pathlib import Path
import struct
import tempfile
import unittest

from build import (ROOT, PAYLOAD_ADDRESS, BOOT_LOAD_LIMIT, apply_dol, branch, compile_payload, digest,
                   find_disc_space, make_patch, sections, u32, write_iso, write_dol, validate_boot_layout)


class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dol = (ROOT / "orig/GSAE01/sys/main.dol").read_bytes()
        cls.payload, cls.exports = compile_payload(ROOT / "build/practice", True)
        cls.manifest = make_patch(cls.dol, cls.payload, cls.exports)

    def test_disabled_has_no_code(self):
        self.assertEqual(compile_payload(ROOT / "build/practice", False), (b"", {}))

    def test_original_sections_addresses_and_bytes(self):
        patched = apply_dol(self.dol, self.manifest, self.payload)
        self.assertEqual(sections(patched)[:2], sections(self.dol)[:2])
        for section in sections(self.dol):
            self.assertIn(section, sections(patched))
        original_part = bytearray(patched[:len(self.dol)])
        for edit in self.manifest["edits"]:
            original_part[edit["offset"]:edit["offset"] + 4] = bytes.fromhex(edit["before"])
        self.assertEqual(original_part, self.dol)
        self.assertEqual(len([e for e in self.manifest["edits"] if "hook" in e]), 7)

    def test_reject_previous_apploader_boundary_regression(self):
        patched = bytearray(apply_dol(self.dol, self.manifest, self.payload))
        self.assertLessEqual(max(a + s for _, _, a, s in sections(patched)), BOOT_LOAD_LIMIT)
        struct.pack_into(">I", patched, 0x48 + 2 * 4, 0x816C0000)
        with self.assertRaisesRegex(ValueError, "apploader"):
            validate_boot_layout(patched)

    def test_reject_changed_inputs(self):
        bad = bytearray(self.dol)
        bad[-1] ^= 1
        with self.assertRaises(ValueError):
            apply_dol(bytes(bad), self.manifest, self.payload)
        with self.assertRaises(ValueError):
            apply_dol(self.dol, self.manifest, self.payload + b"x")
        bad_manifest = copy.deepcopy(self.manifest)
        bad_manifest["edits"][0]["before"] = "00000000"
        with self.assertRaises(ValueError):
            apply_dol(self.dol, bad_manifest, self.payload)

    def test_branch_bounds_and_disc_space(self):
        self.assertEqual(branch(0x80000000, 0x80000004), bytes.fromhex("48000005"))
        with self.assertRaises(ValueError):
            branch(0x80000000, 0x84000000)
        with self.assertRaises(ValueError):
            find_disc_space([(0, 0x10000)], 32, 0x10000)

    def test_iso_roundtrip_and_original_protection(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/practice") as tmp:
            iso, output = Path(tmp) / "clean.iso", Path(tmp) / "practice.iso"
            data = bytearray(16 << 20)
            data[:8] = b"GSAE01\0\0"
            struct.pack_into(">I", data, 0x1C, 0xC2339F3D)
            struct.pack_into(">4I", data, 0x420, 0x3000, 0x400000, 32, 32)
            data[0x3000:0x3000 + len(self.dol)] = self.dol
            struct.pack_into(">6I", data, 0x400000, 0x01000000, 0, 2, 0, 0x480000, 16)
            data[0x480000:0x480010] = bytes(range(16))
            iso.write_bytes(data)
            manifest = self.manifest
            report = write_iso(iso, output, manifest, self.payload)
            result = output.read_bytes()
            self.assertEqual(iso.read_bytes(), data)
            self.assertEqual(result[0x480000:0x480010], bytes(range(16)))
            start = u32(result, 0x420)
            expected = apply_dol(self.dol, manifest, self.payload)
            self.assertEqual(result[start:start + len(expected)], expected)
            self.assertTrue(report["all_other_bytes_identical"])
            self.assertFalse(report["dol_relocated"])
            self.assertEqual(start, 0x3000)
            with self.assertRaises(ValueError):
                write_iso(iso, iso, manifest, self.payload)
            with self.assertRaises(ValueError):
                write_iso(iso, output, manifest, self.payload)

    def test_relocates_only_when_the_existing_extent_is_too_small(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/practice") as tmp:
            iso, output = Path(tmp) / "packed.iso", Path(tmp) / "practice.iso"
            data = bytearray(16 << 20)
            data[:8] = b"GSAE01\0\0"
            struct.pack_into(">I", data, 0x1C, 0xC2339F3D)
            fst = 0x3000 + len(self.dol) + 32
            struct.pack_into(">4I", data, 0x420, 0x3000, fst, 32, 32)
            data[0x3000:0x3000 + len(self.dol)] = self.dol
            struct.pack_into(">6I", data, fst, 0x01000000, 0, 2, 0, 0x480000, 16)
            iso.write_bytes(data)
            report = write_iso(iso, output, self.manifest, self.payload)
            result = output.read_bytes()
            self.assertTrue(report["dol_relocated"])
            self.assertEqual(result[fst:fst + 32], data[fst:fst + 32])
            self.assertEqual(result[0x3000:0x3000 + len(self.dol)], self.dol)

    def test_dol_only_adapter(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/practice") as tmp:
            output = Path(tmp) / "main.dol"
            write_dol(self.dol, output, self.manifest, self.payload)
            self.assertEqual(output.read_bytes(), apply_dol(self.dol, self.manifest, self.payload))
            with self.assertRaises(FileExistsError):
                write_dol(self.dol, output, self.manifest, self.payload)


if __name__ == "__main__":
    unittest.main()
