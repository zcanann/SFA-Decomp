from pathlib import Path
import struct
import sys
import tempfile
import unittest

import mwcc_backend_capture_gdb as capture


def pe_image(base, entry, signature=b"PE\0\0"):
    dos = bytearray(0x40)
    struct.pack_into("<I", dos, 0x3C, 0x40)
    optional = bytearray(0x60)
    struct.pack_into("<I", optional, 16, entry)
    struct.pack_into("<I", optional, 28, base)
    return bytes(dos) + signature + bytes(20) + bytes(optional)


class GdbCaptureTests(unittest.TestCase):
    def test_entry_point_is_image_base_plus_rva(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "mwcceppc.exe"
            path.write_bytes(pe_image(capture.BASE, 0x1000))
            self.assertEqual(capture.pe_entry_point(path), capture.BASE + 0x1000)

    def test_rejects_non_pe_and_relocated_images(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "mwcceppc.exe"
            path.write_bytes(pe_image(capture.BASE, 0x1000, signature=b"NE\0\0"))
            with self.assertRaises(ValueError):
                capture.pe_entry_point(path)
            path.write_bytes(pe_image(0x10000000, 0x1000))
            with self.assertRaises(ValueError):
                capture.pe_entry_point(path)

    def test_hook_addresses_match_the_lldb_provider(self):
        self.assertEqual(capture.DUMP, capture.BASE + 0xFF2D0)
        self.assertEqual(set(capture.GRAPH), {capture.BASE + 0x107070, capture.BASE + 0x106E20})

    def test_capture_refuses_other_platforms(self):
        if sys.platform.startswith("linux"):
            self.skipTest("provider is native here")
        with self.assertRaises(RuntimeError):
            capture.capture(["build/compilers/GC/1.3/mwcceppc.exe"], ".", {"f"})


if __name__ == "__main__":
    unittest.main()
