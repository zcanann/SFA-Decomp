"""Exercise source recovery with and without optional debug references."""

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.orig.source_recovery import collect_candidates, parse_debug_split_text_ranges


class SourceWorklistTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.dol = self.directory / "main.dol"
        self.symbols = self.directory / "symbols.txt"
        self.splits = self.directory / "splits.txt"
        self.debug_symbols = self.directory / "debug-symbols.txt"
        self.debug_splits = self.directory / "debug-splits.txt"
        self.debug_srcfiles = self.directory / "debug-srcfiles.txt"

        # lis r3,0x8000; addi r3,r3,0x2000; blr references the source tag.
        code = struct.pack(">III", 0x3C608000, 0x38632000, 0x4E800020)
        message = b"example.c: missing frame\0"
        header = bytearray(0x100)
        for index, offset, address, size in (
            (0, 0x100, 0x80001000, len(code)),
            (7, 0x120, 0x80002000, len(message)),
        ):
            struct.pack_into(">I", header, index * 4, offset)
            struct.pack_into(">I", header, 0x48 + index * 4, address)
            struct.pack_into(">I", header, 0x90 + index * 4, size)
        self.dol.write_bytes(header + code + bytes(0x20 - len(code)) + message)
        self.symbols.write_text(
            "exampleInit = .text:0x80001000; // type:function size:0xC\n"
        )
        self.splits.write_text(
            "main/example.c:\n\t.text start:0x80001000 end:0x8000100C\n"
        )

    def candidates(self):
        return collect_candidates(
            self.dol, self.symbols, self.debug_symbols,
            self.debug_splits, self.debug_srcfiles,
        )

    def test_missing_debug_keeps_retail_xref(self):
        candidates = self.candidates()
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.retail_source_name, "example.c")
        self.assertEqual(candidate.retail_address, 0x80002000)
        self.assertEqual(len(candidate.xrefs), 1)
        self.assertEqual(candidate.xrefs[0].function_name, "exampleInit")
        self.assertEqual(candidate.debug_sources, ())
        self.assertEqual(candidate.debug_symbol_hits, ())
        self.assertFalse(candidate.listed_in_debug_srcfiles)

    def test_present_debug_still_enriches_retail(self):
        self.debug_symbols.write_text(
            "exampleDebugInit = .text:0x81001000; // type:function size:0x10\n"
        )
        self.debug_splits.write_text(
            "example.c:\n\t.text start:0x81001000 end:0x81001010\n"
            "data_only.c:\n\t.data start:0x81002000 end:0x81002004\n"
            "next.c:\n\t.text start:0x81001010 end:0x81001020\n"
        )
        self.debug_srcfiles.write_text("example.c\nnext.c\n")
        self.assertEqual(parse_debug_split_text_ranges(self.debug_splits), {
            "example.c": (0x81001000, 0x81001010),
            "next.c": (0x81001010, 0x81001020),
        })
        candidate = self.candidates()[0]
        self.assertTrue(candidate.listed_in_debug_srcfiles)
        self.assertEqual(len(candidate.debug_sources), 1)
        self.assertEqual(candidate.debug_sources[0].path, "example.c")
        self.assertEqual(candidate.debug_sources[0].functions[0].name, "exampleDebugInit")
        self.assertEqual(candidate.xrefs[0].function_start, 0x80001000)

    def test_cli_json_reports_missing_context_separately(self):
        result = subprocess.run([
            sys.executable, str(ROOT / "tools/orig/source_worklist.py"),
            "--dol", str(self.dol), "--symbols", str(self.symbols),
            "--splits", str(self.splits), "--format", "json",
            "--debug-symbols", str(self.debug_symbols),
            "--debug-splits", str(self.debug_splits),
            "--debug-srcfiles", str(self.debug_srcfiles),
        ], cwd=self.directory, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["retail_source_name"], "example.c")
        self.assertEqual(rows[0]["xref_functions"], ["exampleInit@0x80001000-0x8000100C"])
        self.assertIsNone(rows[0]["debug_target_size"])
        self.assertEqual(rows[0]["debug_prev_paths"], [])
        self.assertEqual(rows[0]["debug_next_paths"], [])
        self.assertIn("Optional debug inputs unavailable", result.stderr)
        self.assertIn(str(self.debug_splits), result.stderr)


if __name__ == "__main__":
    unittest.main()
