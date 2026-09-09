import subprocess
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pool_value_sequence as pool


ASSEMBLER = pool.REPO / "build/binutils/powerpc-eabi-as.exe"
if not ASSEMBLER.is_file():
    ASSEMBLER = ASSEMBLER.with_suffix("")


@unittest.skipUnless(ASSEMBLER.is_file(), "PowerPC assembler is not installed")
class LiteralLoadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def scan(self, instructions, data, section=".sdata2", **options):
        root = Path(self.temp.name)
        source = root / "fixture.s"
        obj = root / "fixture.o"
        source.write_text(
            '.section .text,"ax",@progbits\n'
            '.global probe\n.type probe,@function\nprobe:\n'
            + instructions + '\nblr\n.size probe,.-probe\n'
            + '.section .sdata2,"a",@progbits\n' + data + '\n',
            encoding="ascii",
        )
        subprocess.run([str(ASSEMBLER), "-o", str(obj), str(source)], check=True, capture_output=True)
        return pool.sequences(obj, section, **options)[0]["probe"]

    def test_repeated_load_is_not_silently_removed(self):
        data = "value: .long 0x3f800000"
        once = self.scan("lfs 1,value@sda21(0)", data)
        twice = self.scan("lfs 1,value@sda21(0)\nlfs 2,value@sda21(0)", data)
        self.assertEqual(twice, ["3f800000", "3f800000"])
        self.assertNotEqual(once, twice)
        legacy = self.scan("lfs 1,value@sda21(0)\nlfs 2,value@sda21(0)", data,
                           collapse_repeats=True)
        self.assertEqual(legacy, once)

    def test_merged_pools_follow_instruction_order(self):
        instructions = "lfs 1,first@sda21(0)\nlfs 2,second@sda21(0)\nlfs 3,first@sda21(0)"
        split_data = ('second: .long 0x40000000\n.section .sdata,"aw",@progbits\n'
                      'first: .long 0x3f800000')
        merged = self.scan(instructions, split_data, (".sdata", ".sdata2"))
        retail = self.scan(instructions, "first: .long 0x3f800000\nsecond: .long 0x40000000")
        self.assertEqual(merged, ["3f800000", "40000000", "3f800000"])
        self.assertEqual(merged, retail)
        self.assertNotEqual(self.scan(instructions, split_data), retail)

    def test_terminal_halfword_does_not_read_padding(self):
        values = self.scan("lhz 3,types@sda21(0)", "types: .byte 0x0a,0x08")
        self.assertEqual(values, ["0a08"])

    def test_load_widths_and_relocation_addends(self):
        values = self.scan(
            "lbz 3,bytes@sda21(0)\n"
            "lha 3,bytes+2@sda21(0)\n"
            "lfs 1,bytes+4@sda21(0)\n"
            "lfd 1,bytes+8@sda21(0)",
            "bytes: .byte 0x12,0,0xfe,0xdc\n"
            ".long 0x3f800000,0x3ff00000,0x00000001",
        )
        self.assertEqual(values, ["12", "fedc", "3f800000", "3ff0000000000001"])

    def test_double_low_word_is_compared(self):
        first = self.scan("lfd 1,value@sda21(0)", "value: .long 0x3ff00000,1")
        second = self.scan("lfd 1,value@sda21(0)", "value: .long 0x3ff00000,2")
        self.assertNotEqual(first, second)

    def test_short_pool_is_unscannable(self):
        with self.assertRaisesRegex(pool.UnscannableObject, "4-byte load outside"):
            self.scan("lwz 3,value@sda21(0)", "value: .byte 0x0a,0x08")

    def test_address_reference_is_not_assumed_to_be_a_load(self):
        with self.assertRaisesRegex(pool.UnscannableObject, "non-load SDA21"):
            self.scan("addi 3,0,value@sda21", "value: .long 1")


class ConsumerComparisonTests(unittest.TestCase):
    def test_version_selects_both_object_paths(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(
            pool, "sequences", return_value=({}, [])
        ) as scan:
            pool.compare("src/main/fixture.c", (".sdata", ".sdata2"), version="GSAJ01")
        self.assertEqual([call.args[0] for call in scan.call_args_list], [
            pool.REPO / "build/GSAJ01/src/main/fixture.o",
            pool.REPO / "build/GSAJ01/obj/main/fixture.o",
        ])

    def test_extra_source_consumer_is_a_difference(self):
        ours = ({"main": ["3f800000"], "pool_anchor": ["40000000"]}, ["main", "pool_anchor"])
        retail = ({"main": ["3f800000"]}, ["main"])
        with patch.object(Path, "is_file", return_value=True), patch.object(
            pool, "sequences", side_effect=[ours, retail]
        ):
            self.assertEqual(pool.compare("src/fixture.c", ".sdata2", quiet=True), (1, 1))

    def test_missing_source_consumer_is_a_difference(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(
            pool, "sequences", side_effect=[({}, []), ({"main": ["0a08"]}, ["main"])]
        ):
            self.assertEqual(pool.compare("src/fixture.c", ".sdata2", quiet=True), (0, 1))


class CommandLineTests(unittest.TestCase):
    def test_malformed_section_selection_does_not_fall_back_to_default(self):
        for sections in ("", ".sdata,", ".sdata, .sdata2", "."):
            with self.subTest(sections=sections), patch.object(pool, "verified_dol") as verify, \
                    patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    pool.main(["src/main/fixture.c", "--sections", sections])
                self.assertEqual(error.exception.code, 2)
                verify.assert_not_called()

    def test_wrong_retail_identity_stops_before_comparison(self):
        with patch.object(pool, "verified_dol", side_effect=ValueError("Retail hash mismatch")), \
                patch.object(pool, "compare") as compare, patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                pool.main(["src/main/fixture.c", "--version", "GSAP01"])
        self.assertEqual(error.exception.code, 1)
        compare.assert_not_called()

    def test_merged_sections_and_legacy_mode_are_explicit(self):
        with patch.object(pool, "verified_dol") as verify, \
                patch.object(pool, "compare", return_value=(1, 0)) as compare, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(pool.main(["src/main/fixture.c", "-v", "GSAJ01",
                                        "--sections", ".sdata,.sdata2", "--collapse-repeats"]), 0)
        verify.assert_called_once_with(pool.REPO / "orig/GSAJ01/sys/main.dol",
                                       pool.REPO / "config/GSAJ01/config.yml")
        compare.assert_called_once_with("src/main/fixture.c", (".sdata", ".sdata2"),
                                        version="GSAJ01", collapse_repeats=True)
        self.assertIn("repeated loads collapsed", output.getvalue())

    def test_sweep_uses_selected_version_and_accounts_for_failed_row(self):
        rows = [("src/first.c", ".sdata2", 0.0, 4), ("src/last.c", ".sdata2", 0.0, 4)]
        with patch.object(pool, "verified_dol"), patch.object(pool, "sub100_sections", return_value=rows) as report, \
                patch.object(pool, "compare", side_effect=[pool.MissingObject("missing"), (1, 0)]) as compare, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(pool.main(["--all", ".sdata2", "--version", "GSAJ01"]), 1)
        report.assert_called_once_with("GSAJ01")
        self.assertEqual(compare.call_count, 2)
        self.assertIn("population 2  scanned 1  differing 0  unscanned 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
