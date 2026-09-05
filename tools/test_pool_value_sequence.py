import subprocess
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

    def scan(self, instructions, data):
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
        return pool.sequences(obj, ".sdata2")[0]["probe"]

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


if __name__ == "__main__":
    unittest.main()
