import os
import subprocess
import unittest
from unittest.mock import patch

from compiler_command import split_command_line


class CommandLineTests(unittest.TestCase):
    def test_empty_command(self):
        self.assertEqual(split_command_line(""), [])
        self.assertEqual(split_command_line(" \t\n"), [])

    def test_nul_is_rejected(self):
        with self.assertRaises(ValueError):
            split_command_line("mwcc\0-c hidden.c")

    def test_posix_quoting(self):
        with patch("compiler_command.os.name", "posix"):
            self.assertEqual(
                split_command_line("wine 'build tools/mwcc.exe' -pragma 'cats off' -DNAME='a\\b'"),
                ["wine", "build tools/mwcc.exe", "-pragma", "cats off", "-DNAME=a\\b"],
            )

    def test_posix_unclosed_quote_is_rejected(self):
        with patch("compiler_command.os.name", "posix"):
            with self.assertRaises(ValueError):
                split_command_line('mwcc "unfinished')

    @unittest.skipUnless(os.name == "nt", "Windows argument parser")
    def test_windows_ninja_paths_and_pragma(self):
        self.assertEqual(
            split_command_line(
                r'build\tools\sjiswrap.exe build\compilers\GC\1.3\mwcceppc.exe '
                r'-pragma "cats off" -c src\dlls\objects\196_Tricky\tricky.c'
            ),
            [r"build\tools\sjiswrap.exe", r"build\compilers\GC\1.3\mwcceppc.exe",
             "-pragma", "cats off", "-c", r"src\dlls\objects\196_Tricky\tricky.c"],
        )

    @unittest.skipUnless(os.name == "nt", "Windows argument parser")
    def test_windows_round_trip_literal_arguments(self):
        arguments = [
            r"C:\compiler tools\mwcc.exe", "-pragma", "cats off",
            '-DNAME="quoted value"', r"-DPATH=a\b", "",
            "C:\\output folder\\", "literal\\\"quote",
        ]
        self.assertEqual(split_command_line(subprocess.list2cmdline(arguments)), arguments)

    @unittest.skipUnless(os.name == "nt", "Windows argument parser")
    def test_windows_extra_flags(self):
        self.assertEqual(split_command_line('  -opt propagation -pragma "cats off"  '),
                         ["-opt", "propagation", "-pragma", "cats off"])


if __name__ == "__main__":
    unittest.main()
