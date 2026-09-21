import unittest

from asmlift_sfa import candidate_command


class CandidateCommandTests(unittest.TestCase):
    def test_preserves_profile_and_redirects_scratch_outputs(self):
        command = (
            'build/tools/wibo build/tools/sjiswrap.exe '
            'build/compilers/GC/1.3/mwcceppc.exe -O4,p -pragma "cats off" '
            '-opt nopeephole,noschedule -i include -lang=c -MMD '
            '-c src/main/pad.c -o build/GSAE01/src/main && '
            'python3 tools/transform_dep.py build/GSAE01/src/main/pad.d '
            'build/GSAE01/src/main/pad.d'
        )
        self.assertEqual(candidate_command(command, "src/main/pad.c"), [
            "build/tools/wibo", "build/tools/sjiswrap.exe",
            "build/compilers/GC/1.3/mwcceppc.exe", "-O4,p", "-pragma", "cats off",
            "-opt", "nopeephole,noschedule", "-i", "include", "-lang=c",
            "-c", "{input}", "-o", "{output}",
        ])

    def test_sdk_compiler_is_not_migrated(self):
        argv = candidate_command(
            'wibo "build/compilers/GC/1.2.5n/mwcceppc.exe" -O4,p '
            '-c src/dolphin/test.c -o build/sdk', "src/dolphin/test.c")
        self.assertIn("build/compilers/GC/1.2.5n/mwcceppc.exe", argv)

    def test_prodg_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ProDG"):
            candidate_command("prodg -c src/main/zlb.c -o build/zlb.o", "src/main/zlb.c")

    def test_unknown_shell_tail_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "post-compile"):
            candidate_command("mwcceppc.exe -c a.c -o a.o && touch shared", "a.c")

    def test_wrong_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unexpected compiler source"):
            candidate_command("mwcceppc.exe -c a.c -o a.o", "b.c")


if __name__ == "__main__":
    unittest.main()
