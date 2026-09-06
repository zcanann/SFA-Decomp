import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import tricky_compiler_probe as probe


class CompilerProbeTests(unittest.TestCase):
    def setUp(self):
        self.base = [
            "launcher", "build/compilers/GC/1.3/mwcceppc.exe", "-O4,p", "-inline", "deferred",
            "-opt", "nopeephole,noschedule", "-MMD", "-c", "src/tricky.c", "-o", "build/production",
        ]

    def test_scratch_command_preserves_flags_and_does_not_mutate_base(self):
        original = self.base.copy()
        command = probe.compile_command(
            self.base, Path("compiler with spaces/mwcceppc.exe"), Path("src/tricky.c"),
            Path("scratch with spaces"), "current",
        )
        self.assertEqual(self.base, original)
        self.assertEqual(command[0], "launcher")
        self.assertEqual(command[1], str(Path("compiler with spaces/mwcceppc.exe")))
        self.assertNotIn("-MMD", command)
        self.assertEqual(command[command.index("-c") + 1], str(Path("src/tricky.c")))
        self.assertEqual(command[command.index("-o") + 1], str(Path("scratch with spaces")))
        self.assertEqual(command[2:7], original[2:7])

    def test_propagation_override_is_explicit(self):
        for mode, flag in (("on", "propagation"), ("off", "nopropagation")):
            with self.subTest(mode=mode):
                command = probe.compile_command(self.base, "cc/mwcceppc.exe", "test.c", "scratch", mode)
                self.assertEqual(command[-2:], ["-opt", flag])
                self.assertIn("nopeephole,noschedule", command)

    def test_report_uses_candidate_object_and_counts_differences_separately(self):
        output = io.StringIO()
        rows = [(" ", 0, 0), ("r", 1, 1), ("M", 2, 2), ("-", 3, None), ("+", None, 3)]
        with patch.object(probe.flag_probe, "score", return_value=((75.0, {"exact": 100.0, "probe": 50.0}), None)) as score:
            with patch.object(probe.strucdiff, "analyse", return_value=(rows, [], [], 4, 4)) as analyse:
                with contextlib.redirect_stdout(output):
                    probe.report_tu(Path("scratch/tricky.o"), ["probe"])
        score.assert_called_once_with(probe.UNIT, str(Path("scratch/tricky.o")))
        analyse.assert_called_once_with(probe.UNIT, "probe", str(Path("scratch/tricky.o")))
        self.assertIn("1/2 functions exact", output.getvalue())
        self.assertIn("STRUC 3; recolour 1", output.getvalue())
        self.assertIn("do not establish data", output.getvalue())

    def test_failed_score_is_not_reported_as_a_match(self):
        with patch.object(probe.flag_probe, "score", return_value=(None, "objdiff failed")):
            with self.assertRaisesRegex(RuntimeError, "objdiff failed"):
                probe.report_tu(Path("scratch/tricky.o"), ["probe"])

    def test_missing_function_is_not_reported_as_exact(self):
        with patch.object(probe.flag_probe, "score", return_value=((100.0, {"exact": 100.0}), None)):
            with patch.object(probe.strucdiff, "analyse", return_value=([], [], [], 0, 0)):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "absent from both"):
                        probe.report_tu(Path("scratch/tricky.o"), ["missing"])

    def test_whole_tu_options_rejected_in_fixture_mode(self):
        for option in (["--link"], ["--functions", "moveTricky"]):
            with self.subTest(option=option):
                with patch.object(probe.sys, "argv", ["probe", *option]):
                    with patch.object(probe.flag_probe, "base_cmd") as base_cmd:
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as error:
                                probe.main()
                        self.assertEqual(error.exception.code, 2)
                        base_cmd.assert_not_called()

    def test_whole_tu_links_scratch_object_without_writing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler = root / "build/compilers/GC/1.3/mwcceppc.exe"
            compiler.parent.mkdir(parents=True)
            compiler.touch()
            source = root / "src/dlls/objects/196_Tricky/tricky.c"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"original source\n")
            scratch = root / "scratch"
            candidate = scratch / "tricky_compiler_whole_1.3_current/tricky.o"
            with patch.multiple(probe.flag_probe, ROOT=str(root), SCRATCH=str(scratch)):
                with (
                    patch.object(probe.flag_probe, "base_cmd", return_value="unused"),
                    patch.object(probe, "split_command_line", return_value=self.base),
                    patch.object(probe, "report_tu") as report,
                    patch.object(probe.subprocess, "run") as run,
                    patch.object(probe.sys, "argv", ["probe", "--whole-tu", "--link", "--versions", "1.3"]),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    run.return_value.stdout = ""
                    probe.main()
                    self.assertEqual(run.call_count, 2)
                    calls = run.call_args_list.copy()
                    report.assert_called_once_with(candidate, probe.RESIDUAL_FUNCTIONS)
                    report.reset_mock()
                    run.reset_mock()
                    run.return_value.stdout = "Unknown option -test"
                    with self.assertRaisesRegex(RuntimeError, "ignored a requested compiler option"):
                        probe.main()
                    report.assert_not_called()
                    self.assertEqual(run.call_count, 1)
            compile_args = calls[0].args[0]
            link_args = calls[1].args[0]
            self.assertEqual(compile_args[compile_args.index("-c") + 1], str(source))
            self.assertEqual(compile_args[compile_args.index("-o") + 1], str(candidate.parent))
            self.assertEqual(link_args[link_args.index("--object") + 1], str(candidate))
            self.assertEqual(link_args[link_args.index("--output") + 1], str(candidate.parent / "link"))
            self.assertEqual(source.read_bytes(), b"original source\n")
            self.assertFalse(source.with_suffix(".o").exists())


if __name__ == "__main__":
    unittest.main()
