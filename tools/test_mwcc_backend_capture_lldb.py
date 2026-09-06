from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import mwcc_backend_capture_lldb as capture


class LldbCaptureTests(unittest.TestCase):
    def test_ret_uses_four_byte_guest_stack(self):
        word, write = Mock(return_value=capture.BASE + 0x1234), Mock()
        self.assertEqual(capture.emulate_hook(capture.DUMP, 0x1000, 0, word, write),
                         (0x1004, capture.BASE + 0x1234))
        word.assert_called_once_with(0x1000)
        write.assert_not_called()

    def test_graph_push_preserves_low_guest_ebx(self):
        for address in capture.GRAPH:
            word, write = Mock(), Mock()
            self.assertEqual(capture.emulate_hook(address, 0x1000, 0x123456789A, word, write),
                             (0xFFC, address + 1))
            write.assert_called_once_with(0xFFC, 0x3456789A)
            word.assert_not_called()

    def test_invalid_hook_stack_and_return_do_not_write(self):
        for pc, sp, destination in [(capture.DUMP, 0x1000, 0), (capture.BASE, 0x1000, 0),
                                    (capture.DUMP, 0x100000000, capture.BASE),
                                    (next(iter(capture.GRAPH)), 3, 0)]:
            write = Mock()
            with self.subTest(pc=pc, sp=sp), self.assertRaises(ValueError):
                capture.emulate_hook(pc, sp, 0, lambda a: destination, write)
            write.assert_not_called()

    def test_page_cache_reads_across_boundaries_once(self):
        read = Mock(side_effect=lambda address, size: bytes([address // 4096]) * size)
        memory = capture.page_reader(read)
        self.assertEqual(memory(4094, 4), b"\0\0\1\1")
        self.assertEqual(memory(4096, 1), b"\1")
        self.assertEqual(read.call_count, 2)
        self.assertEqual(memory(0, 0), b"")

    def test_invalid_and_short_memory_reads_are_rejected(self):
        for address, size in [(-1, 1), (0, -1), (0xFFFFFFFF, 2)]:
            with self.subTest(address=address, size=size), self.assertRaisesRegex(ValueError, "outside"):
                capture.page_reader(Mock())(address, size)
        with self.assertRaisesRegex(ValueError, "short process page"):
            capture.page_reader(lambda a, n: bytes(n - 1))(0, 1)

    def test_timeout_only_kills_guest_with_this_output(self):
        for args, expected in [("wibo mwcceppc.exe -o /tmp/unique/traced", True),
                               ("wibo mwcceppc.exe -o /tmp/another/traced", False),
                               ("unrelated /tmp/unique/traced", False), ("", False)]:
            with self.subTest(args=args), tempfile.TemporaryDirectory() as directory:
                pid = Path(directory) / "pid"
                pid.write_text("4321")
                process = Mock(pid=1234)
                with patch.object(capture.subprocess, "run", return_value=SimpleNamespace(stdout=args)), \
                        patch.object(capture.os, "kill") as kill, patch.object(capture.os, "killpg") as killpg:
                    capture._stop_timed_out_capture(process, pid, ["compiler", "-o", "/tmp/unique/traced"])
                    if expected:
                        kill.assert_called_once_with(4321, signal.SIGKILL)
                    else:
                        kill.assert_not_called()
                    killpg.assert_called_once_with(1234, signal.SIGKILL)
                    process.wait.assert_called_once()

    def test_cleanup_reaps_debugger_when_pid_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            pid = Path(directory) / "pid"
            pid.write_text("4321")
            process = Mock(pid=1234)
            with patch.object(capture.subprocess, "run", side_effect=subprocess.TimeoutExpired("ps", 2)), \
                    patch.object(capture.os, "kill") as kill, patch.object(capture.os, "killpg") as killpg:
                capture._stop_timed_out_capture(process, pid, ["compiler", "-o", "/tmp/unique/traced"])
                kill.assert_not_called()
                killpg.assert_called_once_with(1234, signal.SIGKILL)
                process.wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
