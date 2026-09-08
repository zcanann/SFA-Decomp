from pathlib import Path
import os
import select
import shutil
import signal
import subprocess
import sys
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

    def test_timeout_stops_descendant_debugserver_before_debugger_without_guest_pid(self):
        snapshot = """1234 1 /usr/bin/lldb
2200 1234 /usr/bin/helper
2201 2200 /Library/Apple/usr/libexec/oah/debugserver
2202 1234 /tmp/unrelated-child
3300 1 /Library/Apple/usr/libexec/oah/debugserver
"""
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            process = Mock(pid=1234)
            with patch.object(capture.subprocess, "run", side_effect=[
                    SimpleNamespace(stdout=snapshot),
                    SimpleNamespace(stdout="2200 /Library/Apple/usr/libexec/oah/debugserver\n")]), \
                    patch.object(capture.os, "kill", side_effect=lambda *args: calls.append(("pid", *args))), \
                    patch.object(capture.os, "killpg", side_effect=lambda *args: calls.append(("group", *args))):
                capture._stop_timed_out_capture(process, Path(directory) / "missing.pid",
                                                ["compiler", "-o", "/tmp/unique/traced"])
            self.assertEqual(calls, [("pid", 2201, signal.SIGKILL), ("group", 1234, signal.SIGKILL)])
            process.wait.assert_called_once()

    def test_debugserver_cleanup_rejects_changed_process_identity(self):
        for current in ["", "1 /usr/libexec/debugserver\n", "1234 /tmp/another-program\n"]:
            with self.subTest(current=current), \
                    patch.object(capture.subprocess, "run", side_effect=[
                        SimpleNamespace(stdout="2201 1234 /usr/libexec/debugserver\n"),
                        SimpleNamespace(stdout=current)]), \
                    patch.object(capture.os, "kill") as kill:
                capture._stop_capture_debugservers(1234)
                kill.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "native macOS process-tree integration")
    def test_live_separate_session_debugserver_is_reaped(self):
        with tempfile.TemporaryDirectory(prefix="sfa-debugserver-cleanup-") as directory:
            executable = Path(directory) / "debugserver"
            shutil.copyfile("/bin/sleep", executable)
            executable.chmod(0o755)
            script = ("import subprocess,sys; "
                      "p=subprocess.Popen([sys.argv[1],'10'],start_new_session=True); "
                      "print(p.pid,flush=True); p.wait()")
            process = subprocess.Popen([sys.executable, "-c", script, str(executable)],
                                       stdout=subprocess.PIPE, text=True, start_new_session=True)
            try:
                self.assertTrue(select.select([process.stdout], [], [], 3)[0], "child did not start")
                self.assertGreater(int(process.stdout.readline()), 1)
                capture._stop_capture_debugservers(process.pid)
                self.assertEqual(process.wait(timeout=3), 0)
            finally:
                if process.poll() is None:
                    capture._stop_capture_debugservers(process.pid)
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
