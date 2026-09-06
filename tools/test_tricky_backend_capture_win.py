"""Mock debugger ownership/error paths; no compiler or child process is launched."""

from collections import Counter
from contextlib import ExitStack
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform == "win32" and sys.maxsize > 2**32, "requires 64-bit Windows ctypes")
class BackendCaptureWindowsTests(unittest.TestCase):
    def exercise(self, fail_exit_once=False, timeout=60, persistent_failure=False):
        import tricky_backend_capture_win as win

        created = win.Event(code=3, pid=20, tid=10)
        created.info.create.file = 11
        created.info.create.process = 21
        created.info.create.thread = 22
        created.info.create.base = 0x400000
        thread = win.Event(code=2, pid=20, tid=30)
        thread.info.thread.thread = 23
        thread_exit = win.Event(code=4, pid=20, tid=30)
        process_exit = win.Event(code=5, pid=20, tid=10)
        events = [created, thread, thread_exit, process_exit]
        closed, continued = Counter(), Counter()
        terminated = []
        current = None

        def create(*args):
            pi = args[-1]._obj
            pi.process, pi.thread, pi.pid, pi.tid = 1, 2, 20, 10
            return True

        def wait(event, milliseconds):
            nonlocal current
            self.assertTrue(events, "unexpected wait after all mock events")
            current = events.pop(0)
            win.C.memmove(event, win.C.byref(current), win.C.sizeof(win.Event))
            return True

        def resume(pid, tid, status):
            continued[current.code] += 1
            if current.code == 5 and (persistent_failure or (fail_exit_once and continued[5] == 1)):
                win.C.set_last_error(5)
                return False
            # Model only Windows-owned event handles. PROCESS_INFORMATION's
            # independently returned handles 1/2 still belong to the caller.
            if current.code == 4:
                closed[23] += 1
            elif current.code == 5:
                closed[21] += 1
                closed[22] += 1
            return True

        def read(process, address, buffer, size, count):
            self.assertEqual((address, size), (0x4FF2D0, 1))
            win.C.memmove(buffer, b"\xc3", 1)
            count._obj.value = 1
            return True

        def write(process, address, data, size, count):
            self.assertEqual((address, data, size), (0x4FF2D0, b"\xcc", 1))
            count._obj.value = 1
            return True

        def close(handle):
            closed[handle] += 1
            return True

        with ExitStack() as stack:
            stack.enter_context(patch.object(Path, "read_bytes", return_value=b""))
            stack.enter_context(patch.object(win, "COMPILER_SHA256", hashlib.sha256(b"").hexdigest()))
            for name, callback in {
                "create": create, "wait": wait, "resume": resume, "read": read,
                "write": write, "close": close, "flush": lambda *a: True,
                "terminate": lambda *a: terminated.append(a) or not persistent_failure,
                "waitprocess": lambda *a: 258 if persistent_failure else 0,
                "detach": lambda *a: False,
            }.items():
                stack.enter_context(patch.object(win, name, side_effect=callback))
            if persistent_failure:
                # Expire only the cleanup deadline, without slowing the test.
                ticks = iter(range(0, 1000, 4))
                stack.enter_context(patch.object(win.time, "monotonic", side_effect=lambda: next(ticks)))
                stack.enter_context(patch.object(win.time, "sleep"))
            error = RuntimeError if persistent_failure else TimeoutError if timeout == 0 else OSError if fail_exit_once else RuntimeError
            with self.assertRaises(error) as raised:
                win.capture(["mock-compiler.exe"], Path.cwd(), {"missing"}, timeout=timeout)
            if persistent_failure:
                self.assertIn("incomplete compiler teardown", str(raised.exception))
        return closed, continued, terminated

    def test_event_handles_are_not_closed_twice(self):
        closed, continued, terminated = self.exercise()
        self.assertEqual(closed, Counter({1: 1, 2: 1, 11: 1, 21: 1, 22: 1, 23: 1}))
        self.assertEqual(continued[5], 1)
        self.assertFalse(terminated)

    def test_exit_continuation_failure_still_drains_pending_event(self):
        closed, continued, terminated = self.exercise(fail_exit_once=True)
        self.assertEqual(continued[5], 2)
        self.assertEqual(closed, Counter({1: 1, 2: 1, 11: 1, 21: 1, 22: 1, 23: 1}))
        self.assertEqual(len(terminated), 1)

    def test_timeout_before_first_event_drains_created_file_handle(self):
        closed, continued, terminated = self.exercise(timeout=0)
        self.assertEqual(continued[5], 1)
        self.assertEqual(closed, Counter({1: 1, 2: 1, 11: 1, 21: 1, 22: 1, 23: 1}))
        self.assertEqual(len(terminated), 1)

    def test_persistent_failure_retries_pending_event_and_reports_teardown(self):
        closed, continued, terminated = self.exercise(persistent_failure=True)
        self.assertGreater(continued[5], 1)
        self.assertEqual(closed, Counter({1: 1, 2: 1, 11: 1, 23: 1}))
        self.assertEqual(len(terminated), 1)


if __name__ == "__main__":
    unittest.main()
