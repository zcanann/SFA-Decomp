"""Execute the production text color setter in direct and deferred modes."""
import ctypes
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body


ROOT = Path(__file__).resolve().parents[1]


class GameTextColorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/gametext.c").read_text()
        start, end = find_function_body(source, "gameTextSetColor")
        declaration = source.rfind("void gameTextSetColor", 0, start)
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-text-color-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "color.c"
        fixture.write_text(r'''
#define _TYPES_H_
typedef unsigned char u8;
#include "main/gametext_color_api.h"
#define NULL ((void*)0)
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
typedef struct GameTextSlot {
    int opcode, arg0, arg1, arg2, arg3;
} GameTextSlot;
static int gGameTextCommandCount;
static GameTextSlot gGameTextCommandSlots[4];
static u8 gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA;
static void (*gameTextDrawFunc)(void);
static void draw(void) {}
EXPORT void prepare(int direct) {
    int i;
    gGameTextCommandCount = 1;
    for (i = 0; i < 4; i++) {
        gGameTextCommandSlots[i].opcode = 17;
        gGameTextCommandSlots[i].arg0 = 18;
        gGameTextCommandSlots[i].arg1 = 19;
        gGameTextCommandSlots[i].arg2 = 20;
        gGameTextCommandSlots[i].arg3 = 21;
    }
    gGameTextColorR = 18; gGameTextColorG = 19;
    gGameTextColorB = 20; gGameTextColorA = 21;
    gameTextDrawFunc = direct ? draw : NULL;
}
''' + source[declaration:end + 1] + r'''
EXPORT void run(int r, int g, int b, int a) { gameTextSetColor(r, g, b, a); }
EXPORT int readState(int* out) {
    int i;
    out[0] = gGameTextColorR; out[1] = gGameTextColorG;
    out[2] = gGameTextColorB; out[3] = gGameTextColorA;
    for (i = 0; i < 4; i++) {
        out[4 + i * 5] = gGameTextCommandSlots[i].opcode;
        out[5 + i * 5] = gGameTextCommandSlots[i].arg0;
        out[6 + i * 5] = gGameTextCommandSlots[i].arg1;
        out[7 + i * 5] = gGameTextCommandSlots[i].arg2;
        out[8 + i * 5] = gGameTextCommandSlots[i].arg3;
    }
    return gGameTextCommandCount;
}
''')
        library = directory / ("color.dll" if sys.platform == "win32" else "color.so")
        command = [compiler, "-shared", "-O2", "-Wall", "-Werror", "-fno-builtin",
                   "-I", str(ROOT / "include"), str(fixture), "-o", str(library)]
        if sys.platform == "win32":
            command += ["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
        else:
            command += ["-fPIC"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.library = ctypes.CDLL(str(library))
        if sys.platform == "win32":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            cls.addClassCleanup(kernel.FreeLibrary, cls.library._handle)
        cls.library.prepare.argtypes = [ctypes.c_int]
        cls.library.prepare.restype = None
        cls.library.run.argtypes = [ctypes.c_int] * 4
        cls.library.run.restype = None
        cls.library.readState.argtypes = [ctypes.POINTER(ctypes.c_int)]
        cls.library.readState.restype = ctypes.c_int

    def check_mode(self, direct):
        rng = random.Random(0x80019908)
        cases = [(n, n, n, n) for n in range(256)]
        cases += [(-1, 256, -256, 511), (-(2**31), 2**31 - 1, 0x12345678, -257)]
        cases += [tuple(rng.randrange(-(2**31), 2**31) for _ in range(4)) for _ in range(256)]
        for channels in cases:
            with self.subTest(direct=direct, channels=channels):
                self.library.prepare(direct)
                self.library.run(*channels)
                state = (ctypes.c_int * 24)()
                count = self.library.readState(state)
                expected = [18, 19, 20, 21] + [17, 18, 19, 20, 21] * 4
                colors = [value & 255 for value in channels]
                if direct:
                    expected[:4] = colors
                else:
                    expected[9:14] = [3] + colors
                self.assertEqual(count, 1 if direct else 2)
                self.assertEqual(list(state), expected)

    def test_direct_colors(self):
        self.check_mode(1)

    def test_deferred_colors(self):
        self.check_mode(0)


if __name__ == "__main__":
    unittest.main()
