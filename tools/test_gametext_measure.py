"""Execute bounds measurement and its production inline ID lookup."""
import ctypes
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body


ROOT = Path(__file__).resolve().parents[1]


class GameTextMeasureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/gametext.c").read_text()
        header = (ROOT / "include/main/gametext_internal.h").read_text()
        definitions = "\n".join(re.search(r"typedef struct " + name + r" \{.*?\} " + name + ";",
                                          header, re.S).group() for name in ("GameTextDef", "TextFont"))
        functions = []
        for name, prefix in (("gameTextIdExists", "static inline int"), ("gameTextMeasureById", "void")):
            start, end = find_function_body(source, name)
            declaration = source.rfind(prefix + " " + name, 0, start)
            functions.append(source[declaration:end + 1])
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-text-measure-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "measure.c"
        fixture.write_text(r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef float f32;
typedef struct TextGlyph TextGlyph;
#define NULL ((void*)0)
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
''' + definitions + r'''
static GameTextDef entries[3];
static TextFont font;
static TextFont* gameTextFonts = &font;
static int gGameTextMeasureOnly;
static int gGameTextBoundsMinX, gGameTextBoundsMaxX;
static int gGameTextBoundsMinY, gGameTextBoundsMaxY;
static int renderCount, valid;
static void gameTextRenderById(int textId, int x, int y) {
    renderCount++;
    valid &= textId >= 100 && textId <= 102 && x == -13 && y == 27;
    valid &= gGameTextMeasureOnly == 1;
    valid &= gGameTextBoundsMinX == 0x7FFFFFFF && gGameTextBoundsMaxX == 0;
    valid &= gGameTextBoundsMinY == 0x7FFFFFFF && gGameTextBoundsMaxY == 0;
    gGameTextBoundsMinX = -17; gGameTextBoundsMaxX = 38;
    gGameTextBoundsMinY = -9; gGameTextBoundsMaxY = 83;
}
''' + "\n".join(functions) + r'''
EXPORT int run(int status, int count, int textId, unsigned int mask, int* out) {
    int i;
    for (i = 0; i < 3; i++) entries[i].identifier = 100 + i;
    for (i = 0; i < 4; i++) out[i] = 999;
    font.status = status; font.entryCount = count; font.entries = entries;
    gGameTextMeasureOnly = 7;
    renderCount = 0; valid = 1;
    gameTextMeasureById(textId, -13, 27, mask & 1 ? out : NULL,
                        mask & 2 ? out + 1 : NULL, mask & 4 ? out + 2 : NULL,
                        mask & 8 ? out + 3 : NULL);
    out[4] = renderCount;
    out[5] = gGameTextMeasureOnly;
    return valid;
}
''')
        library = directory / ("measure.dll" if sys.platform == "win32" else "measure.so")
        command = [compiler, "-shared", "-O2", "-Wall", "-Werror", "-fno-builtin",
                   str(fixture), "-o", str(library)]
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
        cls.library.run.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_uint, ctypes.POINTER(ctypes.c_int)]
        cls.library.run.restype = ctypes.c_int

    def test_loaded_ids_and_optional_output_coordinates(self):
        for text_id in range(100, 103):
            for mask in range(16):
                with self.subTest(text_id=text_id, mask=mask):
                    out = (ctypes.c_int * 6)()
                    self.assertEqual(self.library.run(2, 3, text_id, mask, out), 1)
                    expected = [value if mask & (1 << i) else 999
                                for i, value in enumerate((-5, 9, -3, 20))]
                    self.assertEqual(list(out), expected + [1, 0])

    def test_absent_ids_clear_all_outputs_without_rendering(self):
        # Retail requires all four output pointers on the missing-ID path.
        for status, count, text_id in [(state, 3, 100) for state in (0, 1, 3, 4)] + [(2, 0, 100), (2, 3, 99)]:
            with self.subTest(status=status, count=count, text_id=text_id):
                out = (ctypes.c_int * 6)()
                self.assertEqual(self.library.run(status, count, text_id, 15, out), 1)
                self.assertEqual(list(out), [0, 0, 0, 0, 0, 7])


if __name__ == "__main__":
    unittest.main()
