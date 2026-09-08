"""Check production debug-record rectangle bounds and boundary dispatch.

GX drawing, text color, and glyph width are controlled dependencies. These
tests do not emulate the font atlas, GX hardware, or out-of-range FP casts.
"""
import ctypes
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DebugRecordRectangleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/dll_80136a40.c").read_text()
        names = ("debugPrintXpos", "debugPrintYpos", "gDebugRectStartX", "gDebugRectStartY",
                 "gDebugDrawPass", "gDebugFixedWidthMode", "gDebugScaleX", "gDebugScaleY",
                 "gDebugScaleBiasX", "gDebugScaleBiasY", "gDebugTextColorR", "gDebugTextColorG",
                 "gDebugTextColorB", "gDebugTextColorA", "gDebugTabWidth", "gDebugPrintOriginX",
                 "gDebugScreenWidth")
        commands = re.search(r"enum DebugLogCommand \{.*?\};", source, re.S).group()
        globals_source = "\n".join(re.search(r"^\w+ " + name + r"(?: = [^;]+)?;", source, re.M).group()
                                   for name in names)
        functions = "\n".join(re.search(r"^(?:static inline void|int) " + name + r"\([^;{}]*\) \{.*?^\}",
                                         source, re.M | re.S).group()
                               for name in ("debugPrintFillRect", "debugDrawLogRect", "debugPrintDrawRecord"))
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-debug-rectangles-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "rectangles.c"
        fixture.write_text(r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef float f32;
typedef struct GXColor { u8 r, g, b, a; } GXColor;
#define GX_TEVREG0 1
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
''' + commands + '\n' + globals_source + r'''
static int rectangles[32][8], rectangleCount, glyphCount, colorCount;
static int glyphColorCount, glyphColor[5];
static void hudDrawRect(int x0, int y0, int x1, int y1, GXColor color) {
    int i = rectangleCount++;
    if (i >= 32) return;
    rectangles[i][0] = x0; rectangles[i][1] = y0;
    rectangles[i][2] = x1; rectangles[i][3] = y1;
    rectangles[i][4] = color.r; rectangles[i][5] = color.g;
    rectangles[i][6] = color.b; rectangles[i][7] = color.a;
}
static int debugPrintDrawGlyph(void* context, int c) { glyphCount++; return 5; }
static void setTextColor(void* context, int r, int g, int b, int a) { colorCount++; }
static void GXSetTevColor(int reg, GXColor color) {
    glyphColorCount++;
    glyphColor[0] = reg;
    glyphColor[1] = color.r; glyphColor[2] = color.g;
    glyphColor[3] = color.b; glyphColor[4] = color.a;
}
''' + functions + r'''
EXPORT void prepare(int x, int y, int left, int top, int pass, float sx, float sy, int screenWidth) {
    rectangleCount = glyphCount = colorCount = 0;
    glyphColorCount = 0;
    debugPrintXpos = x; debugPrintYpos = y;
    gDebugRectStartX = left; gDebugRectStartY = top;
    gDebugDrawPass = pass;
    gDebugScaleX = sx; gDebugScaleY = sy;
    gDebugScaleBiasX = gDebugScaleBiasY = 0;
    gDebugFixedWidthMode = 0;
    gDebugTabWidth = 32;
    gDebugPrintOriginX = 16;
    gDebugScreenWidth = screenWidth;
    gDebugTextColorR = 10; gDebugTextColorG = 20;
    gDebugTextColorB = 30; gDebugTextColorA = 40;
}
EXPORT void drawRectangle(void) { debugDrawLogRect(); }
EXPORT int drawRecord(u8* record) { return debugPrintDrawRecord(0, record); }
EXPORT int count(void) { return rectangleCount; }
EXPORT int value(int rectangle, int field) { return rectangles[rectangle][field]; }
EXPORT int state(int field) {
    switch (field) {
    case 0: return debugPrintXpos;
    case 1: return debugPrintYpos;
    case 2: return gDebugRectStartX;
    case 3: return gDebugRectStartY;
    case 4: return glyphCount;
    case 5: return colorCount;
    case 6: return glyphColorCount;
    case 7: return gDebugTabWidth;
    }
    if (field >= 8 && field < 13) return glyphColor[field - 8];
    return -1;
}
''')
        cls.libraries = []
        for optimization in ("-O0", "-O2"):
            library = directory / (optimization[1:] + (".dll" if sys.platform == "win32" else ".so"))
            command = [compiler, "-shared", optimization, "-fno-builtin", str(fixture), "-o", str(library)]
            if sys.platform == "win32":
                command += ["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
            else:
                command += ["-fPIC"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            handle = ctypes.CDLL(str(library))
            if sys.platform == "win32":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, handle._handle)
            handle.prepare.argtypes = [ctypes.c_int] * 5 + [ctypes.c_float] * 2 + [ctypes.c_int]
            handle.prepare.restype = None
            handle.drawRectangle.argtypes = []
            handle.drawRectangle.restype = None
            handle.drawRecord.argtypes = [ctypes.c_char_p]
            handle.drawRecord.restype = ctypes.c_int
            handle.count.argtypes = []
            handle.count.restype = ctypes.c_int
            handle.value.argtypes = [ctypes.c_int, ctypes.c_int]
            handle.value.restype = ctypes.c_int
            handle.state.argtypes = [ctypes.c_int]
            handle.state.restype = ctypes.c_int
            cls.libraries.append(handle)

    @staticmethod
    def rectangle(x, y, left, top, sx, sy, color=(10, 20, 30, 40)):
        if x == left or y + 10 == top:
            return []
        return [(int((left - 2 if left >= 2 else left) * sx), int(top * sy),
                 int((x + 2) * sx), int((y + 10) * sy), *color)]

    def check_rectangles(self, library, expected):
        actual = [tuple(library.value(i, j) for j in range(8)) for i in range(library.count())]
        self.assertEqual(actual, expected)

    def test_bounds_padding_and_scaling(self):
        for library in self.libraries:
            for sx, sy in ((1.0, 1.0), (1.5, 2.0), (0.5, 1.25)):
                for left in (0, 1, 2, 20, 80):
                    for x, y, top in ((left, 10, 6), (left + 17, 10, 6), (left + 17, 10, 20)):
                        library.prepare(x, y, left, top, 0, sx, sy, 640)
                        library.drawRectangle()
                        self.check_rectangles(library, self.rectangle(x, y, left, top, sx, sy))
                        self.assertEqual([library.state(i) for i in range(4)], [x, y, left, top])

    def test_newline_and_reposition_boundaries(self):
        for library in self.libraries:
            for draw_pass in (0, 1):
                for record, position in ((b"\n\0", [16, 31]), (b"\x82\x64\0\x32\0\0", [100, 50])):
                    library.prepare(40, 20, 16, 20, draw_pass, 1.5, 1.25, 640)
                    self.assertEqual(library.drawRecord(record), len(record))
                    expected = self.rectangle(40, 20, 16, 20, 1.5, 1.25) if draw_pass == 0 else []
                    self.check_rectangles(library, expected)
                    self.assertEqual([library.state(i) for i in range(4)], position * 2)

    def test_wrap_threshold_and_color(self):
        for library in self.libraries:
            for x in (619, 620):
                for draw_pass in (0, 1):
                    library.prepare(x, 20, 610, 20, draw_pass, 1.0, 1.0, 640)
                    self.assertEqual(library.drawRecord(b"A\0"), 2)
                    wraps = x == 620
                    expected = self.rectangle(x + 5, 20, 610, 20, 1, 1) if wraps and draw_pass == 0 else []
                    self.check_rectangles(library, expected)
                    position = [16, 31, 16, 31] if wraps else [624, 20, 610, 20]
                    self.assertEqual([library.state(i) for i in range(4)], position)
                    self.assertEqual(library.state(4), 1)
            library.prepare(40, 20, 16, 20, 0, 1.0, 1.0, 640)
            record = b"\x85\x03\0\xff\x80\n\0"
            self.assertEqual(library.drawRecord(record), len(record))
            self.check_rectangles(library, self.rectangle(40, 20, 16, 20, 1, 1, (3, 0, 255, 128)))
            self.assertEqual(library.state(5), 1)
            library.prepare(40, 20, 16, 20, 0, 1.0, 1.0, 640)
            record = b"\x87\x02\x01\n\0"
            self.assertEqual(library.drawRecord(record), len(record))
            self.check_rectangles(library, self.rectangle(40, 20, 16, 20, 3, 2))

    def test_width_modes_and_little_endian_tab_payload(self):
        for library in self.libraries:
            for draw_pass in (0, 1):
                library.prepare(16, 20, 16, 20, draw_pass, 1.0, 1.0, 2048)
                record = b"\x84A \x83A \0"
                self.assertEqual(library.drawRecord(record), len(record))
                self.assertEqual(library.state(0), 16 + 7 + 7 + 5 + 6)
                self.assertEqual(library.state(4), 2)
                # A zero low byte belongs to the payload, not the record terminator.
                library.prepare(16, 20, 16, 20, draw_pass, 1.0, 1.0, 2048)
                record = b"\x86\0\x01\t\t\0"
                self.assertEqual(library.drawRecord(record), len(record))
                self.assertEqual(library.state(7), 256)
                self.assertEqual(library.state(0), 512)

    def test_glyph_color_is_applied_only_on_glyph_pass(self):
        for library in self.libraries:
            for draw_pass in (0, 1):
                library.prepare(16, 20, 16, 20, draw_pass, 1.0, 1.0, 640)
                record = b"\x81\0\x80\xff\0A\0"
                self.assertEqual(library.drawRecord(record), len(record))
                self.assertEqual(library.state(6), draw_pass)
                if draw_pass:
                    self.assertEqual([library.state(i) for i in range(8, 13)], [1, 0, 128, 255, 0])
                self.assertEqual(library.state(5), 0)
                self.assertEqual(library.state(4), 1)
                self.assertEqual(library.state(0), 21)


if __name__ == "__main__":
    unittest.main()
