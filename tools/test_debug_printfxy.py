"""Exercise the production debug formatter's layout and dual-framebuffer dispatch.

Formatting is mocked as a single %s copy; this does not test MSL vsprintf or
the glyph rasterizer. The actual formatter body and font view are compiled.
"""
import ctypes
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DebugPrintfxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/dll_80136a40.c").read_text()
        function = re.search(r"^void debugPrintfxy\(.*?^\}", source, re.M | re.S).group()
        view = re.search(r"typedef struct DebugFontErrorDataView \{.*?\} DebugFontErrorDataView;",
                         source, re.S).group()
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-debug-printfxy-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "debug.c"
        fixture.write_text(r'''
#include <stdarg.h>
typedef unsigned char u8;
typedef unsigned short u16;
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
''' + view + r'''
static u8 gDebugFontAndErrorData[sizeof(DebugFontErrorDataView)];
static u16 frameBuffers[3];
static u16* externalFrameBuffer0 = &frameBuffers[0];
static u16* externalFrameBuffer1 = &frameBuffers[1];
static u16* debugDrawFrameBuffer;
static u8 enableDebugText;
static int calls[512][5], callCount, formatCount, valid;

static int vsprintf(char* destination, char* format, va_list args) {
    const char* input = va_arg(args, const char*);
    int i = 0;
    valid &= format[0] == '%' && format[1] == 's' && format[2] == 0;
    formatCount++;
    do { destination[i] = input[i]; } while (input[i++] != 0);
    return i - 1;
}

static void debugTextDrawToFrameBuffer(int x, int y, u8* glyph, int unused) {
    int offset = (int)(glyph - gDebugFontAndErrorData);
    int slot = callCount++;
    valid &= slot < 512 && offset >= 0 && offset < 290 && offset % 5 == 0;
    if (slot >= 512) return;
    calls[slot][0] = x;
    calls[slot][1] = y;
    calls[slot][2] = offset / 5 + 0x21;
    calls[slot][3] = (int)(debugDrawFrameBuffer - frameBuffers);
    calls[slot][4] = unused;
}
''' + function + r'''
EXPORT void run(int enabled, int x, int y, const char* text) {
    valid = 1;
    callCount = formatCount = 0;
    enableDebugText = enabled;
    debugDrawFrameBuffer = &frameBuffers[2];
    debugPrintfxy(x, y, "%s", text);
    valid &= debugDrawFrameBuffer == &frameBuffers[2];
}
EXPORT int count(void) { return callCount; }
EXPORT int formatted(void) { return formatCount; }
EXPORT int isValid(void) { return valid; }
EXPORT int value(int call, int field) { return calls[call][field]; }
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
            handle.run.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
            handle.run.restype = None
            for name in ("count", "formatted", "isValid"):
                getattr(handle, name).argtypes = []
                getattr(handle, name).restype = ctypes.c_int
            handle.value.argtypes = [ctypes.c_int, ctypes.c_int]
            handle.value.restype = ctypes.c_int
            cls.libraries.append(handle)

    def check_layout(self, text, x=17, y=21, enabled=1):
        expected = []
        current_x, current_y = x, y
        if enabled:
            for byte in text.split(b"\0", 1)[0]:
                if byte == 10:
                    current_x, current_y = x, current_y + 12
                elif byte == 9:
                    current_x = (current_x // 64 + 1) * 64
                elif byte == 32:
                    current_x += 8
                else:
                    glyph = byte - 32 if 97 <= byte <= 122 else byte
                    if 33 <= glyph <= 90:
                        expected.extend((current_x, current_y, glyph, frame, -1) for frame in (0, 1))
                        current_x += 15
        for library in self.libraries:
            library.run(enabled, x, y, text)
            self.assertEqual(library.isValid(), 1)
            self.assertEqual(library.formatted(), bool(enabled))
            actual = [tuple(library.value(i, field) for field in range(5))
                      for i in range(library.count())]
            self.assertEqual(actual, expected)

    def test_layout_controls_and_byte_ranges(self):
        for text in (b"", b"aZ!", b"a\tb c\nD\n\tE", bytes(range(1, 256)),
                     b"A\0B", b"z" * 255):
            self.check_layout(text)
        for x in (-65, -1, 0, 63, 64, 65):
            self.check_layout(b"\tA\n\tB", x=x)

    def test_disabled_does_not_format_or_draw(self):
        self.check_layout(b"disabled\ttext\n", enabled=0)

    def test_randomized_layout(self):
        rng = random.Random(0x80136A40)
        for _ in range(64):
            text = bytes(rng.randrange(1, 256) for _ in range(rng.randrange(256)))
            self.check_layout(text, x=rng.randrange(-80, 80), y=rng.randrange(100))


if __name__ == "__main__":
    unittest.main()
