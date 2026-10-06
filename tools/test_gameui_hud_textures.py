#!/usr/bin/env python3
"""Check GameUI's recovered HUD array accesses with 64-bit texture pointers."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body
from test_gameui_storage import hud_texture_slots

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef float f32;
typedef struct Texture { int id; } Texture;
/* Only text-service behavior is stubbed; this is not a target layout fixture. */
typedef struct TextSlot { s16 maxWidth, height, width, x, alpha; } TextSlot;
static Texture textures[102];
static Texture* gGameTextBoxFrameTextures[5];
static TextSlot textBox = {200, 40, 0, 0, 0};
static s16 gHudCommAlertTimer, gPauseMenuTitleFadeCounter;
static int gWorldMapVoiceoverTimer, gPauseMenuTextCharset;
static int gPauseMenuTitleTextId, gPauseMenuTitlePhraseIndex;
static Texture* drawn[64];
static int drawCount;
static void record(void* texture) {
    assert(drawCount < 64);
    drawn[drawCount++] = texture;
}
static void drawTexture(void* texture, f32 x, f32 y, int alpha, int scale) {
    record(texture);
}
static void drawScaledTexture(void* texture, f32 x, f32 y, int alpha, int scale,
                              int width, int height, int flags) {
    record(texture);
}
static int gameTextGetCharset(void) { return 0; }
static void gameTextSetCharset(int charset, int flags) {}
static void* gameTextGetPhrase(int id, int index) { return "Test"; }
static TextSlot* gameTextGetBox(int id) { return &textBox; }
static void gameTextSetCursor(int width, int height, int flags) {}
static void gameTextResetCursor(int flags) {}
static void gameTextMeasureStringBoundsAt(void* phrase, int id, int x, int y,
                                         int* left, int* right, int* top, int* bottom) {
    *left = 0; *right = 100; *top = 0; *bottom = 20;
}
static void gameTextSetColor(int r, int g, int b, int a) {}
static void gameTextAppendStr(void* phrase, int id) {}
"""
CASES = r"""
int main(void) {
    /* These expected indices come from retail offsets divided by pointer size 4. */
    static const int filled[] = {10, 13, 11, 12, 13, 11, 10, 10, 10};
    static const int outline[] = {10, 13, 11, 13, 11, 10, 10, 10};
    assert(sizeof(void*) == 8);
    for (int i = 0; i < 102; i++) hudTextures[i] = &textures[i];
    drawHudBox(10, 20, 80, 30, 255, 1);
    assert(drawCount == 9);
    for (int i = 0; i < 9; i++) assert(drawn[i] == &textures[filled[i]]);
    drawCount = 0;
    drawHudBox(-10, -20, 80, 30, 127, 0);
    assert(drawCount == 8);
    for (int i = 0; i < 8; i++) assert(drawn[i] == &textures[outline[i]]);

    drawCount = 0;
    hudDrawCommunicatorAlert(0, 0, 0);
    assert(drawCount == 0);
    for (int timer = 1; timer <= 64; timer++) {
        drawCount = 0;
        gHudCommAlertTimer = timer;
        hudDrawCommunicatorAlert(0, 0, 0);
        assert(drawCount == 13);
        assert(drawn[0] == &textures[68]);
        for (int i = 1; i < 13; i++) assert(drawn[i] == &textures[69]);
    }

    pauseMenuDrawText(0, 0, 0);
    for (int i = 0; i < 5; i++) assert(gGameTextBoxFrameTextures[i] == NULL);
    gPauseMenuTitleFadeCounter = 64;
    gWorldMapVoiceoverTimer = 1;
    pauseMenuDrawText(0, 0, 0);
    for (int i = 0; i < 5; i++) assert(gGameTextBoxFrameTextures[i] == NULL);
    gWorldMapVoiceoverTimer = 0;
    pauseMenuDrawText(0, 0, 0);
    for (int i = 0; i < 5; i++) assert(gGameTextBoxFrameTextures[i] == &textures[79 + i]);
    return 0;
}
"""


def harness():
    source = (ROOT / "src/dlls/engine/0/0.c").read_text()
    array = re.search(r"^Texture\* hudTextures\[[^\]]+\];$", source, re.M)
    if array is None:
        raise ValueError("HUD texture array definition not found")
    parts = [PRELUDE, hud_texture_slots(source), array[0]]
    for name in ("drawHudBox", "hudDrawCommunicatorAlert", "pauseMenuDrawText"):
        start, end = find_function_body(source, name)
        declaration = source.rfind("void " + name, 0, start)
        if declaration < 0:
            raise ValueError(f"function definition not found: {name}")
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class GameUiHudTextureTests(unittest.TestCase):
    def test_native_texture_selection(self):
        with tempfile.TemporaryDirectory(prefix="gameui-hud-textures-") as directory:
            source = Path(directory) / "draw.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "draw"
                    subprocess.run([
                        "clang", "-std=c99", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-fsanitize=address,undefined", str(source),
                        "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
