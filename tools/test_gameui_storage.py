#!/usr/bin/env python3
"""Exercise GameUI texture cleanup with independent globals and native pointers.

Extract the production declarations and helper bodies. ASan places redzones
between globals, so a fabricated aggregate or a four-byte pointer stride cannot
silently rely on the target compiler's global pooling.
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
SYMBOLS = (
    "hudTextures", "gPauseMenuIconTextures", "gPauseMenuIconTextureIds",
    "gCMenuItemTextures", "gCMenuItemTextureIds", "gCMenuItemFlags",
    "gPauseMenuGridBackdropTexture", "gTrickyHudCachedIconTexture",
    "gTrickyHudCachedIconIndex", "gGameUiBlinkTexture",
)
HELPERS = (
    "pauseMenuFreeIconTextures", "gameUiClearItemSlots",
    "gameUiReleaseMenuResources", "gameUiFreeResources",
)
PRELUDE = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef int16_t s16;
typedef struct Texture { int id; } Texture;
#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
static Texture textures[256];
static Texture* expected[256];
static int expectedCount, freeCount, resetCount;
static void textureFree(Texture* texture) {
    assert(freeCount < expectedCount);
    assert(texture == expected[freeCount++]);
}
static void gameUiResetMenuState(void) { resetCount++; }
"""
CASES = r"""
static void checkMenuCleared(void) {
    for (int i = 0; i < 64; i++) {
        assert(gCMenuItemTextures[i] == NULL);
        assert(gCMenuItemTextureIds[i] == -1);
        assert(gCMenuItemFlags[i] == 1);
    }
    assert(gPauseMenuGridBackdropTexture == NULL);
    assert(gTrickyHudCachedIconTexture == NULL);
    assert(gTrickyHudCachedIconIndex == -1);
}

int main(void) {
    assert(sizeof(void*) == 8);
    for (int i = 0; i < 102; i++) {
        hudTextures[i] = i % 2 ? NULL : &textures[i];
        if (hudTextures[i]) expected[expectedCount++] = hudTextures[i];
    }
    for (int i = 0; i < 64; i++) {
        gCMenuItemTextures[i] = i % 2 ? &textures[102 + i] : NULL;
        gCMenuItemTextureIds[i] = 500 + i;
        gCMenuItemFlags[i] = 0;
        if (gCMenuItemTextures[i]) expected[expectedCount++] = gCMenuItemTextures[i];
    }
    gPauseMenuGridBackdropTexture = &textures[166];
    gTrickyHudCachedIconTexture = &textures[167];
    gTrickyHudCachedIconIndex = 7;
    gGameUiBlinkTexture = &textures[168];
    expected[expectedCount++] = gPauseMenuGridBackdropTexture;
    expected[expectedCount++] = gTrickyHudCachedIconTexture;
    expected[expectedCount++] = gGameUiBlinkTexture;
    gameUiFreeResources();
    assert(freeCount == expectedCount && resetCount == 1);
    checkMenuCleared();

    /* The full shutdown retains HUD/blink pointers; only menu cleanup repeats. */
    for (int i = 0; i < 102; i++) {
        assert(hudTextures[i] == (i % 2 ? NULL : &textures[i]));
    }
    assert(gGameUiBlinkTexture == &textures[168]);
    gameUiReleaseMenuResources();
    assert(freeCount == expectedCount && resetCount == 2);
    checkMenuCleared();

    /* Exercise the separate menu helper with every slot populated. */
    for (int i = 0; i < 64; i++) {
        gCMenuItemTextures[i] = &textures[i];
        expected[expectedCount++] = &textures[i];
    }
    gameUiReleaseMenuResources();
    assert(freeCount == expectedCount && resetCount == 3);
    checkMenuCleared();

    for (int i = 0; i < 40; i++) {
        gPauseMenuIconTextureIds[i] = 700 + i;
        gPauseMenuIconTextures[i] = i % 2 ? &textures[i] : NULL;
        if (i % 2) expected[expectedCount++] = &textures[i];
    }
    pauseMenuFreeIconTextures();
    assert(freeCount == expectedCount);
    for (int i = 0; i < 40; i++) {
        assert(gPauseMenuIconTextures[i] == NULL);
        assert(gPauseMenuIconTextureIds[i] == (i % 2 ? 0 : 700 + i));
    }
    pauseMenuFreeIconTextures();
    assert(freeCount == expectedCount);
    return 0;
}
"""


def harness():
    source = (ROOT / "src/dlls/engine/0/0.c").read_text()
    parts = [PRELUDE]
    for symbol in SYMBOLS:
        declaration = re.search(r"^(?:Texture\*|void\*|s16|u8|int) " + symbol +
                                r"(?:\[[^\]]+\])?;$", source, re.M)
        if declaration is None:
            raise ValueError(f"global definition not found: {symbol}")
        parts.append(declaration[0])
    for name in HELPERS:
        start, end = find_function_body(source, name)
        declaration = source.rfind("static inline void " + name, 0, start)
        if declaration < 0:
            raise ValueError(f"helper definition not found: {name}")
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class GameUiStorageTests(unittest.TestCase):
    def test_native_texture_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="gameui-storage-") as directory:
            source = Path(directory) / "storage.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "storage"
                    subprocess.run([
                        "clang", "-std=c99", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-sign-compare", "-fsanitize=address,undefined", str(source),
                        "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
