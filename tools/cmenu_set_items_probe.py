#!/usr/bin/env python3
"""Compare cMenuSetItems state changes and calls against a chosen source baseline.

Compile both function bodies with a host C compiler and deterministic service
stubs. This tests C behavior, not PPC code generation or behavior of the stubs'
real engine counterparts. Target object comparison and retail hashing remain
separate checks.

    python3 tools/cmenu_set_items_probe.py --baseline 6b1ba5bc2c
"""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "src/dlls/engine/0/0.c"


def function(source, name):
    start = re.search(r"^int cMenuSetItems\([^\n]*\) \{", source, re.M)
    if start is None:
        raise ValueError("cMenuSetItems definition not found")
    end = source.index("\n}", start.start()) + 2
    return source[start.start():end].replace("cMenuSetItems(", name + "(", 1)


def layouts():
    items = (ROOT / "include/main/dll/cmenu_item_table.h").read_text()
    item = re.search(r"typedef struct CMenuItemDef\s*\{.*?\} CMenuItemDef;", items, re.S)
    hud = (ROOT / "include/main/dll/dll_0000_gameui.h").read_text()
    end = hud.index("} CMenuHud;") + len("} CMenuHud;")
    start = hud.rindex("typedef struct {", 0, end)
    enum = re.search(r"typedef enum HudStatusSlot \{.*?\} HudStatusSlot;", hud, re.S)
    if item is None or enum is None:
        raise ValueError("canonical C-menu layouts not found")
    return item[0] + "\n" + enum[0] + "\n" + hud[start:end]


PRELUDE = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef float f32;
typedef struct Texture { int id; } Texture;
typedef struct GameObject GameObject;
#define CMENU_ITEM_SLOT_COUNT 64
"""

FIXTURE = r"""
typedef struct { int kind, argument; } Event;
typedef struct {
    CMenuHud hud;
    CMenuItemDef staff[65], quest[65];
    s16 forced, yTexture;
    s8 preselect;
    u16 yState, yItem;
    int itemMask, actionMask, fileFlags;
    u32 bits[512];
    Event events[512];
    unsigned eventCount;
} State;
static State live, initial, expected;
static Texture textures[256];
#define lbl_803A87F0 ((void*)&live.hud)
#define gCMenuStaffAbilities live.staff
#define gCMenuForcedSelIndex live.forced
#define gCMenuPreselectOwnedBit live.preselect
#define gTrickyHudItemMask live.itemMask
#define gTrickyHudActionMask live.actionMask
#define yButtonState live.yState
#define yButtonItem live.yItem
#define yButtonItemTextureId live.yTexture
static void record(int kind, int argument) {
    assert(live.eventCount < 512);
    live.events[live.eventCount++] = (Event){kind, argument};
}
static u32 mainGetBit(int bit) {
    assert(bit >= 0 && bit < 512);
    record(1, bit);
    return live.bits[bit];
}
static void* getTrickyObject(void) { record(2, 0); return NULL; }
static void textureFree(Texture* texture) { record(3, texture->id); }
static int getLoadedFileFlags(int file) { record(4, file); return live.fileFlags; }
static Texture* textureLoadAsset(int id) {
    assert(id >= 0 && id < 256);
    record(5, id);
    return &textures[id];
}
static u32 randomState = 0xC0DE0000;
static u32 nextRandom(void) {
    randomState ^= randomState << 13;
    randomState ^= randomState >> 17;
    randomState ^= randomState << 5;
    return randomState;
}
"""

MAIN = r"""
int main(void) {
    static const u32 bitValues[] = {0, 0, 1, 2, 255, 256, 0x80000000u, 0xffffffffu};
    static const s16 terminators[] = {-1, -2, -32768};
    unsigned test, i, count, staff, tricky;
    int oldCount, newCount;
    for (i = 0; i < 256; i++) { textures[i].id = i; }
    for (test = 0; test < CASE_COUNT; test++) {
        memset(&initial, 0, sizeof(initial));
        for (i = 0; i < sizeof(initial.hud); i++) {
            ((u8*)&initial.hud)[i] = nextRandom();
        }
        for (i = 0; i < 64; i++) {
            initial.hud.itemSlots[i] = nextRandom() % 5 == 0 ? -1 : nextRandom() % 256;
            initial.hud.itemTextures[i] = nextRandom() % 3 == 0 ? NULL : &textures[nextRandom() % 256];
        }
        for (i = 0; i < 512; i++) { initial.bits[i] = bitValues[nextRandom() % 8]; }
        count = test % 65;  /* Includes empty and full-capacity lists. */
        staff = (test / 65) & 1;
        tricky = (test / 130) % 3;  /* Both nonzero flag values take the Tricky path. */
        for (i = 0; i < count; i++) {
            CMenuItemDef item;
            item.ownedGameBit = tricky ? 1 << (nextRandom() % 9) : nextRandom() % 128;
            item.usedGameBit = nextRandom() % 3 == 0 ? -1 : nextRandom() % 128;
            item.activeGameBit = nextRandom() % 3 == 0 ? -1 : nextRandom() % 128;
            item.iconTextureId = nextRandom() % 256;
            item.unk8 = -1;
            item.auxiliaryValue = nextRandom();
            item.nameTextId = nextRandom();
            item.auxiliaryByte = nextRandom();
            item.closeMode = nextRandom();
            initial.staff[i] = initial.quest[i] = item;
        }
        initial.staff[count].ownedGameBit = initial.quest[count].ownedGameBit = terminators[test % 3];
        initial.forced = 37;
        initial.preselect = test % 3 == 0 && count ? initial.quest[count / 2].ownedGameBit : nextRandom();
        initial.itemMask = test % 5 == 0 ? -1 : nextRandom() & 511;
        initial.actionMask = test % 7 == 0 ? 511 : nextRandom() & 511;
        initial.yState = test % 4;
        initial.yItem = count ? initial.quest[count / 2].activeGameBit : 4;
        initial.yTexture = 23;
        initial.fileFlags = test % 2;

        live = initial;
        oldCount = baseline(staff ? live.staff : live.quest, tricky);
        expected = live;
        live = initial;
        newCount = candidate(staff ? live.staff : live.quest, tricky);
        if (oldCount != newCount || memcmp(&expected, &live, sizeof(live))) {
            fprintf(stderr, "Mismatch in case %u (entries=%u staff=%u tricky=%u counts=%d/%d)\n",
                    test, count, staff, tricky, oldCount, newCount);
            return 1;
        }
    }
    printf("%u cases: identical return values, complete HUD/global state, and ordered engine calls\n", test);
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="Git revision containing the reference function")
    parser.add_argument("--cases", type=int, default=10000)
    parser.add_argument("--cc", default="clang", help="Host C compiler executable")
    parser.add_argument("--timeout", type=float, default=30,
                        help="Time limit in seconds for compilation and execution separately")
    args = parser.parse_args()
    if args.cases < 1:
        parser.error("--cases must be positive")
    if not 0 < args.timeout < float("inf"):
        parser.error("--timeout must be finite and positive")
    old = subprocess.check_output(["git", "show", f"{args.baseline}:{SOURCE}"], cwd=ROOT, text=True)
    current = (ROOT / SOURCE).read_text()
    harness = "\n".join([PRELUDE, layouts(), FIXTURE, function(old, "baseline"),
                         function(current, "candidate"), MAIN])
    with tempfile.TemporaryDirectory(prefix="cmenu-probe-") as directory:
        source = Path(directory) / "probe.c"
        executable = Path(directory) / "probe"
        source.write_text(harness)
        phase = "compilation"
        try:
            subprocess.run([args.cc, "-std=c99", "-O1", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", f"-DCASE_COUNT={args.cases}",
                            str(source), "-o", str(executable)], check=True, timeout=args.timeout)
            phase = "execution"
            subprocess.run([str(executable)], check=True, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            parser.exit(1, f"C-menu differential probe {phase} timed out after {args.timeout:g} seconds\n")


if __name__ == "__main__":
    main()
