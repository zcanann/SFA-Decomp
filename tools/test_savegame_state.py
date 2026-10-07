#!/usr/bin/env python3
"""Exercise the actual save-game checkpoint and timer code with native pointers."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
#define STATIC_ASSERT(x) _Static_assert(x, #x)
"""
SERVICES = r"""
/* Player and allocator services are stubs; records and functions come from source. */
typedef struct GameObject { int unused; } GameObject;
static GameObject player;
static int allocations, releases, failAllocation, bitWrites, standUp;
static f32 timeDelta;
static void* mmAlloc(size_t size, u32 color, const char* allocationName) {
    assert(size == 0x6ec);
    if (failAllocation) return NULL;
    allocations++;
    return malloc(size);
}
static void mm_free(void* memory) { releases++; free(memory); }
static GameObject* Obj_GetPlayerObject(void) { return &player; }
static int playerGetCurHealth(GameObject* object) {
    assert(object == &player);
    return gSaveGameState.save.characterStatus[gSaveGameState.save.currentCharacter].health;
}
static void playerAddHealth(GameObject* object, int amount) {
    assert(object == &player);
    gSaveGameState.save.characterStatus[gSaveGameState.save.currentCharacter].health += amount;
}
static void mainSetBits(int bit, int value) {
    assert(bit == GAMEBIT_CF_DoStandUpAnim);
    bitWrites++;
    standUp = value;
}
"""
CASES = r"""
static void checkpoints(void) {
    f32 pos[] = {1.5f, -12.0f, 900.0f};
    gSaveGameState.save.currentCharacter = 1;
    gSaveGameState.save.characterStatus[1].health = 6;
    gSaveGameState.save.characterPositions[0].x = 42.0f;
    memset(&gSaveGameState.runtime, 0xa5, sizeof(gSaveGameState.runtime));
    failAllocation = 1;
    SaveGame_gplayRestartPoint(pos, 0x7f00, -2, 1);
    assert(!SaveGame_gplayGetRestartGameNotCleared());
    assert(bitWrites == 0 && playerGetCurHealth(&player) == 6);
    failAllocation = 0;
    SaveGame_gplayRestartPoint(pos, 0x7f00, -2, 1);
    assert(SaveGame_gplayGetRestartGameNotCleared());
    assert((uintptr_t)pRestartPoint > UINT32_MAX);
    assert(allocations == 1 && releases == 0);
    assert(pRestartPoint->characterStatus[1].health == 5);
    assert(playerGetCurHealth(&player) == 6 && standUp == 0 && bitWrites == 2);
    assert(pRestartPoint->characterPositions[0].x == 42.0f);
    assert(pRestartPoint->characterPositions[1].x == 1.5f);
    assert(pRestartPoint->characterPositions[1].y == -12.0f);
    assert(pRestartPoint->characterPositions[1].z == 900.0f);
    assert(pRestartPoint->characterPositions[1].angle == 127);
    assert(pRestartPoint->characterPositions[1].mapLayer == -2);
    SaveGame_gplayRestartPoint(pos, 0, 3, 0);
    assert(allocations == 1 && pRestartPoint->characterStatus[1].health == 6);

    /* A partial save preserves spawn/environment data after the copy boundary. */
    memset(gSaveGameWorkBuffer, 0x5a, sizeof(*gSaveGameWorkBuffer));
    gSaveGameState.save.characterPositions[1].x = 123.0f;
    SaveGame_gplaySavePoint(pos, 0, 1, 0);
    assert(memcmp(gSaveGameWorkBuffer, &gSaveGameState.save, 0x5d8) == 0);
    assert(memcmp(pRestartPoint, &gSaveGameState.save, 0x5d8) == 0);
    for (size_t i = 0x5d8; i < sizeof(*gSaveGameWorkBuffer); i++) {
        assert(((u8*)gSaveGameWorkBuffer)[i] == 0x5a);
    }
    assert(pRestartPoint->characterPositions[1].x == 1.5f);

    SaveGame_gplaySavePoint(pos, 0x1200, 2, -1);
    assert(!pRestartPoint && releases == 1);
    assert(gSaveGameState.save.savePointLocked == 1);
    assert(gSaveGameWorkBuffer->characterPositions[1].angle == 0x12);
    assert(gSaveGameWorkBuffer->characterPositions[1].mapLayer == -1);
    pos[0] = 80.0f;
    SaveGame_gplaySavePoint(pos, 0, 0, 0);
    assert(gSaveGameWorkBuffer->characterPositions[1].x == 1.5f);
    SaveGame_gplaySavePoint(pos, 0, 4, 0);
    assert(gSaveGameWorkBuffer->characterPositions[1].x == 80.0f);
    assert(gSaveGameState.save.savePointLocked == 0);
    for (size_t i = 0; i < sizeof(gSaveGameState.runtime); i++) {
        assert(((u8*)&gSaveGameState.runtime)[i] == 0xa5);
    }
    SaveGame_gplayRestartPoint(pos, 0, 0, 0);
    SaveGame_gplayClearRestartPoint();
    SaveGame_gplayClearRestartPoint();
    assert(allocations == 2 && releases == 2 && !pRestartPoint);
}

static void timers(void) {
    memset(&gSaveGameState, 0, sizeof(gSaveGameState));
    memset(gSaveGameWorkBuffer, 0, sizeof(*gSaveGameWorkBuffer));
    memset(gSaveGameState.runtime.unknown804, 0xa5, sizeof(gSaveGameState.runtime.unknown804));
    gSaveGameState.save.playTime = 100.0f;
    SaveGame_gplayAddTime(-1, 10.0f);
    assert(gSaveGameState.runtime.timeEntryCount == 0);
    assert(SaveGame_gplayDidTimeExpire(-1) && SaveGame_gplayDidTimeExpire(99));
    assert(SaveGame_gplayGetTimeRemaining(-1) == 0.0f);
    assert(SaveGame_gplayGetTimeRemaining(99) == 0.0f);
    SaveGame_gplayAddTime(7, 1.5f);
    SaveGame_gplayAddTime(9, 2.0f);
    SaveGame_gplayAddTime(7, 0.5f);
    assert(gSaveGameState.runtime.timeEntryCount == 2);
    assert(SaveGame_gplayGetTimeRemaining(7) == 10.0f);
    timeDelta = 10.0f;
    SaveGame_updateTimes();
    assert(!SaveGame_gplayDidTimeExpire(7)); /* equality is still active */
    assert(SaveGame_gplayGetTimeRemaining(7) == 0.0f);
    timeDelta = 0.5f;
    SaveGame_updateTimes();
    assert(SaveGame_gplayDidTimeExpire(7));
    assert(gSaveGameState.runtime.timeEntryCount == 1);
    assert(gSaveGameState.runtime.timeEntries[0].objId == 9);
    assert(SaveGame_gplayGetTimeRemaining(9) == 29.5f);
    timeDelta = 30.0f;
    SaveGame_updateTimes();
    assert(gSaveGameState.runtime.timeEntryCount == 0);
    for (int i = 0; i < 256; i++) SaveGame_gplayAddTime(i, 1.0f);
    assert(gSaveGameState.runtime.timeEntryCount == 256);
    SaveGame_gplayAddTime(256, 5.0f);
    SaveGame_gplayAddTime(0, 5.0f); /* retail rejects replacements when full too */
    assert(gSaveGameState.runtime.timeEntryCount == 256);
    assert(SaveGame_gplayDidTimeExpire(256));
    assert(SaveGame_gplayGetTimeRemaining(0) == 20.0f);
    timeDelta = 21.0f;
    SaveGame_updateTimes();
    assert(gSaveGameState.runtime.timeEntryCount == 0);
    for (size_t i = 0; i < sizeof(gSaveGameState.runtime.unknown804); i++) {
        assert(gSaveGameState.runtime.unknown804[i] == 0xa5);
    }
}

int main(void) {
    assert(sizeof(void*) == 8);
    gSaveGameWorkBuffer = malloc(sizeof(*gSaveGameWorkBuffer));
    assert(gSaveGameWorkBuffer);
    checkpoints();
    timers();
    free(gSaveGameWorkBuffer);
    return 0;
}
"""


def record(path, name):
    source = (ROOT / path).read_text()
    match = re.search(rf"typedef struct {name}\s*\{{.*?\}} {name};", source, re.S)
    if match is None:
        raise ValueError(f"record definition not found: {name}")
    return match[0]


def harness():
    source = (ROOT / "src/dlls/engine/23/23.c").read_text()
    state = (ROOT / "include/main/dll/savegame_state.h").read_text()
    parts = [PRELUDE]
    for path, name in (
        ("include/main/dll/player_state.h", "PlayerStatus"),
        ("include/main/mapEventTypes.h", "TrickyStats"),
        ("include/main/dll/savegame_env_api.h", "SaveGameEnvState"),
    ):
        parts.append(record(path, name))
    parts.append(re.sub(r"^#include[^\n]*", "", state, flags=re.M))
    for name in ("gSaveGameState", "gSaveGameWorkBuffer", "pRestartPoint"):
        parts.append(re.search(rf"^SaveGame\w+\*? {name};$", source, re.M)[0])
    for name in ("SAVEGAME_ACTIVE_SIZE", "SAVEGAME_CHARACTER_POSITION"):
        parts.append(re.search(rf"^#define {name}[^\n]*(?:\\\n[^\n]*)*", source, re.M)[0])
    bits = (ROOT / "include/main/gamebit_ids.h").read_text()
    parts.append("enum { " + re.search(r"GAMEBIT_CF_DoStandUpAnim = [^,]+", bits)[0] + " };")
    parts.append(SERVICES)
    for name in (
        "SaveGame_gplaySavePoint", "SaveGame_gplayRestartPoint",
        "SaveGame_gplayClearRestartPoint", "SaveGame_gplayGetRestartGameNotCleared",
        "SaveGame_gplayAddTime", "SaveGame_gplayDidTimeExpire",
        "SaveGame_gplayGetTimeRemaining", "SaveGame_updateTimes",
    ):
        start, end = find_function_body(source, name)
        declaration = source.rfind("\n", 0, source.rfind(name, 0, start)) + 1
        parts.append(source[declaration:end + 1])
    return "\n".join(parts + [CASES])


class SaveGameStateTests(unittest.TestCase):
    def test_native_checkpoints_and_timers(self):
        with tempfile.TemporaryDirectory(prefix="savegame-state-") as directory:
            source = Path(directory) / "savegame.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "savegame"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        # The retail task-count assertions deliberately store to null.
                        "-Wno-unused-parameter", "-Wno-null-dereference",
                        "-fsanitize=address,undefined", str(source),
                        "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
