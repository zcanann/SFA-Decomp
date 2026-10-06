#!/usr/bin/env python3
"""Exercise the complete map loader with native pointers and service spies.

The two neighbouring-global address views are host allocations in this fixture;
this is not a native registry implementation or an asset decoder. DVD callbacks
are captured, not executed. Unchecked allocation failures deliberately record
retail's NULL destination submission without having the DVD spy dereference it.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;
typedef int16_t s16;
typedef struct DVDFileInfo { u32 length; int index; } DVDFileInfo;
typedef void (*DVDCallback)(s32, DVDFileInfo*);
"""
CALLBACKS = ('animCurvReadCb', 'animCurvTabReadCb', 'voxMapReadCb', 'voxMapTabReadCb',
             'blocksReadCb', 'blocksTabReadCb', 'modelsReadCb', 'modelsTabReadCb',
             'animReadCb', 'animTabReadCb', 'tex0readCb', 'tex0tab1readCb', 'tex0tab2readCb',
             'tex1ReadCb', 'tex1tab1readCb', 'tex1tab2readCb')
SERVICES = r"""
static struct MldfNames nameView;
static struct MldfTables resourceView;
#define sResourceFileNameAudioTab ((char*)&nameView)
#define gResourceFileTable ((u8*)&resourceView)
static char mapNames[73][8], fileNames[88][8];
static s16 gForceNextLoadSync;
static int gForceLoadImmediately, gModelsArchiveLoadCount;
static u32 gAssetLoadInFlightFlags;
static void* pool;
static void** gDvdFileInfoPool = &pool;
static DVDFileInfo files[8];
static int pops, opens, allocations, frees, invalidations, reads, asyncs, closes, pushes, merges, restructs, romLoads;
static int failAllocation, statuses[8], lengths[8], allocatedSizes[8];
static void* allocated[8];
static int released[8];
static char paths[8][56];
static DVDCallback submitted[8];
static int storedBeforeSubmit[8], romMaps[8];
static void* destinations[8];
static DVDFileInfo* readInfos[8];
static int events[64], eventCount;
enum { FREE=1, ROM, POP, OPEN, ALLOC, INVALIDATE, READ, CLOSE, PUSH, MERGE, RESTRUCT, ASYNC };
static void event(int id) { assert(eventCount < 64); events[eventCount++] = id; }
static void* AtomicSList_Pop(void** p) {
    assert(p == gDvdFileInfoPool && pops < 8); event(POP); return &files[pops++];
}
static void AtomicSList_Push(void** p, DVDFileInfo* file) {
    assert(p == gDvdFileInfoPool && file >= files && file < files + pops); pushes++; event(PUSH);
}
static int DVDOpen(char* path, DVDFileInfo* file) {
    assert(opens < 8 && strlen(path) < 56); strcpy(paths[opens], path);
    file->index = opens; file->length = lengths[opens]; event(OPEN); return statuses[opens++];
}
static void* mmAlloc(int size, u32 tag, const char* allocationName) {
    assert(size >= 0 && size <= 256 && tag == 0x7d7d7d7d && allocationName == 0 && allocations < 8);
    void* result = failAllocation ? NULL : malloc(size + 16);
    assert(failAllocation || (result && (uintptr_t)result > UINT32_MAX));
    if (result) memset(result, 0xa7, size + 16);
    allocated[allocations] = result; allocatedSizes[allocations++] = size; event(ALLOC); return result;
}
static void mm_free(void* p) {
    int found = -1;
    for (int i = 0; i < allocations; i++) if (allocated[i] == p) found = i;
    assert(found >= 0 && p && !released[found]); released[found] = 1; free(p); frees++; event(FREE);
}
static void DCInvalidateRange(void* p, int size) {
    assert(allocations && p == allocated[allocations - 1] && size >= 0 && size <= allocatedSizes[allocations - 1]);
    invalidations++; event(INVALIDATE);
}
static void DVDRead(DVDFileInfo* file, void* p, int size, int offset) {
    assert(reads < 8 && file >= files && file < files + pops && offset == 0);
    assert(size == (int)file->length && allocations && p == allocated[allocations - 1]);
    if (p) memset(p, 0x6b, size);
    destinations[reads] = p; readInfos[reads++] = file; event(READ);
}
static void DVDReadAsyncPrio(DVDFileInfo* file, void* p, int size, int offset, DVDCallback callback, int priority) {
    assert(priority == 2); DVDRead(file, p, size, offset);
    int stored = 0;
    for (int i = 0; i < 88; i++) if (resourceView.workspace.fileInfo[i] == file) stored++;
    storedBeforeSubmit[asyncs] = stored; submitted[asyncs++] = callback; event(ASYNC);
}
static void DVDClose(DVDFileInfo* file) { assert(file); closes++; event(CLOSE); }
static int mergeTableFiles(void* table, int a, int b, int count) {
    assert(table == getMergedTable(a) && b == getOtherTable(a) && count == getMergedCount(a));
    merges++; event(MERGE); return 1;
}
static void texRestructRefs(int value) { assert(value == 1); restructs++; event(RESTRUCT); }
static void piRomLoadSection(int offset, int map, void* destination) {
    assert(offset == 0 && !destination && romLoads < 8); romMaps[romLoads++] = map; event(ROM);
}
static void cleanup(void) {
    for (int i = 0; i < allocations; i++) if (allocated[i] && !released[i]) {
        for (int j = 0; j < 16; j++) assert(((u8*)allocated[i])[allocatedSizes[i] + j] == 0xa7);
        free(allocated[i]);
    }
}
static void reset(void) {
    memset(&nameView, 0, sizeof(nameView)); memset(&resourceView, 0, sizeof(resourceView));
    memset(released, 0, sizeof(released)); memset(files, 0, sizeof(files));
    for (int i = 0; i < 88; i++) {
        snprintf(fileNames[i], sizeof(fileNames[i]), "f%d", i); nameView.fileNames[i] = fileNames[i];
        resourceView.ids[i] = -1; resourceView.owners[i] = -1; resourceView.sizes[i] = 37;
    }
    for (int i = 0; i < 73; i++) { snprintf(mapNames[i], sizeof(mapNames[i]), "m%d", i); nameView.mapNames[i] = mapNames[i]; }
    for (int i = 0; i < (int)(sizeof(nameView.adjacency)/sizeof(nameView.adjacency[0])); i++) nameView.adjacency[i] = -1;
    for (int i = 0; i < 75; i++) nameView.remapGroups[i] = -1;
    nameView.remapGroups[8] = 7; nameView.remapGroups[9] = 8; nameView.remapGroups[4] = 3;
    strcpy(nameView.fmtAnimCurvBin, "%s/animcurv.bin"); strcpy(nameView.fmtAnimCurvTab, "%s/animcurv.tab");
    strcpy(nameView.fmtVoxmapBin, "%s/voxmap.bin"); strcpy(nameView.fmtVoxmapTab, "%s/voxmap.tab");
    strcpy(nameView.fmtWarlockVoxmap, "warlock/voxmap.bin");
    strcpy(nameView.fmtModBin, "%s/mod%d.zlb.bin"); strcpy(nameView.fmtModTab, "%s/mod%d.tab");
    for (int i = 0; i < 8; i++) { statuses[i] = 1; lengths[i] = 128; }
    pops = opens = allocations = frees = invalidations = reads = asyncs = closes = pushes = merges = restructs = romLoads = 0;
    gForceNextLoadSync = gForceLoadImmediately = gModelsArchiveLoadCount = 0;
    gAssetLoadInFlightFlags = 0; failAllocation = eventCount = 0;
}
"""
METADATA = r"""
typedef struct Spec {
    int ids[2]; u32 flags[2]; DVDCallback callbacks[2];
    int tables[2], count, extra, retry;
} Spec;
static const Spec specs[] = {
 {{13,85},{0x10000000,0x40000000},{animCurvReadCb,animCurvReadCb},{14,86},8144,0,1},
 {{14,86},{0x20000000,0x80000000},{animCurvTabReadCb,animCurvTabReadCb},{14,86},8144,0,0},
 {{27,84},{0x1000000,0x4000000},{voxMapReadCb,voxMapReadCb},{26,83},2048,0,0},
 {{26,83},{0x2000000,0x8000000},{voxMapTabReadCb,voxMapTabReadCb},{26,83},2048,0,0},
 {{37,71},{0x10000,0x40000},{blocksReadCb,blocksReadCb},{38,72},2048,0,1},
 {{38,72},{0x20000,0x80000},{blocksTabReadCb,blocksTabReadCb},{38,72},2048,0,0},
 {{43,70},{1,2},{modelsReadCb,modelsReadCb},{42,69},2048,0,1},
 {{42,69},{4,8},{modelsTabReadCb,modelsTabReadCb},{42,69},2048,0,0},
 {{48,74},{0x10,0x20},{animReadCb,animReadCb},{47,73},3000,0,1},
 {{47,73},{0x40,0x80},{animTabReadCb,animTabReadCb},{47,73},3000,0,0},
 {{35,77},{0x100,0x200},{tex0readCb,tex0readCb},{36,78},4096,32,1},
 {{36,78},{0x400,0x800},{tex0tab1readCb,tex0tab2readCb},{36,78},4096,32,0},
 {{32,75},{0x1000,0x2000},{tex1ReadCb,tex1ReadCb},{33,76},4096,32,1},
 {{33,76},{0x4000,0x8000},{tex1tab1readCb,tex1tab2readCb},{33,76},4096,0,0},
};
static void* getMergedTable(int id) {
    switch (id) {
    case 14: return resourceView.workspace.mergeAnimCurv;
    case 26: return resourceView.workspace.mergeVoxMap;
    case 38: return resourceView.workspace.mergeBlocks;
    case 42: return resourceView.workspace.mergeModels;
    case 47: return resourceView.workspace.mergeAnim;
    case 36: return resourceView.workspace.mergeTex0;
    case 33: return resourceView.workspace.mergeTex1;
    default: abort();
    }
}
static int getOtherTable(int id) {
    for (int i = 0; i < 14; i++) if (specs[i].tables[0] == id) return specs[i].tables[1];
    abort();
}
static int getMergedCount(int id) {
    for (int i = 0; i < 14; i++) if (specs[i].tables[0] == id) return specs[i].count;
    abort();
}
static void checkPath(int index, int kind, int map, int id, int fallback) {
    char expected[56];
    const char* suffixes[] = {"animcurv.bin","animcurv.tab","voxmap.bin","voxmap.tab"};
    if (fallback) strcpy(expected, "warlock/voxmap.bin");
    else if (kind < 4) snprintf(expected, sizeof(expected), "m%d/%s", map, suffixes[kind]);
    else if (kind < 6) snprintf(expected, sizeof(expected), kind == 4 ? "m%d/mod%d.zlb.bin" : "m%d/mod%d.tab", map, map > 4 ? map + 1 : map);
    else snprintf(expected, sizeof(expected), "m%d/f%d", map, id);
    assert(strcmp(paths[index], expected) == 0);
}
"""
CASES = r"""
static void checkLoad(int kind, int requested, int bank, int mode, int stale, int failure, int busy, int map) {
    reset(); const Spec* spec = &specs[kind];
    int slot = spec->ids[bank], id = spec->ids[requested];
    if (bank) resourceView.owners[spec->ids[0]] = 99;
    if (stale) resourceView.ptrs[slot] = mmAlloc(64, 0x7d7d7d7d, 0);
    struct MldfTables before = resourceView;
    gForceNextLoadSync = mode == 1; gForceLoadImmediately = mode == 2;
    u32 pending = busy ? specs[kind | 1].flags[0] | specs[kind | 1].flags[1] : 0;
    gAssetLoadInFlightFlags = pending;
    if (failure == 1) for (int i = 0; i < 8; i++) statuses[i] = 0;
    failAllocation = failure == 2; eventCount = 0;
    void* result = mapLoadDataFile(map, id);
    int allocatedNow = failure != 1;
    int stopped = failure == 1 || (failure == 2 && spec->retry);
    int submittedRead = !stopped;
    assert(opens == (kind == 2 && failure == 1 ? 2 : 1) && pops == 1);
    assert(allocations == stale + allocatedNow && frees == stale && invalidations == allocatedNow);
    assert(reads == submittedRead && asyncs == (submittedRead && mode == 0));
    assert(closes == ((failure == 2 && spec->retry) || (submittedRead && mode != 0)) && pushes == closes);
    assert(restructs == (failure == 2 && spec->retry));
    assert(merges == (submittedRead && mode != 0 && !busy));
    assert(gForceNextLoadSync == 0 && gModelsArchiveLoadCount == (kind == 6 && submittedRead));
    assert(gAssetLoadInFlightFlags == (pending | (submittedRead && mode == 0 ? spec->flags[bank] : 0)));
    assert(result == (failure ? NULL : allocated[stale]));
    assert(resourceView.ptrs[slot] == result);
    assert(resourceView.owners[slot] == (stopped ? -1 : map));
    assert(resourceView.ids[slot] == (failure == 2 && spec->retry ? map : -1));
    assert(resourceView.sizes[slot] == (failure == 1 ? 37 : failure == 2 && spec->retry ? 0 : 128));
    if (allocatedNow) assert(allocatedSizes[stale] == 128 + spec->extra);
    if (asyncs) {
        assert(submitted[0] == spec->callbacks[bank] && resourceView.workspace.fileInfo[slot] == &files[0]);
        assert(storedBeforeSubmit[0] == (kind > 1));
    } else assert(resourceView.workspace.fileInfo[slot] == NULL);
    for (int i = 0; i < 88; i++) if (i != slot) {
        assert(resourceView.ptrs[i] == before.ptrs[i] && resourceView.owners[i] == before.owners[i]);
        assert(resourceView.ids[i] == before.ids[i] && resourceView.sizes[i] == before.sizes[i]);
        assert(resourceView.workspace.fileInfo[i] == before.workspace.fileInfo[i]);
    }
    checkPath(0, kind, map, id, 0);
    if (opens == 2) checkPath(1, kind, map, id, 1);
    assert(romLoads == (kind == 5));
    if (romLoads) assert(romMaps[0] == (map == 3 ? 4 : 8));
    int expected[32], n = 0;
    if (stale) expected[n++] = FREE;
    if (kind == 5) expected[n++] = ROM;
    expected[n++] = POP; expected[n++] = OPEN;
    if (opens == 2) expected[n++] = OPEN;
    if (allocatedNow) {
        expected[n++] = ALLOC; expected[n++] = INVALIDATE;
        if (stopped) { expected[n++] = RESTRUCT; expected[n++] = CLOSE; expected[n++] = PUSH; }
        else {
            expected[n++] = READ;
            if (!mode) expected[n++] = ASYNC;
            else { expected[n++] = CLOSE; expected[n++] = PUSH; if (!busy) expected[n++] = MERGE; }
        }
    }
    assert(eventCount == n && memcmp(events, expected, n * sizeof(int)) == 0);
    cleanup();
}
static void checkCached(int kind, int requested, int bank, int forced) {
    reset(); const Spec* spec = &specs[kind];
    void* resident = resourceView.ptrs[spec->ids[bank]] = mmAlloc(64, 0x7d7d7d7d, 0);
    resourceView.owners[spec->ids[bank]] = 7;
    gForceNextLoadSync = forced; eventCount = 0;
    assert(mapLoadDataFile(7, spec->ids[requested]) == resident);
    assert(gForceNextLoadSync == 0 && eventCount == 0 && allocations == 1);
    cleanup();
}
static void checkPending(int kind, int requested, int bank) {
    reset(); const Spec* spec = &specs[kind];
    resourceView.owners[spec->ids[0]] = resourceView.owners[spec->ids[1]] = 99;
    resourceView.ids[spec->ids[bank]] = 7;
    assert(mapLoadDataFile(7, spec->ids[requested]) == allocated[0]);
    assert(resourceView.owners[spec->ids[bank]] == 7 && resourceView.ids[spec->ids[bank]] == -1);
    assert(resourceView.workspace.fileInfo[spec->ids[bank]] == &files[0]);
    cleanup();
}
static void checkEmpty(int kind) {
    reset(); lengths[0] = 0;
    assert(mapLoadDataFile(7, specs[kind].ids[0]) == NULL);
    assert(allocations == 0 && reads == 0 && closes == 0);
    assert(pushes == (kind == 3) && pops == 1 && resourceView.sizes[specs[kind].ids[0]] == 0);
    cleanup();
}
static void checkVoxFallback(int empty, int fallbackFails) {
    reset(); if (empty) lengths[0] = 0; else statuses[0] = 0;
    statuses[1] = !fallbackFails;
    void* result = mapLoadDataFile(7, 27);
    assert(opens == 2 && pops == 1);
    checkPath(0, 2, 7, 27, 0); checkPath(1, 2, 7, 27, 1);
    assert(reads == !fallbackFails && allocations == !fallbackFails);
    assert(result == (fallbackFails ? NULL : allocated[0]));
    cleanup();
}
static void checkAdjacent(int kind) {
    reset(); nameView.adjacency[7] = 8;
    void* result = mapLoadDataFile(7, specs[kind].ids[0]);
    assert(allocations == 2 && reads == 2 && asyncs == 0 && closes == 2 && pushes == 2 && merges == 2);
    assert(result == allocated[1] && gForceNextLoadSync == 0 && gAssetLoadInFlightFlags == 0);
    assert(resourceView.owners[specs[kind].ids[0]] == 8 && resourceView.owners[specs[kind].ids[1]] == 7);
    checkPath(0, kind, 8, specs[kind].ids[0], 0); checkPath(1, kind, 7, specs[kind].ids[0], 0);
    if (kind == 5) assert(romLoads == 2 && romMaps[0] == 9 && romMaps[1] == 8);
    cleanup();
}
int main(void) {
    int cases = 0;
    for (int kind = 0; kind < 14; kind++) {
        for (int request = 0; request < 2; request++) for (int bank = 0; bank < 2; bank++) {
            for (int forced = 0; forced < 2; forced++) { checkCached(kind, request, bank, forced); cases++; }
            if (specs[kind].retry) { checkPending(kind, request, bank); cases++; }
            for (int mode = 0; mode < 3; mode++) for (int stale = 0; stale < 2; stale++)
                for (int failure = 0; failure < 3; failure++) for (int busy = 0; busy < 2; busy++)
                    for (int map = 3; map <= 7; map += 4) { checkLoad(kind, request, bank, mode, stale, failure, busy, map); cases++; }
        }
        reset(); resourceView.owners[specs[kind].ids[0]] = resourceView.owners[specs[kind].ids[1]] = 99;
        assert(mapLoadDataFile(7, specs[kind].ids[0]) == NULL && eventCount == 0); cleanup(); cases++;
        checkAdjacent(kind); cases++;
    }
    checkEmpty(0); checkEmpty(1); checkEmpty(3); cases += 3;
    for (int empty = 0; empty < 2; empty++) for (int fail = 0; fail < 2; fail++) { checkVoxFallback(empty, fail); cases++; }
    reset(); assert(mapLoadDataFile(7, -1) == NULL && eventCount == 0); cleanup(); cases++;
    printf("%d complete map loader cases checked\n", cases);
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE]
    for name in ('MldfNames', 'ResourceTableWorkspace', 'MldfTables'):
        parts.append(re.search(rf'struct {name} \{{.*?\n\}};', source, re.S)[0])
    start = source.index('typedef u8 MldfArenaBlock')
    parts.append(source[start:source.index('\n};', start) + 3])
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts.append(re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0])
    for name in ('MLDF_ID_RT', 'MLDF_OWNER_RT', 'MLDF_PTR_RT', 'DVD_FI_LENGTH'):
        parts.append(re.search(rf'^#define {name}\b(?:[^\n]*\\\n)*[^\n]*', source, re.M)[0])
    parts.append(re.search(r'^char sArchivePathFormat[^;]+;', source, re.M)[0])
    parts.append('static void* getMergedTable(int); static int getOtherTable(int); static int getMergedCount(int);')
    for callback in CALLBACKS:
        parts.append(f'static void {callback}(s32 result, DVDFileInfo* file) {{ (void)result; (void)file; abort(); }}')
    parts.extend([SERVICES, METADATA, function(source, 'mapLoadDataFile'), CASES])
    return '\n'.join(parts)


class MapResourceLoadingTests(unittest.TestCase):
    def test_complete_native_map_loader(self):
        with tempfile.TemporaryDirectory(prefix='map-resource-loading-') as directory:
            directory = Path(directory)
            source = directory / 'map-loader.c'
            source.write_text(harness())
            for version in ('VERSION_GSAE01', 'VERSION_GSAP01'):
                for optimization in ('-O0', '-O2'):
                    with self.subTest(version=version, optimization=optimization):
                        executable = directory / 'map-loader'
                        subprocess.run(['clang', '-std=c11', optimization, '-D' + version,
                                        '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
                                        '-Wno-format-security', '-fsanitize=address,undefined',
                                        str(source), '-o', str(executable)], check=True, timeout=30)
                        subprocess.run([str(executable)], check=True, timeout=30,
                                       env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
