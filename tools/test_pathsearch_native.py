#!/usr/bin/env python3
"""Execute production path search with native pointers and a heap-priority oracle."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef float f32;
#define STATIC_ASSERT(...)
'''

SERVICES = r'''
static RomCurveDef points[254];
static unsigned char bits[2048];
static int bitReads, allocations, frees;
static size_t allocationSize;
static u8* allocation;
static void* lbl_803DCD10;
static char* gPathSearchLastNonTrickyPoint;
static RomCurveDef* getCurve(u32 id) { return id < 254 ? &points[id] : NULL; }
static RomCurveInterface interface = {.getById = getCurve};
static RomCurveInterface* interfacePointer = &interface;
RomCurveInterface** gRomCurveInterface = &interfacePointer;
static int mainGetBit(int id) {
    assert(id >= 0 && id < (int)sizeof(bits));
    bitReads++;
    return bits[id];
}
static f32 vec3f_distanceSquared(f32* a, f32* b) {
    f32 x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2];
    return x*x + y*y + z*z;
}
static void* mmAlloc(int size, int tag, const char* name) {
    assert(!allocation && tag == 0x10 && name == NULL);
    allocationSize = size;
    allocation = malloc(size + 32);
    assert(allocation && (uintptr_t)allocation > UINT32_MAX);
    memset(allocation, 0xa5, size + 32);
    allocations++;
    return allocation;
}
static void mm_free(void* p) {
    assert(p == allocation);
    for (int i = 0; i < 32; i++) assert(allocation[allocationSize + i] == 0xa5);
    free(allocation);
    allocation = NULL;
    frees++;
}
'''

CHECKS = r'''
static int cases;
static u32 randomState;
static u32 nextRandom(void) {
    randomState = randomState * 1664525u + 1013904223u;
    return randomState;
}

static PathSearch* createSearch(void) {
    PathSearch* search = calloc(1, sizeof(*search));
    assert(search && (uintptr_t)search > UINT32_MAX);
    assert((uintptr_t)points > UINT32_MAX);
    pathSearchInit(search);
    assert(allocationSize == 254 * (sizeof(PathSearchNode) + sizeof(PathHeapEntry)) + 100 * sizeof(RomCurveDef*));
    assert((void*)search->nodes == allocation);
    assert((void*)search->heap == allocation + 254 * sizeof(PathSearchNode));
    assert((void*)search->path == allocation + 254 * (sizeof(PathSearchNode) + sizeof(PathHeapEntry)));
    memset(points, 0, sizeof(points));
    memset(bits, 0, sizeof(bits));
    bitReads = 0;
    gPathSearchLastNonTrickyPoint = NULL;
    for (int i = 0; i < 254; i++) {
        points[i].id = i;
        points[i].requiredBit = points[i].forbiddenBit = -1;
        for (int j = 0; j < 4; j++) points[i].linkIds[j] = -1;
        search->nodes[i].point = &points[i];
        search->nodes[i].visited = 0;
    }
    search->heap[0].nodeIndex = 0xffff;
    return search;
}

static void destroySearch(PathSearch* search) {
    void* owned = search->nodes;
    freeAndNull(&owned);
    assert(!owned);
    freeAndNull(&owned);
    free(search);
}

/* Independent oracle: an unordered set of live node IDs and their priorities.
   It does not reproduce either sift algorithm or assume an ordering for ties. */
static void checkHeap(PathSearch* search, const u32* priority, const u8* live, int count) {
    u8 seen[254] = {0};
    u32 maximum = 0;
    assert(search->heapSize == count && search->heap[0].priority == UINT32_MAX);
    assert(search->heap[0].nodeIndex == 0xffff);
    for (int i = 1; i < 254; i++) if (live[i] && priority[i] > maximum) maximum = priority[i];
    for (int i = 1; i <= count; i++) {
        int node = search->heap[i].nodeIndex;
        assert(node > 0 && node < 254 && live[node] && !seen[node]);
        seen[node] = 1;
        assert(search->heap[i].priority == priority[node]);
        assert(search->heap[i / 2].priority >= search->heap[i].priority);
    }
    for (int i = 1; i < 254; i++) assert(seen[i] == live[i]);
    for (int i = 0; i < 254; i++) assert(search->heap[i].padding == 0xa5a5);
    if (count) assert(search->heap[1].priority == maximum);
}

static void heapOperations(void) {
    const int counts[] = {1, 2, 3, 7, 16, 127, 253};
    for (int seed = 0; seed < 25; seed++) {
        for (int variant = 0; variant < 7; variant++) {
            PathSearch* search = createSearch();
            u32 priority[254] = {0};
            u8 live[254] = {0};
            int count = counts[variant];
            randomState = seed;
            for (int i = 1; i <= count; i++) {
                u32 distance = seed == 0 ? 0 : seed == 1 ? UINT32_MAX : nextRandom();
                priority[i] = UINT32_MAX - distance;
                live[i] = 1;
                pathSearchHeapInsert(search, i, distance);
                checkHeap(search, priority, live, i);
            }
            for (int i = 0; i < 24; i++) {
                int node = 1 + nextRandom() % count;
                u32 value = i % 3 == 0 ? 0 : i % 3 == 1 ? UINT32_MAX : nextRandom();
                priority[node] = value;
                pathSearchHeapChangePriority(search->heap, count, node, value);
                checkHeap(search, priority, live, count);
            }
            while (count) {
                u32 maximum = 0;
                for (int i = 1; i < 254; i++) if (live[i] && priority[i] > maximum) maximum = priority[i];
                assert(pathSearchStep(search, 1) == PATH_SEARCH_PENDING);
                int node = search->currentNode;
                assert(live[node] && priority[node] == maximum && search->nodes[node].visited == 1);
                live[node] = 0;
                checkHeap(search, priority, live, --count);
            }
            assert(pathSearchStep(search, 1) == PATH_SEARCH_EXHAUSTED);
            destroySearch(search);
            cases++;
        }
    }
}

static void targetIdentity(void) {
    PathSearch* search = createSearch();
    PathSearchNode node = {.point = &points[253]};
    points[253].type = ROMCURVE_TYPE_TRICKY;
    for (int i = 0; i < 128; i++) {
        points[i].linkIds[2] = 253;
        points[i].linkWalkGroups[2] = 9;
    }
    for (int parent = 0; parent < 256; parent++) {
        node.parentIndex = parent;
        for (int ownGroup = 0; ownGroup < 2; ownGroup++) {
            points[253].walkGroup = ownGroup ? 9 : 0;
            search->target = 9;
            assert(pathSearchNodeMatchesTarget(search, &node) == (parent < 128));
            search->target = 8;
            assert(!pathSearchNodeMatchesTarget(search, &node));
            cases++;
        }
    }
    points[253].type = 0;
    search->target = (ptrdiff_t)&points[253];
    assert(pathSearchNodeMatchesTarget(search, &node));
    search->target = (ptrdiff_t)&points[252];
    assert(!pathSearchNodeMatchesTarget(search, &node));
    f32 target[3] = {0};
    pathSearchBegin(search, &points[253], target, (ptrdiff_t)&points[253], 0);
    assert(search->target == (ptrdiff_t)&points[253]);
    assert(pathSearchStep(search, 1) == PATH_SEARCH_REACHED_TARGET);
    assert(pathSearchBuildPath(search) == 0 && !pathSearchGetNextPoint(search));
    destroySearch(search);
    cases++;
}

static void routes(void) {
    for (int scenario = 0; scenario < 10; scenario++) {
        PathSearch* search = createSearch();
        f32 goal[3] = {2, 0, 0};
        for (int i = 0; i < 3; i++) {
            points[i].type = ROMCURVE_TYPE_TRICKY;
            points[i].x = i;
            points[i].linkIds[0] = i == 2 ? -1 : i + 1;
        }
        points[2].walkGroup = 7;
        int reverse = scenario == 1 ? 1 : 0;
        if (scenario == 1 || scenario == 2) points[0].backwardLinkMask = points[1].backwardLinkMask = 1;
        if (scenario == 3 || scenario == 4) { points[2].requiredBit = 20; bits[20] = scenario == 4; }
        if (scenario == 5 || scenario == 6) { points[2].forbiddenBit = 21; bits[21] = scenario == 5; }
        if (scenario == 7) {
            points[1].subtype = ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B;
            points[2].subtype = ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A;
        }
        if (scenario == 8) points[2].type = 0;
        if (scenario == 9) points[1].linkIds[1] = 0; /* Cycle reaches an already visited node. */
        assert(pathSearchBegin(search, points, goal, 7, reverse | 0x80) == 0);
        assert(search->reverse == reverse && search->nodeCount == 1 && search->heapSize == 1);
        assert(search->nodes[0].distanceToTargetSq == 4 && search->nodes[0].routeCost == 0);
        assert(pathSearchStep(search, 0) == PATH_SEARCH_PENDING && search->heapSize == 1);
        int result = pathSearchStep(search, 10);
        int reached = scenario == 0 || scenario == 1 || scenario == 4 || scenario == 6 || scenario == 9;
        assert(result == (reached ? PATH_SEARCH_REACHED_TARGET : PATH_SEARCH_EXHAUSTED));
        if (reached) {
            assert(search->nodes[2].routeCost == 2 && search->nodes[2].distanceToTargetSq == 0);
            assert(pathSearchBuildPath(search) == 2);
            assert(pathSearchGetNextPoint(search) == &points[1]);
            assert(pathSearchGetNextPoint(search) == &points[2]);
            assert(pathSearchGetNextPoint(search) == NULL);
        }
        assert(gPathSearchLastNonTrickyPoint == (scenario == 8 ? (char*)&points[2] : NULL));
        destroySearch(search);
        cases++;
    }
}

static void existingRoute(void) {
    PathSearch* search = createSearch();
    f32 target[3] = {0};
    search->targetPosition = target;
    search->nodeCount = 2;
    search->nodes[1].routeCost = 100;
    search->nodes[1].distanceToTargetSq = 10;
    pathSearchHeapInsert(search, 1, 110);
    pathSearchAddNeighbor(search, &search->nodes[0], 0, 5, &points[1]);
    assert(search->nodeCount == 2 && search->heapSize == 1);
    assert(search->nodes[1].routeCost == 5 && search->nodes[1].parentIndex == 0);
    /* Retail updates an existing route with raw cost, unlike inverted insertion. */
    assert(search->heap[1].priority == 15);
    destroySearch(search);
    cases++;
}

static void capacities(void) {
    PathSearch* search = createSearch();
    search->currentNode = 129;
    for (int i = 0; i <= 129; i++) search->nodes[i].parentIndex = i ? i - 1 : 0xff;
    assert(pathSearchBuildPath(search) == 100);
    for (int i = 1; i <= 100; i++) assert(pathSearchGetNextPoint(search) == &points[i]);
    assert(!pathSearchGetNextPoint(search) && search->pathIndex == 100);
    search->nodeCount = 254;
    RomCurveDef extra = {0};
    pathSearchAddNeighbor(search, &search->nodes[0], 0, 1, &extra);
    assert(search->nodeCount == 254 && search->heapSize == 0);
    destroySearch(search);
    cases++;
}

int main(void) {
    heapOperations();
    targetIdentity();
    routes();
    existingRoute();
    capacities();
    assert(allocations == frees);
    printf("PASS: %d native path-search cases; heap oracle, target identity, route gates and reconstruction\n", cases);
}
'''


def fixture(source, header):
    def without_includes(text):
        return re.sub(r'^#include.*\n', '', text, flags=re.M)
    curve = (ROOT / 'include/main/dll/rom_curve_def.h').read_text()
    interface = (ROOT / 'include/main/dll/rom_curve_interface.h').read_text()
    curve_types = (ROOT / 'include/main/dll/dll_0015_curves.h').read_text()
    gamebits = (ROOT / 'include/main/gamebit_ids.h').read_text()
    constants = re.search(r'^#define ROMCURVE_TYPE_TRICKY\s+\S+', curve_types, re.M)[0] + '\n'
    constants += '#define GAMEBIT_TrickyPathRelated04E2 ' + re.search(r'GAMEBIT_TrickyPathRelated04E2 = (0x\w+)', gamebits)[1] + '\n'
    return (PRELUDE + without_includes(curve) + without_includes(interface) + without_includes(header)
            + constants + SERVICES + without_includes(source) + CHECKS)


class PathSearchNativeTests(unittest.TestCase):
    def test_native_path_search(self):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('clang is required')
        source = (ROOT / 'src/main/pi_pathsearch.c').read_text()
        header = (ROOT / 'include/main/pi_dolphin_path_api.h').read_text()
        with tempfile.TemporaryDirectory(prefix='sfa-path-search-') as temporary:
            path = Path(temporary) / 'pathsearch.c'
            path.write_text(fixture(source, header))
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    binary = Path(temporary) / 'pathsearch'
                    subprocess.run([compiler, '-std=c11', optimization, '-g', '-ffp-contract=off',
                                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                    str(path), '-o', str(binary)], check=True, timeout=30)
                    subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
