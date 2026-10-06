#!/usr/bin/env python3
"""Run the complete production resource loader with native-address fixtures.

The fixture supplies the MldfTables address view as one host allocation; the
retail view spans separate globals. Resident headers are host-endian. DVD,
decompression, packed-animation handling and wait-loop services are spies.
The known invalid animation-curve wait lookup and disk DIR infinite loop are
not exercised. This is not a native resource-registry or asset-decoder port.
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
typedef int16_t s16;
typedef uint32_t u32;
typedef struct DVDFileInfo { u8 opaque[96]; } DVDFileInfo;
"""
SERVICES = r"""
static struct MldfTables arena;
#define gResourceFileTable ((u8*)&arena)
static volatile int gAssetLoadInFlightFlags;
static u8 gDvdErrorPauseActive;
static char sZlbBlockTag[] = "ZLB", sDirBlockTag[] = "DIR";
static char* sResourceFileNameTable[0x58];
static _Alignas(32) u8 banks[2][512], output[256], disk[512];
static u32 tables[2][8];
static int expectedFile, expectedOffset, expectedLength, packed;
static int opens, closes, reads, allocs, frees, stores, inflates, probes, unpacks;
static int polls, loads, pads, resets, frames, ticks, texts, flushes, errors;
static u8* expectedSource;
static u8* expectedDestination;
static u8* allocated;
static u32 allocatedBytes;
static u32 expectedCompressed;
static int dvdTexture;
static int OSDisableInterrupts(void) { polls++; return 7; }
static void OSRestoreInterrupts(int state) { assert(state == 7); }
static void padUpdate(void) { pads++; }
static void checkReset(void) { resets++; }
static void waitNextFrame(void) { frames++; }
static void loadDataFiles(int unused) {
    assert(unused == 0);
    if (++loads == 2) gAssetLoadInFlightFlags = 0x1000000; /* unrelated pending load */
}
static void dvdCheckError(void) { errors++; }
static void mmFreeTick(int mode) { assert(mode == 0); ticks++; }
static void gameTextRun(void) { texts++; }
static void GXFlush_(int a, int b) { assert(a == 1 && b == 0); flushes++; }
static void DVDOpen(char* name, DVDFileInfo* info) {
    assert(name == sResourceFileNameTable[expectedFile] && info);
    assert(opens++ == 0 && reads == 0);
}
static void DVDClose(DVDFileInfo* info) {
    assert(info && opens == 1 && reads == 1 && closes++ == 0);
}
static void* mmAlloc(u32 bytes, u32 tag, const char* allocationName) {
    assert(opens == 1 && tag == 0x7f7f7fff && allocationName == 0 && allocs++ == 0);
    assert(bytes == (u32)((expectedLength + 31) / 32 * 32));
    allocatedBytes = bytes;
    allocated = aligned_alloc(32, bytes + 32);
    assert(allocated && (uintptr_t)allocated > UINT32_MAX);
    memset(allocated, 0xa7, bytes + 32);
    return allocated;
}
static void mm_free(void* pointer) {
    assert(pointer == allocated && frees++ == 0 && reads == 1);
    for (unsigned i = 0; i < 32; i++) assert(allocated[allocatedBytes + i] == 0xa7);
    if (dvdTexture) assert(closes == 1 && stores == 1 && inflates == 1);
    else assert(closes == 0 && stores == 0);
    free(pointer);
}
static void DVDRead(DVDFileInfo* info, void* destination, u32 bytes, int offset) {
    assert(info && opens == 1 && closes == 0 && reads++ == 0);
    assert(offset == expectedOffset && (uintptr_t)destination > UINT32_MAX);
    assert(bytes == (allocs ? allocatedBytes : (u32)expectedLength));
    assert(destination == (allocs ? allocated : expectedDestination));
    memcpy(destination, disk, bytes);
}
static void DCStoreRange(void* pointer, u32 bytes) {
    stores++;
    if (dvdTexture) {
        assert(pointer == allocated && bytes == (u32)expectedLength && closes == 1 && inflates == 0);
    } else if (opens) {
        assert(pointer == expectedDestination && bytes == (u32)expectedLength && closes == 0);
    } else {
        assert(pointer == expectedDestination && bytes == 17 && inflates == 1);
    }
}
static void zlbDecompress(u8* source, int bytes, u8* destination, void* sizeOut) {
    u32 size;
    memcpy(&size, sizeOut, 4);
    assert(source == (dvdTexture ? allocated + 16 : expectedSource));
    assert(bytes == (int)expectedCompressed && destination == expectedDestination && size == 21);
    assert(inflates++ == 0);
    memset(destination, 0x6b, 17);
    size = 17;
    memcpy(sizeOut, &size, 4);
}
static int ObjModel_IsPackedResource(u8* resource) {
    assert(resource == expectedSource && (uintptr_t)resource > UINT32_MAX);
    probes++;
    return packed;
}
static int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize) {
    assert(resource == expectedSource && baseSize == 80 && packed);
    return baseSize + 17;
}
static void ObjModel_UnpackResourcePayload(u8* source, int srcSize, u8* destination, int dstSize) {
    assert(source == expectedSource && srcSize == 80 && dstSize == 97);
    assert(destination == expectedDestination && packed && unpacks++ == 0);
    memset(destination, 0x7c, 97);
}
static void reset(void) {
    memset(&arena, 0, sizeof(arena));
    memset(output, 0xcc, sizeof(output));
    memset(banks, 0x3b, sizeof(banks));
    for (unsigned i = 0; i < sizeof(disk); i++) disk[i] = i * 13 + 7;
    memset(tables, 0, sizeof(tables));
    for (int i = 0; i < 0x58; i++) sResourceFileNameTable[i] = (char*)&banks[0][i];
    gAssetLoadInFlightFlags = gDvdErrorPauseActive = 0;
    opens = closes = reads = allocs = frees = stores = inflates = probes = unpacks = 0;
    polls = loads = pads = resets = frames = ticks = texts = flushes = errors = 0;
    packed = dvdTexture = 0;
    expectedDestination = output + 32;
    expectedLength = 32;
    allocated = NULL;
}
static void word(u8* pointer, unsigned offset, u32 value) { memcpy(pointer + offset, &value, 4); }
static void zlb(u8* header) {
    memcpy(header, "ZLB\0", 4);
    word(header, 8, 21);
    word(header, 12, 14);
}
static void unchanged(void) {
    for (unsigned i = 0; i < sizeof(output); i++) assert(output[i] == 0xcc);
}
"""
CASES = r"""
static void checkResident(int family, int bank, int mode) {
    reset();
    const int primary[] = {0x0d, 0x1b, 0x25, 0x2b, 0x30, 0x23, 0x20, 0x51, 0x4f, 0x2c};
    const int alternate[] = {0x55, 0x54, 0x47, 0x46, 0x4a, 0x4d, 0x4b, 0x51, 0x4f, 0x2c};
    const int tableA[] = {0x0e, 0x1a, 0x26, 0x2a, 0x2f, 0x24, 0x21, 0x52, 0x50, 0};
    const int tableB[] = {0x56, 0x53, 0x48, 0x45, 0x49, 0x4e, 0x4c, 0x52, 0x50, 0};
    const u32 selectB[] = {0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000,
                          0x80000000, 0x80000000, 0, 0, 0};
    int selected = bank ? alternate[family] : primary[family];
    int table = bank ? tableB[family] : tableA[family];
    if (table) arena.ptrs[table] = tables[bank];
    tables[bank][0] = 64;
    tables[bank][1] = 144;
    arena.ptrs[selected] = banks[bank];
    u8* header = banks[bank] + 64;
    expectedSource = header;
    int offset = 64 | (bank ? selectB[family] : 0);
    int dataSize = 80;
    int compressed = family == 1 || family == 2 || family == 5 || family == 6 || family == 8;
    if (compressed) {
        zlb(header);
        expectedSource = header + 16;
        expectedCompressed = 14;
        if (mode == 1) memcpy(header, "DIR\0", 4);
        if (mode == 2) memcpy(header, "BAD\0", 4);
    }
    if (family == 3) {
        word(header, 0, mode == 0 ? 0xe0e0e0e0 : mode == 1 ? 0xfacefeed : 0);
        word(header, 4, 21);
        word(header, 8, 16);
        word(header, 12, 30);
        expectedSource = header + (mode == 1 ? 56 : 40);
        expectedCompressed = 14;
    }
    if (family == 4 || family == 7) packed = mode == 1;
    void* result = loadAndDecompressDataFile(primary[family], expectedDestination, offset, 32,
                                            family == 4 || family == 7 ? &dataSize : NULL, 0, 0);
    assert(opens == 0 && allocs == 0);
    if ((family == 6 || family == 8) && mode == 1) {
        assert(result == header + 32 && inflates == 0 && stores == 0);
        unchanged();
    } else {
        assert(result == NULL);
        if (family == 3 && mode == 0) assert(memcmp(expectedDestination, header + 40, 21) == 0);
        else if ((family == 3 && mode == 1) || (compressed && (mode == 0 || family == 5))) {
            assert(inflates == 1 && stores == 1);
            for (int i = 0; i < 17; i++) assert(expectedDestination[i] == 0x6b);
        } else if ((family == 4 || family == 7) && packed) {
            assert(probes == 1 && unpacks == 1);
        } else if (!compressed && family != 3) assert(memcmp(expectedDestination, header, 32) == 0);
        else unchanged();
    }
    for (int i = 0; i < 32; i++) assert(output[i] == 0xcc);
    for (unsigned i = 160; i < sizeof(output); i++) assert(output[i] == 0xcc);
}
static void checkQuery(int preanim, int bank, int isPacked) {
    reset();
    int file = preanim ? 0x51 : bank ? 0x4a : 0x30;
    int table = preanim ? 0x52 : bank ? 0x49 : 0x2f;
    tables[bank][0] = 0x10000040;
    tables[bank][1] = 0x10000090;
    arena.ptrs[table] = tables[bank];
    arena.ptrs[file] = banks[bank];
    expectedSource = banks[bank] + 64;
    packed = isPacked;
    int size = -1;
    void* result = loadAndDecompressDataFile(preanim ? 0x51 : 0x30, expectedDestination,
                                            64 | (bank ? 0x20000000 : 0), 32, &size, 0, 0x101);
    assert(result == NULL && size == 80 + (packed ? 17 : 0) && probes == 1);
    assert(unpacks == 0 && opens == 0 && inflates == 0);
    unchanged();
}
static void checkSparseQuery(int family, int bank, int shape) {
    reset();
    const int files[] = {0x2b, 0x23, 0x20, 0x4f};
    const int tabA[] = {0x2a, 0x24, 0x21, 0x50};
    const int tabB[] = {0x45, 0x4e, 0x4c, 0x50};
    const u32 data[][5] = {{0, 0, 64, 128, 256}, {0, 64, 64, 128, 256}, {0, 64, 128, 64, 256}};
    memcpy(tables[bank], data[shape], sizeof(data[shape]));
    arena.ptrs[bank ? tabB[family] : tabA[family]] = tables[bank];
    int index = shape == 0 ? 0 : shape == 1 ? 2 : 3;
    int size = -1;
    int offset = tables[bank][index] | (bank ? (family == 0 ? 0x20000000 : 0x80000000) : 0);
    assert(loadAndDecompressDataFile(files[family], expectedDestination, offset, 32, &size, index, 1) == NULL);
    assert(size == (shape == 2 && family != 0 ? 192 : 64));
    assert(opens == 0 && probes == 0 && inflates == 0);
    unchanged();
}
static void checkSparseMatrix(const struct QueryCase* test) {
    reset();
    const int files[] = {0x2b, 0x23, 0x20, 0x4f};
    const int tabA[] = {0x2a, 0x24, 0x21, 0x50};
    const int tabB[] = {0x45, 0x4e, 0x4c, 0x50};
    memcpy(tables, test->entries, sizeof(tables));
    if (test->present & 1) arena.ptrs[tabA[test->family]] = tables[0];
    if (test->present & 2) arena.ptrs[tabB[test->family]] = tables[1];
    arena.workspace.mergeTex0[test->index] = test->merged | 0x07123456u;
    arena.workspace.mergeTex1[test->index] = test->merged | 0x07123456u;
    int size = -1;
    assert(loadAndDecompressDataFile(files[test->family], expectedDestination, test->request | 0x1234,
                                    0, &size, test->index, 0x101) == NULL);
    assert(size == test->expectedSize);
    assert(opens == 0 && probes == 0 && inflates == 0 && loads == 0 && stores == 0);
    assert(memcmp(tables, test->entries, sizeof(tables)) == 0);
    unchanged();
}
static void checkDvd(int texture, int length, int alignment) {
    reset();
    expectedFile = texture ? 0x4b : 0x2c;
    expectedOffset = 64;
    expectedLength = length;
    expectedDestination = output + 32 + alignment;
    dvdTexture = texture;
    if (texture) { zlb(disk); expectedCompressed = 14; }
    void* result = loadAndDecompressDataFile(expectedFile, expectedDestination,
                                            texture ? 0x80000040 : 64, length, NULL, 0, 0);
    assert(result == NULL && opens == 1 && closes == 1 && reads == 1 && stores == 1);
    assert(allocs == !!(texture || alignment || (length & 31)) && frees == allocs);
    if (texture) assert(inflates == 1);
    else assert(memcmp(expectedDestination, disk, length) == 0);
    for (u8* p = output; p < expectedDestination; p++) assert(*p == 0xcc);
    for (u8* p = expectedDestination + (texture ? 17 : length); p < output + sizeof(output); p++) assert(*p == 0xcc);
}
static void checkWait(void) {
    reset();
    arena.ptrs[0x2f] = tables[0];
    arena.ptrs[0x30] = banks[0];
    gAssetLoadInFlightFlags = 0x50;
    gDvdErrorPauseActive = 1;
    expectedSource = banks[0] + 64;
    assert(loadAndDecompressDataFile(0x30, expectedDestination, 0x10000040, 32, NULL, 0, 0) == NULL);
    assert(loads == 2 && pads == 2 && resets == 2 && errors == 2);
    assert(frames == 1 && ticks == 1 && texts == 1 && flushes == 1);
    assert(probes == 1 && memcmp(expectedDestination, expectedSource, 32) == 0);
}
int main(void) {
    for (int family = 0; family < 10; family++) for (int bank = 0; bank < 2; bank++)
        for (int mode = 0; mode < 3; mode++) checkResident(family, bank, mode);
    for (int pre = 0; pre < 2; pre++) for (int bank = 0; bank < 2; bank++)
        for (int mode = 0; mode < 2; mode++) checkQuery(pre, bank, mode);
    for (int family = 0; family < 4; family++) for (int bank = 0; bank < 2; bank++)
        for (int shape = 0; shape < 3; shape++) checkSparseQuery(family, bank, shape);
    for (int length = 0; length <= 65; length++) for (int align = 0; align < 32; align++) checkDvd(0, length, align);
    for (int align = 0; align < 32; align++) checkDvd(1, 40, align);
    for (unsigned i = 0; i < sizeof(queryCases) / sizeof(queryCases[0]); i++) checkSparseMatrix(&queryCases[i]);
    printf("%zu sparse-table and competing-bank query cases checked\n", sizeof(queryCases) / sizeof(queryCases[0]));
    checkWait();
    puts("60 resident, 32 size-query, 2144 DVD and one wait-loop cases checked");
    return 0;
}
"""


def query_fixtures():
    """Use ordered offset lists and an explicit bank-priority contract as oracle."""
    shapes = ((0, 32, 32, 64, 96, 96, 192, 256),
              (0, 32, 64, 32, 96, 64, 192, 256),
              (0, 0, 32, 0, 64, 32, 192, 256))
    rows = []
    for family in range(4):
        for shape in shapes:
            values = (shape, tuple(value * 2 + 16 if value else 0 for value in shape))
            for present in ((1,) if family == 3 else (1, 2, 3)):
                for request in range(1 if family == 3 else 4):
                    for merged in range(4 if family in (1, 2) else 1):
                        if present != 3:
                            bank = 0 if present == 1 else 1
                        elif family == 0:
                            bank = (0, 0, 1, 1)[request]
                        else:
                            bank = (1, 0, 1, 1)[merged]
                        for index in range(7):
                            entries = values[bank]
                            offset = entries[index]
                            start = index
                            if not offset:
                                start = 0
                            elif family == 0 and entries[index - 1] > offset:
                                start = entries.index(offset)
                            size = next(value for value in entries[start:] if value > offset) - offset
                            flag_a = 0x10000000 if family == 0 else 0x40000000
                            flag_b = 0x20000000 if family == 0 else 0x80000000
                            request_bits = (flag_a if request & 1 else 0) | (flag_b if request & 2 else 0)
                            merged_bits = (0x40000000 if merged & 1 else 0) | (0x80000000 if merged & 2 else 0)
                            # The size scan must ignore each entry's high-byte metadata.
                            arrays = ['{' + ','.join(f'0x{value | ((i + bank + 1) << 24):08x}u'
                                                     for i, value in enumerate(table)) + '}'
                                      for bank, table in enumerate(values)]
                            fields = (family, present, f'0x{request_bits:08x}u', f'0x{merged_bits:08x}u', index, size)
                            rows.append('{' + ','.join(map(str, fields)) + ',{' + ','.join(arrays) + '}}')
    assert len(rows) == 2289
    return ('struct QueryCase { int family, present; u32 request, merged; int index, expectedSize; '
            'u32 entries[2][8]; };\nstatic const struct QueryCase queryCases[] = {\n'
            + ',\n'.join(rows) + '\n};\n')


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE]
    for name in ('ResourceTableWorkspace', 'MldfTables'):
        parts.append(re.search(rf'struct {name} \{{.*?\n\}};', source, re.S)[0])
    start = source.index('typedef u8 MldfArenaBlock')
    end = source.index('\n};', start) + 3
    parts.append(source[start:end])
    for name in ('ZlbStreamInfo', 'ZlbHeader', 'PackHeader'):
        parts.append(re.search(rf'struct {name} \{{.*?\n\}};', source, re.S)[0])
    for name in ('MLDF_PTR_RT', 'MLDF_BUFFER_FROM_CURSOR', 'ZLB_HDR'):
        parts.append(re.search(rf'^#define {name}\b[^\n]+', source, re.M)[0])
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts.append(re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0])
    bank_header = (ROOT / 'include/main/rcp_dolphin.h').read_text()
    parts.extend(re.findall(r'^#define TEX_TAB_MAP_[^\n]+', bank_header, re.M))
    parts.extend([SERVICES, function(source, 'loadAndDecompressDataFile'), query_fixtures(), CASES])
    return '\n'.join(parts)


class ResourceLoaderAddressTests(unittest.TestCase):
    def test_native_loader_paths(self):
        with tempfile.TemporaryDirectory(prefix='resource-loader-') as directory:
            source = Path(directory) / 'loader.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / 'loader'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(executable)],
                                   check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
