#!/usr/bin/env python3
"""Run MAPS table lookup, page relocation and bounds setup with native records.

Archive fixtures represent decoded, host-endian headers. IO and decompression
are spies, so this does not claim that raw retail pointer-bearing headers can
be read directly on a native host. The separate corpus check reads retail bytes.
"""
from pathlib import Path
import os
import re
import struct
import subprocess
import tempfile
import unittest

from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32; typedef float f32;
'''
SERVICES = r'''
static MapRomListOffsets table[121];
static MapRomListOffsets* gMapsTab=table;
static MapRomListIndex gMapRomListIndexes[120];
static void* gCurRomListPage;
static void* gResourceFileBuffers[0x58];
static union { max_align_t alignment; u8 bytes[32768]; } archive,info;
static u8* gMapInfoBuffer=info.bytes;
static u8 *allocation,*pageBase;
static int mapId,headerOffset,pageBytes,objectBytes,objectCount,cases,events;
static size_t expectedSize;
static void* mmAlloc(int size,int tag,int unused) {
    assert(size==(int)expectedSize && tag==5 && unused==0 && events++==0);
    allocation=malloc(size+64); assert(allocation); memset(allocation,0xa5,size+64);
    pageBase=allocation+32; assert((uintptr_t)pageBase>UINT32_MAX); return pageBase;
}
static void fileLoadToBufferOffset(int file,void* dst,int offset,int size) {
    assert(file==MLDF_FILEID_MAPS_BIN && dst==pageBase && offset==headerOffset && size==pageBytes);
    assert(events++==1); memcpy(dst,archive.bytes+offset,size);
}
static void getTabEntry(void* dst,int file,int offset,int size) {
    assert(file==MLDF_FILEID_MAPS_BIN && dst==gMapInfoBuffer && offset==headerOffset);
    assert(size==table[mapId].cellRectsOffset-headerOffset);
    memcpy(dst,archive.bytes+offset,size);
}
static void piRomLoadSection(int offset,int id,void* dst) {
    assert(id==mapId && offset==table[id].objectsOffset && events++==2);
    assert(dst==pageBase+offset-headerOffset); memset(dst,0x39,objectBytes);
}
static void mapBuildRomListIndex(MapRomListPage* page,MapRomListIndex* index,int id,int unloading) {
    assert(page==(void*)pageBase && index==&gMapRomListIndexes[mapId] && id==mapId && !unloading);
    assert(events++==3 && page->worldX==0 && page->worldZ==0 && page->mapLayer==0 && page->unk18==0);
    for (int i=0;i<((objectCount+7)>>3)+1;i++) assert(page->loadedObjectBits[i]==0);
}
static void updateGroups(int id) { assert(id==mapId && events++==4); }
static struct { void (*updateObjGroups)(int); } eventTable={updateGroups},*eventPointer=&eventTable,
    **gMapEventInterface=&eventPointer;
static void fixture(int id,int x,int z,int count,int bytes,int variant) {
    mapId=id; headerOffset=128+id*64; objectCount=count; objectBytes=bytes;
    memset(archive.bytes,0xa5,sizeof(archive.bytes)); memset(info.bytes,0xa5,sizeof(info.bytes));
    MapRomListOffsets* t=&table[id];
    t->headerOffset=headerOffset; t->cellsOffset=headerOffset+sizeof(MapRomListPage);
    t->cellRectsOffset=t->cellsOffset+x*z*4; t->visCellRectsOffset=t->cellRectsOffset+x*z*8;
    t->layerRectsOffset=t->visCellRectsOffset+x*z*8;
    t->visLayerRectsOffset=t->layerRectsOffset+variant*16; t->objectsOffset=t->visLayerRectsOffset+variant*16;
    table[id+1].headerOffset=t->objectsOffset+32;
    pageBytes=table[id+1].headerOffset-headerOffset;
    MapRomListPage* page=(MapRomListPage*)(archive.bytes+headerOffset);
    memset(page,0,sizeof(*page)); page->sizeX=x; page->sizeZ=z;
    page->originX=-3; page->originZ=4; page->objectCount=count; page->unk1E=-1234;
    page->objectDataSize=bytes; page->worldX=99; page->worldZ=-88; page->unk18=7; page->mapLayer=6;
    struct PackHeader* pack=(struct PackHeader*)(archive.bytes+t->objectsOffset);
    *pack=(struct PackHeader){0xfacefeed,bytes,8,32};
    u32* cells=(u32*)(archive.bytes+t->cellsOffset);
    for (int i=0;i<x*z;i++) cells[i]=((i+variant)%3 ? 0xffu : (u32)i)<<23;
    gResourceFileBuffers[MLDF_FILEID_MAPS_BIN]=archive.bytes;
    gResourceFileBuffers[MLDF_FILEID_MAPS_TAB]=table;
    expectedSize=pageBytes+((count+7)>>3)+0x401+bytes; events=0;
}
'''
CHECKS = r'''
static void checkPage(int skip) {
    MapRomListPage* page=mapGetRomListAndOffsets(mapId,skip);
    assert(page==(void*)pageBase && gCurRomListPage==page && events==(skip ? 3 : 5));
    u8* expected=malloc(expectedSize); assert(expected); memset(expected,0xa5,expectedSize);
    memcpy(expected,archive.bytes+headerOffset,pageBytes);
    MapRomListOffsets* t=&table[mapId];
    memset(expected+t->objectsOffset-headerOffset,0x39,objectBytes);
    MapRomListPage* e=(MapRomListPage*)expected;
    e->cells=(u32*)(pageBase+t->cellsOffset-headerOffset);
    e->cellRects=(u32*)(pageBase+t->cellRectsOffset-headerOffset);
    e->visCellRects=(u32*)(pageBase+t->visCellRectsOffset-headerOffset);
    e->layerRects=(u32*)(pageBase+t->layerRectsOffset-headerOffset);
    e->visLayerRects=(u32*)(pageBase+t->visLayerRectsOffset-headerOffset);
    e->objects=(ObjPlacement*)(pageBase+t->objectsOffset-headerOffset);
    e->loadedObjectBits=(s8*)(pageBase+pageBytes+objectBytes);
    e->worldX=e->worldZ=0; e->unk18=e->mapLayer=0;
    memset(expected+pageBytes+objectBytes,0,((objectCount+7)>>3)+1);
    assert(memcmp(expected,pageBase,expectedSize)==0);
    for (int i=0;i<32;i++) assert(allocation[i]==0xa5 && allocation[32+expectedSize+i]==0xa5);
    free(expected); free(allocation); cases++;
}
static void checkBounds(int originX,int originZ) {
    MapBounds bounds; memset(&bounds,0xa5,sizeof(bounds));
    u8 bitmap[64],expected[64]; memset(bitmap,0x40,sizeof(bitmap)); memcpy(expected,bitmap,sizeof(bitmap));
    MapRomListPage* header=(MapRomListPage*)(archive.bytes+headerOffset);
    u32* cells=(u32*)(archive.bytes+table[mapId].cellsOffset);
    for (int i=0;i<header->sizeX*header->sizeZ;i++)
        if (((cells[i]>>23)&255)!=255) expected[i/8]|=1<<(i%8);
    mapInitSetRects(&bounds,bitmap,originX,originZ,mapId);
    assert(bounds.minX==originX-header->originX && bounds.minZ==originZ-header->originZ);
    assert(bounds.maxX==bounds.minX+header->sizeX-1 && bounds.maxZ==bounds.minZ+header->sizeZ-1);
    assert(bounds.originX==header->originX && bounds.originZ==header->originZ);
    assert(memcmp(bitmap,expected,sizeof(bitmap))==0);
    assert(((MapRomListPage*)gMapInfoBuffer)->cells==(void*)(gMapInfoBuffer+sizeof(MapRomListPage)));
    cases++;
}
static void checkMetadata(void) {
    for (int present=0;present<4;present++) {
        gResourceFileBuffers[MLDF_FILEID_MAPS_BIN]=present&1 ? archive.bytes : NULL;
        gResourceFileBuffers[MLDF_FILEID_MAPS_TAB]=present&2 ? table : NULL;
        int count=-1,unknown=-2,bytes=-3;
        mapsBinGetRomlistSize(headerOffset,&count,&unknown,&bytes,mapId*7);
        assert(count==(present==3 ? objectCount : -1));
        assert(unknown==(present==3 ? -1234 : -2));
        assert(bytes==(present==3 ? objectBytes : -3)); cases++;
    }
}
int main(void) {
    const int ids[]={0,1,17,116,119},counts[]={0,1,7,8,9,255,4097,32767},bytes[]={0,24,128,1025};
    for (int id=0;id<5;id++) for (int shape=0;shape<4;shape++)
    for (int n=0;n<8;n++) for (int b=0;b<4;b++) {
        fixture(ids[id],shape*2,shape+1,counts[n],bytes[b],shape);
        checkMetadata(); checkPage(0); events=0; checkPage(1); events=0; checkPage(-1);
        checkBounds(-100,57); checkBounds(123,-456);
    }
    printf("%d native map-page scenarios passed\n",cases);
}
'''


def harness():
    page = (ROOT / 'include/main/map_romlist_page.h').read_text()
    placement = (ROOT / 'include/game/objects/object_setup.h').read_text()
    shader = (ROOT / 'src/main/shader.c').read_text()
    pi = (ROOT / 'src/main/pi_dolphin.c').read_text()
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts = [PRELUDE, re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0]]
    for source, name in ((placement, 'ObjPlacement'), (page, 'MapRomListOffsets'),
                         (page, 'MapRomListPage'), (page, 'MapRomListIndex'), (shader, 'MapBounds')):
        parts.append(re.search(rf'typedef struct {name}\s*\{{.*?\}} {name};', source, re.S)[0])
    parts.append(re.search(r'struct PackHeader \{.*?\n\};', pi, re.S)[0])
    parts.extend(re.findall(r'^#define MAP_SECTION_[^\n]+', shader.replace('\\\n', ''), re.M))
    parts += [SERVICES, function(pi, 'mapsBinGetRomlistSize'),
              function(shader, 'mapGetRomListAndOffsets'), function(shader, 'mapInitSetRects'), CHECKS]
    return '\n'.join(parts)


class MapPageTests(unittest.TestCase):
    def test_native_page_and_bounds(self):
        with tempfile.TemporaryDirectory(prefix='map-page-native-') as directory:
            source = Path(directory) / 'page.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'page'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-Wno-shift-op-parentheses', '-fsanitize=address,undefined',
                                    str(source), '-o', str(exe)], check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})

    def test_retail_offset_layout(self):
        directory = ROOT / 'orig/GSAE01/files'
        if not (directory / 'MAPS.tab').exists():
            self.skipTest('EN retail MAPS files unavailable')
        table = (directory / 'MAPS.tab').read_bytes()
        data = (directory / 'MAPS.bin').read_bytes()
        words = struct.unpack(f'>{len(table)//4}i', table)
        populated = object_only = 0
        for index in range((len(words)-1)//7):
            row = words[index*7:index*7+8]
            if len(set(row[:7])) == 1:
                self.assertEqual(row[7]-row[0], 32)
                self.assertEqual(struct.unpack_from('>I', data, row[0])[0], 0xfacefeed)
                object_only += 1
                continue
            self.assertGreaterEqual(row[0], 0)
            self.assertLessEqual(row[0]+56, len(data))
            x, z = struct.unpack_from('>hh', data, row[0])
            self.assertEqual(row[1]-row[0], 56)
            self.assertEqual(row[2]-row[1], x*z*4)
            self.assertEqual(row[3]-row[2], x*z*8)
            self.assertEqual(row[4]-row[3], x*z*8)
            self.assertEqual(row[6]-row[5], row[5]-row[4])
            self.assertLessEqual(row[6]+16, row[7])
            self.assertLessEqual(row[7], len(data))
            self.assertEqual(struct.unpack_from('>I', data, row[6])[0], 0xfacefeed)
            populated += 1
        self.assertGreater(populated, 0)
        print(f'{populated} populated retail map pages and {object_only} object-only entries checked')


if __name__ == '__main__':
    unittest.main()
