#!/usr/bin/env python3
"""Exercise map layout initialization and stream-slot attachment on native pointers.

Production functions and records are extracted verbatim. Asset IO, page loading,
saved-position lookup and the DVD event loop are controlled service boundaries.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_map_page_loading import PRELUDE
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
SERVICES = r'''
static MapLayoutBuffers gMapLayoutBuffers;
static ShaderRomListSlot gShaderRomListSlots[8];
static s8 gShaderRomListSlotCount,curMapType,curMapLayer;
static s16 lbl_803DCEB6,lbl_803DCEB4;
static MapRomListPage* gLoadedRomListPages[120];
static void* gCurRomListPage;
static int gLastLoadedRomListMapId,gDvdErrorPauseActive;
static s8 gMapLayerOffsets[8]={0,-2,-1,1,2,0,0,0};
static GlobalMapEntry entries[6];
static int fileBytes,allocations,boundsCalls,freed,cases;
static u8* allocated[4];
static const int sizes[4]={1280,512,128,8192};
static int getDataFileSize(int file) { assert(file==MLDF_FILEID_GLOBALMA_BIN); return fileBytes; }
static void loadAssetFileById(void* output,int file) {
    assert(file==MLDF_FILEID_GLOBALMA_BIN); *(GlobalMapEntry**)output=entries;
}
static void* mmAlloc(int bytes,int tag,int unused) {
    assert(allocations<4 && bytes==sizes[allocations] && tag==5 && unused==0);
    u8* p=malloc(bytes+64); assert(p && (uintptr_t)p>UINT32_MAX); memset(p,0xa5,bytes+64);
    allocated[allocations++]=p; return p+32;
}
static void mm_free(void* pointer) { assert(pointer==entries && !freed++); }
static void mapInitSetRects(MapBounds* bounds,u8* bits,int x,int z,int id) {
    assert(bounds==gMapLayoutBuffers.bounds+id && bits==gMapLayoutBuffers.cellBitmaps+id*64);
    *bounds=(MapBounds){x,x+2,z,z+1,-3,4}; bits[0]=0x25; boundsCalls++;
}
static MapRomListPage page;
static u8* objects;
static int requestedMap,expectedIndex,objectOffsets[8],objectTotal,restoredMask;
static int restoreCalls,loads,iterations,errorAt,iteration,eventCount;
static int events[100];
static void event(int e) { assert(eventCount<100); events[eventCount++]=e; }
static int isRomListLoading(void) { return iteration++<iterations; }
static void padUpdate(void) { event(1); }
static void checkReset(void) { event(2); }
static void waitNextFrame(void) { event(3); }
static void loadDataFiles(void) { event(4); }
static void dvdCheckError(void) { event(5); gDvdErrorPauseActive=(iteration==errorAt); }
static void mmFreeTick(int arg) { assert(!arg); event(6); }
static void gameTextRun(void) { event(7); }
static void GXFlush_(int a,int b) { assert(a==1 && b==0); event(8); }
static MapRomListPage* mapGetRomListAndOffsets(int id,int skip) {
    assert(id==requestedMap && skip==0 && !loads++ && iteration==iterations+1);
    assert(gShaderRomListSlotCount>expectedIndex); return &page;
}
static int saveGame_restoreObjectPosToRomList(void* data) {
    assert(restoreCalls<objectTotal && data==objects+objectOffsets[restoreCalls]);
    ObjPlacement* p=data; int saved=(restoredMask>>restoreCalls++)&1;
    if (saved) { p->posX=9001; p->posY=-9002; p->posZ=9003; }
    return saved;
}
'''
CHECKS = r'''
static void checkInit(int length,int sentinel) {
    allocations=boundsCalls=freed=0; memset(&gMapLayoutBuffers,0,sizeof(gMapLayoutBuffers));
    fileBytes=length*sizeof(*entries); memset(entries,0,sizeof(entries));
    for (int i=0;i<6;i++) entries[i]=(GlobalMapEntry){10+i*10,20+i*10,i-2,i*23,i+1,i+2};
    if (sentinel<length) entries[sentinel].mapId=-1;
    curMapType=7; lbl_803DCEB6=8; lbl_803DCEB4=9; initMaps();
    int populated=sentinel<length ? sentinel : length;
    assert(allocations==4 && boundsCalls==populated && freed==1 && gMapLayoutBuffers.unused==-1);
    assert(!curMapType && !lbl_803DCEB6 && !lbl_803DCEB4);
    for (int id=0;id<128;id++) {
        int found=-1;
        for (int i=0;i<populated;i++) if (entries[i].mapId==id) found=i;
        MapBounds expected={-32768,-32768,-32768,-32768,-128,-128};
        int layer=-128,a=-1,b=-1;
        if (found>=0) {
            GlobalMapEntry* e=&entries[found]; expected=(MapBounds){e->originX,e->originX+2,e->originZ,e->originZ+1,-3,4};
            layer=e->layer; a=e->adjacentMapId1; b=e->adjacentMapId2;
        }
        assert(memcmp(&expected,&gMapLayoutBuffers.bounds[id],sizeof(expected))==0);
        assert(gMapLayoutBuffers.layers[id]==layer);
        assert(gMapLayoutBuffers.adjacentMapIds[id*2]==a && gMapLayoutBuffers.adjacentMapIds[id*2+1]==b);
        for (int j=0;j<64;j++) assert(gMapLayoutBuffers.cellBitmaps[id*64+j]==(found>=0 && !j ? 0x25 : 0));
        if (found>=0) {
            curMapLayer=layer;
            for (int z=0;z<2;z++) for (int x=0;x<3;x++)
                assert(mapCoordsToId(expected.minX+x,expected.minZ+z,0)==((0x25>>(x+z*3))&1 ? id : -1));
            assert(mapCoordsToId(expected.minX-1,expected.minZ,0)==-1);
            assert(mapCoordsToId(expected.maxX+1,expected.maxZ,0)==-1);
        }
    }
    for (int i=0;i<4;i++) {
        for (int j=0;j<32;j++) assert(allocated[i][j]==0xa5 && allocated[i][32+sizes[i]+j]==0xa5);
        free(allocated[i]);
    }
    cases++;
}
static void checkStream(int count,int mask,int id,int n,int scenario) {
    MapBounds bounds[128]; s8 layers[128];
    memset(bounds,0,sizeof(bounds)); memset(layers,0,sizeof(layers));
    bounds[id]=(MapBounds){-25,20,17,30,-3,4}; layers[id]=(s8)(scenario-2);
    gMapLayoutBuffers.bounds=bounds; gMapLayoutBuffers.layers=layers;
    memset(&page,0,sizeof(page)); memset(objects,0xa5,512);
    page.originX=3; page.originZ=-4; page.objects=(ObjPlacement*)objects;
    objectTotal=n; int bytes=0;
    for (int i=0;i<n;i++) {
        objectOffsets[i]=bytes; ObjPlacement* p=(ObjPlacement*)(objects+bytes);
        p->size=6+i; p->posX=i+1; p->posY=i+2; p->posZ=i+3; p->ident=100+i;
        bytes+=p->size*4;
    }
    page.objectDataSize=bytes;
    u8 expectedObjects[512]; memcpy(expectedObjects,objects,512);
    memset(gShaderRomListSlots,0xa5,sizeof(gShaderRomListSlots));
    for (int i=0;i<8;i++) gShaderRomListSlots[i].romlist=(mask>>i)&1 ? &gShaderRomListSlots[i] : NULL;
    ShaderRomListSlot expectedSlots[8]; memcpy(expectedSlots,gShaderRomListSlots,sizeof(expectedSlots));
    expectedIndex=0; while (expectedIndex<count && ((mask>>expectedIndex)&1)) expectedIndex++;
    expectedSlots[expectedIndex].romlist=&page; expectedSlots[expectedIndex].slot=id;
    gShaderRomListSlotCount=count;
    for (int i=0;i<120;i++) gLoadedRomListPages[i]=NULL;
    requestedMap=id; gCurRomListPage=NULL; gLastLoadedRomListMapId=-1;
    restoreCalls=loads=eventCount=iteration=0; gDvdErrorPauseActive=0;
    iterations=scenario; errorAt=scenario>1 ? 2 : 0; restoredMask=scenario%2 ? 0x15 : 0x0a;
    int result=mapProcessRomList(id);
    assert(result==expectedIndex && loads==1 && restoreCalls==n);
    assert(gShaderRomListSlotCount==count+(expectedIndex==count));
    assert(memcmp(expectedSlots,gShaderRomListSlots,sizeof(expectedSlots))==0);
    for (int i=0;i<120;i++) assert(gLoadedRomListPages[i]==(i==id ? &page : NULL));
    assert(gCurRomListPage==&page && gLastLoadedRomListMapId==id);
    assert(page.mapLayer==(u8)(scenario-2) && page.worldX==-14080 && page.worldZ==8320);
    for (int i=0;i<n;i++) {
        ObjPlacement* p=(ObjPlacement*)(expectedObjects+objectOffsets[i]);
        if ((restoredMask>>i)&1) { p->posX=9001; p->posY=-9002; p->posZ=9003; }
        else { p->posX+=-14080; p->posZ+=8320; }
    }
    assert(memcmp(expectedObjects,objects,512)==0);
    int expectedEvents[100],num=0;
    for (int i=1;i<=iterations;i++) {
        expectedEvents[num++]=1; expectedEvents[num++]=2;
        if (errorAt && i>errorAt) expectedEvents[num++]=3;
        expectedEvents[num++]=4; expectedEvents[num++]=5;
        if (errorAt && i>errorAt) { expectedEvents[num++]=6; expectedEvents[num++]=7; expectedEvents[num++]=8; }
    }
    assert(eventCount==num && memcmp(expectedEvents,events,num*sizeof(int))==0);
    cases++;
}
static void checkGridBounds(void) {
    MapBounds bounds[128]; memset(bounds,0,sizeof(bounds)); gMapLayoutBuffers.bounds=bounds;
    u32 cells[6]={0},normal[12],visible[12],layers[4]={0},visLayers[4]={0};
    for (int i=0;i<12;i++) { normal[i]=0x01234567u+i*0x11111111u; visible[i]=~normal[i]; }
    page=(MapRomListPage){0}; page.sizeX=3; page.sizeZ=2; page.cells=cells;
    page.cellRects=normal; page.visCellRects=visible; page.layerRects=layers; page.visLayerRects=visLayers;
    bounds[119].minX=-3; bounds[119].minZ=4; gShaderRomListSlots[7].romlist=&page; gShaderRomListSlots[7].slot=119;
    for (int vis=0;vis<2;vis++) for (int z=0;z<2;z++) for (int x=0;x<3;x++) {
        int rect[4][4]; mapGetBlockGridRects(x-3,z+4,rect[0],rect[1],rect[2],rect[3],0,vis,7);
        u32* words=(vis ? visible : normal)+(x+z*3)*2;
        for (int r=0;r<4;r++) {
            u32 v=words[r/2]>>(r%2*16);
            assert(rect[r][0]==(int)((v>>12)&15)-7 && rect[r][1]==(int)((v>>4)&15)-7);
            assert(rect[r][2]==(int)((v>>8)&15)-7 && rect[r][3]==(int)(v&15)-7);
        }
        cases++;
    }
}
int main(void) {
    for (int len=0;len<=6;len++) for (int end=0;end<=6;end++) checkInit(len,end);
    objects=malloc(512); assert(objects && (uintptr_t)objects>UINT32_MAX);
    int ids[]={0,1,63,79,119},counts[]={0,1,5};
    for (int count=0;count<=8;count++) for (int mask=0;mask<(1<<count);mask++) {
        if (count==8 && mask==255) continue; /* Retail requires an available slot. */
        for (int id=0;id<5;id++) for (int n=0;n<3;n++) for (int scenario=0;scenario<5;scenario++)
            checkStream(count,mask,ids[id],counts[n],scenario);
    }
    free(objects); checkGridBounds(); printf("%d native map-streaming scenarios passed\n",cases);
}
'''


def harness():
    shader = (ROOT / 'src/main/shader.c').read_text()
    page = (ROOT / 'include/main/map_romlist_page.h').read_text()
    placement = (ROOT / 'include/game/objects/object_setup.h').read_text()
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts = [PRELUDE, re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0]]
    for source, name in ((placement, 'ObjPlacement'), (page, 'MapRomListPage'),
                         (shader, 'ShaderRomListSlot'), (shader, 'ShaderRomListCursor'),
                         (shader, 'MapBounds'), (shader, 'MapLayoutBuffers'),
                         (shader, 'GlobalMapEntry')):
        parts.append(re.search(rf'typedef struct {name}\s*\{{.*?\}} {name};', source, re.S)[0])
    parts.extend(re.findall(r'^#define MAP_LAYOUT_[^\n]+', shader, re.M))
    parts += [SERVICES]
    parts.extend(function(shader, name) for name in
                 ('initMaps', 'mapCoordsToId', 'mapProcessRomList', 'mapGetBlockGridRects'))
    return '\n'.join(parts + [CHECKS])


class MapStreamingTests(unittest.TestCase):
    def test_native_streaming(self):
        with tempfile.TemporaryDirectory(prefix='map-streaming-') as directory:
            source = Path(directory) / 'stream.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'stream'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
