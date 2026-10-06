#!/usr/bin/env python3
"""Run production collision-line allocation, builders and sorting natively.

Records come from the game. Map lookup and allocation are controlled services;
the separate matching builds cover target layouts and the player consumers.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_map_page_loading import PRELUDE
from test_map_block_init import TYPES
from test_render_queue import record
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
TYPES_EXTRA = r'''
typedef Vec3f Vec;
typedef struct ObjTextureSlotDef ObjTextureSlotDef;
typedef struct ObjHitReactMoveEntry ObjHitReactMoveEntry;
typedef struct ObjAttachPoint ObjAttachPoint;
typedef struct ObjDefHitVolume ObjDefHitVolume;
typedef struct CollisionPolygonGroup CollisionPolygonGroup;
typedef struct Shader Shader;
typedef struct MapDynamicSlot MapDynamicSlot;
'''
SERVICES = r'''
static MapHitLine input[1501];
static MapBlockData block;
static s8 blockIndexes[5][256];
static s16 sortOrder[1500];
static f32 playerMapOffsetX=100,playerMapOffsetZ=-200;
static int hidden,allocations,warnings,cases;
static u8* allocationsRaw[6]; static size_t allocationSizes[6];
static const char sTrackIntersectFuncOverflowFormat[]="track overflow";
static void debugPrintf(const char* text,int value) { assert(text==sTrackIntersectFuncOverflowFormat && value==1); warnings++; }
static int getHudHiddenFrameCount(void) { return hidden; }
static s8* mapGetBlockIdx(int layer) { assert(layer>=0 && layer<5); return blockIndexes[layer]; }
static MapBlockData* mapGetBlock(int index) { assert(index==0); return &block; }
static void* mmAlloc(int bytes,u32 tag,int unused) {
    assert(allocations<6 && bytes>0 && tag==0xffff00ff && !unused);
    u8* raw=malloc(bytes+64); assert(raw && (uintptr_t)raw>UINT32_MAX); memset(raw,0xa5,bytes+64);
    allocationSizes[allocations]=bytes; allocationsRaw[allocations++]=raw; return raw+32;
}
static void guards(void) {
    for (int i=0;i<allocations;i++) for (int j=0;j<32;j++)
        assert(allocationsRaw[i][j]==0xa5 && allocationsRaw[i][32+allocationSizes[i]+j]==0xa5);
}
'''
CHECKS = r'''
static int kind(int i,int variant) {
    int k=(i*7+variant)%20; return k==17 ? 2 : k;
}
static void makeLines(int count,int variant) {
    memset(input,0xa5,sizeof(input));
    for (int i=0;i<count;i++) {
        input[i].x[0]=i; input[i].x[1]=i+1;
        input[i].y[0]=input[i].y[1]=10;
        input[i].z[0]=input[i].z[1]=20;
        input[i].kind=((i*7+variant)%20) | (variant&1 ? 0x80 : 0);
        input[i].flags=i%256; input[i].param=i;
        input[i].endpointData[0]=i%32; input[i].endpointData[1]=(i+1)%32;
    }
}
static void checkInit(void) {
    trackInitCollisionBuffers(); assert(allocations==5);
    assert(allocationSizes[0]==1200*sizeof(TrackTriangle));
    assert(allocationSizes[1]==1500*sizeof(IntersectLine) && allocationSizes[2]==1700*sizeof(Vec));
    assert(allocationSizes[3]==1500*sizeof(s16) && allocationSizes[4]==64*sizeof(MapDynamicSlot));
    assert(gTrackTriangleBuffer==(void*)(allocationsRaw[0]+32) && gIntersectLinePool==(void*)(allocationsRaw[1]+32));
    assert(gIntersectPoints==(void*)(allocationsRaw[2]+32) && gIntersectLineIndexTable==(void*)(allocationsRaw[3]+32));
    assert(gMapDynamicSlots==(void*)(allocationsRaw[4]+32));
    for (int i=0;i<64;i++) {
        MapDynamicSlot expected; memset(&expected,0xa5,sizeof(expected)); expected.cooldown=0;
        assert(memcmp(&expected,&gMapDynamicSlots[i],sizeof(expected))==0);
        gMapDynamicSlots[i].cooldown=2;
    }
    gIntersectLineCount=10; gIntersectPointCount=11; mapBlockFlag=gIntersectRebuildRequested=1;
    trackInitCollisionBuffers(); assert(allocations==5);
    assert(!gIntersectLineCount && !gIntersectPointCount && !mapBlockFlag && !gIntersectRebuildRequested);
    for (int i=0;i<64;i++) assert(!gMapDynamicSlots[i].cooldown);
    guards(); cases++;
}
static void checkMap(int count,int variant,int sort) {
    makeLines(count,variant); memset(blockIndexes,-1,sizeof(blockIndexes));
    blockIndexes[variant%5][3*16+2]=0; block.hits=input; block.hitCount=count;
    memset(gIntersectLinePool,0xa5,1500*sizeof(IntersectLine)); memset(gIntersectPoints,0xa5,1700*sizeof(Vec));
    memset(gIntersectLineIndexTable,0xa5,1500*sizeof(s16)); memset(sortOrder,0xa5,sizeof(sortOrder));
    gIntersectLineSortOrderBuffer=sort ? sortOrder : NULL;
    gIntersectRebuildRequested=1; mapBlockFlag=0; gIntersectRebuildCooldown=0; hidden=variant&1; warnings=0;
    trackIntersect(); int n=count>1500 ? 1500 : count;
    assert(gIntersectLineTableReady && !gIntersectRebuildRequested && !warnings);
    assert(gIntersectRebuildCooldown==(hidden ? 2 : 0));
    assert(gIntersectLineCount==n && gIntersectPointCount==(n ? n+1 : 0));
    for (int i=0;i<n;i++) {
        IntersectLine* line=&gIntersectLinePool[i];
        assert(line->param==i && line->end0==i%32 && line->end1==(i+1)%32);
        assert(line->flags==((i%256)^16) && (line->kind&63)==kind(i,variant));
        assert(line->pt[0]==i && line->pt[1]==i+1 && line->adj[0]==(i ? i-1 : -1));
        assert(line->adj[1]==(i+1<n ? i+1 : -1) && line->pad0E[0]==0xa5 && line->pad0E[1]==0xa5);
    }
    for (int i=0;i<(n ? n+1 : 0);i++) {
        assert(gIntersectPoints[i*3]==i+1380 && gIntersectPoints[i*3+1]==10 && gIntersectPoints[i*3+2]==1740);
    }
    int cursor=0;
    for (int type=19;type>=0;type--) {
        int first=cursor;
        for (int i=0;i<n;i++) if (kind(i,variant)==type) {
            assert(gIntersectLineIndexTable[cursor]==i);
            if (sort) assert(sortOrder[cursor]==i);
            cursor++;
        }
        assert(gIntersectSegmentTypeTable[type*2]==(first==cursor ? 65535 : first));
        assert(gIntersectSegmentTypeTable[type*2+1]==(first==cursor ? 65535 : cursor));
    }
    for (int i=n;i<1500;i++) assert((u16)gIntersectLineIndexTable[i]==0xa5a5 && (u16)sortOrder[i]==0xa5a5);
    if (!sort) for (int i=0;i<n;i++) assert((u16)sortOrder[i]==0xa5a5);
    IntersectLine saved[1500]; memcpy(saved,gIntersectLinePool,sizeof(saved));
    gIntersectLineTableReady=1; trackIntersect(); assert(!gIntersectLineTableReady);
    assert(memcmp(saved,gIntersectLinePool,sizeof(saved))==0);
    mapBlockFlag=1; trackIntersect(); assert(gIntersectRebuildRequested && !mapBlockFlag);
    guards(); cases++;
}
static void checkModel(int count,int variant) {
    makeLines(count,variant); ObjDef definition={0}; definition.modLines=input; definition.modLineCount=count;
    memset(gIntersectLinePool,0xa5,1500*sizeof(IntersectLine));
    intersectModLineBuild(&definition);
    assert(allocations==6 && mapBlockFlag && !gIntersectLineCount && !gIntersectPointCount);
    assert(allocationSizes[5]==(size_t)(count*16+(count ? count+1 : 0)*12+40));
    assert(definition.intersectionLines==(void*)(allocationsRaw[5]+32));
    assert(definition.intersectionPoints==(void*)(allocationsRaw[5]+32+count*16));
    assert(definition.intersectionSegmentRanges==(void*)(allocationsRaw[5]+32+count*16+(count ? count+1 : 0)*12));
    int sourceToSorted[255],cursor=0;
    for (int type=0;type<20;type++) {
        int first=cursor;
        for (int i=0;i<count;i++) if (kind(i,variant)==type) {
            sourceToSorted[i]=cursor; IntersectLine* line=&definition.intersectionLines[cursor++];
            assert(line->param==i && (line->kind&63)==type && line->pt[0]==i && line->pt[1]==i+1);
            assert(line->flags==((i%256)^16) && line->end0==i%32 && line->end1==(i+1)%32);
        }
        TrackModelLineRange range=definition.intersectionSegmentRanges[type];
        assert(range.first==(first==cursor ? 255 : first) && range.end==(first==cursor ? 255 : cursor));
    }
    /* Retail applies ordered label substitutions, including to labels already
     * rewritten. It is not a simultaneous permutation of adjacency indices. */
    int finalLabel[255]; for (int i=0;i<count;i++) finalLabel[i]=i;
    for (int output=0;output<count;output++) {
        int oldLabel=definition.intersectionLines[output].param;
        for (int i=0;i<count;i++) if (finalLabel[i]==oldLabel) finalLabel[i]=output;
    }
    for (int i=0;i<count;i++) {
        IntersectLine* line=&definition.intersectionLines[sourceToSorted[i]];
        assert(line->adj[0]==(i ? finalLabel[i-1] : -1));
        assert(line->adj[1]==(i+1<count ? finalLabel[i+1] : -1));
        assert(gIntersectLinePool[i].kind==20);
    }
    for (int i=0;i<(count ? count+1 : 0);i++) {
        assert(definition.intersectionPoints[i*3]==i && definition.intersectionPoints[i*3+1]==10);
        assert(definition.intersectionPoints[i*3+2]==20);
    }
    GameObject owner={0}; owner.anim.modelInstance=&definition;
    for (int i=0;i<count;i++) {
        trackSetLinesEnabledByParam(i,&owner,0);
        assert(definition.intersectionLines[sourceToSorted[i]].kind&64);
        trackSetLinesEnabledByParam(i,&owner,1);
        assert(!(definition.intersectionLines[sourceToSorted[i]].kind&64));
    }
    guards(); free(allocationsRaw[5]); allocations=5; cases++;
}
int main(void) {
    assert(sizeof(void*)==8); checkInit();
    int counts[]={0,1,2,17,255,1500,1501};
    for (int variant=0;variant<6;variant++) for (int i=0;i<7;i++) for (int sort=0;sort<2;sort++) checkMap(counts[i],variant,sort);
    for (int variant=0;variant<6;variant++) for (int i=0;i<5;i++) checkModel(counts[i],variant);
    for (int i=0;i<5;i++) free(allocationsRaw[i]);
    printf("%d native collision-line storage scenarios passed\n",cases);
}
'''


def records():
    parts = [PRELUDE, TYPES, TYPES_EXTRA]
    for path, name, kind in (
        ('include/main/objanim_internal.h', 'ObjDef', 'struct'),
        ('include/main/objanim_internal.h', 'ObjAnimComponent', 'struct'),
        ('include/main/track_line.h', 'IntersectLine', 'struct'),
        ('include/main/track_line.h', 'TrackModelLineRange', 'struct'),
        ('include/main/map_block.h', 'MapTextureRef', 'union'),
        ('include/main/map_block.h', 'MapHitLine', 'struct'),
        ('include/main/map_block.h', 'MapTriIndex', 'struct'),
        ('include/main/map_block.h', 'MapBlockBoundsRec', 'struct'),
        ('include/main/map_block.h', 'MapBlockData', 'struct'),
        ('include/main/track_dolphin.h', 'TrackTriangle', 'struct'),
    ):
        parts.append(record(path, name, kind))
    parts.append(re.search(r'struct GameObject \{.*?\n\};', (ROOT / 'include/game/objects/object.h').read_text(), re.S)[0])
    source = (ROOT / 'src/main/track_dolphin.c').read_text()
    parts.append(re.search(r'struct MapDynamicSlot \{.*?\n\};', source, re.S)[0])
    return '\n'.join(parts)


def harness():
    source = (ROOT / 'src/main/track_dolphin.c').read_text()
    parts = [records()]
    for name in ('MAP_DYNAMIC_SLOT_COUNT', 'TRACK_TRIANGLE_CAPACITY', 'INTERSECT_LINE_CAPACITY', 'INTERSECT_POINT_CAPACITY'):
        parts.append(re.search(rf'^#define {name}\s+[^\n]+', source, re.M)[0])
    for name in ('gTrackTriangleBuffer', 'gIntersectLinePool', 'gIntersectLineIndexTable', 'gIntersectPoints',
                 'gMapDynamicSlots', 'gIntersectLineCount', 'gIntersectPointCount', 'mapBlockFlag',
                 'gIntersectRebuildRequested', 'gIntersectRebuildCooldown', 'gIntersectLineTableReady',
                 'gIntersectLineSortOrderBuffer', 'gIntersectSegmentTypeTable'):
        parts.append(re.search(rf'^\w+\*? {name}(?:\[[^\n]+?\])?;', source, re.M)[0])
    parts.append(SERVICES)
    for name in ('insertPoint', 'trackGetPooledLine', 'trackSortLineOrder', 'trackInitCollisionBuffers',
                 'trackIntersect', 'intersectModLineBuild', 'trackSetLinesEnabledByParam'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CHECKS])


class TrackLineStorageTests(unittest.TestCase):
    def test_native_storage(self):
        with tempfile.TemporaryDirectory(prefix='sfa-track-line-storage-') as directory:
            source = Path(directory) / 'storage.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'storage'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
