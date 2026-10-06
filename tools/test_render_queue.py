#!/usr/bin/env python3
"""Execute queue producers, sorting, dispatch and effect-pool routing natively.

Production records and function bodies use pointers above 4 GiB. Camera,
frustum and draw services are controlled fixtures; this is not a GPU test or
a native execution test of the rest of the effect simulation.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_map_page_loading import PRELUDE
from test_map_block_init import TYPES
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
SERVICES = r'''
typedef float Mtx[3][4]; typedef float (*MtxPtr)[4];
typedef Vec3f Vec;
static MapRenderQueueStorage gLightmapDrawQueue;
static int gLightmapDrawQueueCount,cases,draws,disguised;
static f32 playerMapOffsetX=100,playerMapOffsetZ=-200,framesThisStep=2;
static GameObject objects[1000];
static MapBlockData blocks[1000];
static MapBlockBoundsRec bounds[1000];
static unsigned char pools[80][4000];
static ExpgfxPoolSourcePosition positions[80];
static Mtx view={{1,0,0,3},{0,1,0,5},{0,0,1,7}};
static ExpgfxPlaneOffsets planes[2];
static int visible[80],frustumCalls,drawOrder[2000];
static char events[20000]; static int eventCount;
static void event(char c) { assert(eventCount<19999); events[eventCount++]=c; events[eventCount]=0; }
static void sceneDrawTransparentPolys(void);
static void lightmap_sortTransparentDrawQueue(void);
static void lightmap_queueExternalRenderEntry(void*,u32,f32*);
static f32* Camera_GetViewMatrix(void) { return &view[0][0]; }
static void PSMTXMultVec(MtxPtr m,Vec* src,Vec* dst) {
    Vec v=*src;
    dst->x=m[0][0]*v.x+m[0][1]*v.y+m[0][2]*v.z+m[0][3];
    dst->y=m[1][0]*v.x+m[1][1]*v.y+m[1][2]*v.z+m[1][3];
    dst->z=m[2][0]*v.x+m[2][1]*v.y+m[2][2]*v.z+m[2][3];
}
static void PSMTXConcat(MtxPtr a,MtxPtr b,MtxPtr result) {
    assert(a==view);
    for (int row=0;row<3;row++) for (int col=0;col<4;col++) {
        result[row][col]=col==3 ? a[row][3] : 0;
        for (int k=0;k<3;k++) result[row][col]+=a[row][k]*b[k][col];
    }
}
static void OSs16tof32(s16* from,f32* to) { *to=*from; }
static ExpgfxPlaneOffsets* Expgfx_GetPlaneOffsets(int set) { assert(set<2); return &planes[set]; }
static int frustumTestAabbWithPlaneOffsets(float x0,float x1,float y0,float y1,float z0,float z1,f32* p) {
    int i=(int)y0; assert(i>=0 && i<80); frustumCalls++;
    assert(x0==i-playerMapOffsetX && x1==i+2-playerMapOffsetX && y1==i+4);
    assert(z0==-i*20-playerMapOffsetZ && z1==-i*20+6-playerMapOffsetZ);
    assert(p==planes[gExpgfxPoolPlaneOffsetSetIds[i]].offsets);
    return visible[i];
}
static void drawGlow(void* pool,int index) {
    assert(index>=0 && index<80 && pool==pools[index] && (uintptr_t)pool>UINT32_MAX);
    assert(draws<2000); drawOrder[draws++]=index; event('G');
}
static GameObject* Obj_GetPlayerObject(void) { return &objects[0]; }
static void* Obj_GetActiveModel(GameObject* object) { assert(object>=objects && object<objects+1000); return object; }
static int playerIsDisguised(GameObject* object) { assert(object==objects); return disguised; }
static void playerRenderFuzz(GameObject* object,int a,int b) { assert(object==objects && a==1 && b==1); event('P'); }
static void objRenderFuzz(GameObject* object) { assert(object==objects+1); event('F'); }
static void lightmapDrawQueuedObject(GameObject* object) { assert(object==objects); event('O'); }
static void Camera_ApplyDecalViewport(void) { event('D'); }
static void Camera_ApplyFullViewport(void) { event('V'); }
static void objShadowRender(GameObject* object,int a,int b,float frames) {
    assert(object==objects && !a && !b && frames==2); event('S');
}
static void objDrawGroundShadow(GameObject* object,void* model) { assert(object==objects && model==object); event('H'); }
enum { GX_COLOR0,GX_TRUE,GX_SRC_REG,GX_SRC_VTX,GX_LIGHT_NULL,GX_DF_NONE,GX_AF_NONE,GX_ALPHA0,GX_FALSE };
static void GXSetChanCtrl(int chan,int enable,int ambient,int material,int lights,int diffuse,int attenuation) {
    assert((chan==GX_COLOR0 && enable==GX_TRUE) || (chan==GX_ALPHA0 && enable==GX_FALSE));
    assert(ambient==GX_SRC_REG && material==GX_SRC_VTX && lights==GX_LIGHT_NULL);
    assert(diffuse==GX_DF_NONE && attenuation==GX_AF_NONE);
}
static void lightmapSetObjAmbColor(void) {}
static void setupToRenderMapBlock(MapBlockData* block,float* matrix) {
    assert(block==blocks && matrix[3]==view[0][3]+block->transform[0][3]);
    assert(matrix[7]==view[1][3]+block->transform[1][3] && matrix[11]==view[2][3]+block->transform[2][3]);
}
#define BLOCK_DRAW(name,code) static void name(MapBlockBoundsRec* b,MapBlockData* block,float* m) { \
    assert(b==bounds && block==blocks); setupToRenderMapBlock(block,m); event(code); }
BLOCK_DRAW(mapBlockRenderTransparent,'T') BLOCK_DRAW(mapBlockRenderWater,'W') BLOCK_DRAW(mapBlockRenderMain,'M')
static void waterFxDraw(void) { event('8'); }
static void waterRender(int a,int b) { assert(!a && !b); event('9'); }
static struct { void (*render)(int,int); } waterTable={waterRender},*waterPointer=&waterTable,**gWaterfxInterface=&waterPointer;
'''
CHECKS = r'''
static u32 randomState=123;
static u32 randomWord(void) { randomState=randomState*1664525u+1013904223u; return randomState; }
static u32 depth(float z) { int value=(int)-z; return value<0 ? 0 : value>0x7ffffff ? 0x7ffffff : value; }
static void reset(void) {
    memset(&gLightmapDrawQueue,0xa5,sizeof(gLightmapDrawQueue));
    gLightmapDrawQueueCount=eventCount=draws=frustumCalls=0; events[0]=0;
}
static void guard(void) {
    for (size_t i=0;i<sizeof(gLightmapDrawQueue.opaqueTail);i++) assert(gLightmapDrawQueue.opaqueTail[i]==0xa5);
}
static void checkSort(int count) {
    reset(); gLightmapDrawQueueCount=count;
    LightmapDrawEntry original[1000]; unsigned char seen[1000]={0};
    for (int i=0;i<count;i++) {
        LightmapDrawEntry* entry=&gLightmapDrawQueue.entries[i];
        entry->arg0.object=&objects[i]; entry->arg1.block=&blocks[i];
        entry->type=i; entry->key=randomWord(); original[i]=*entry;
    }
    lightmap_sortTransparentDrawQueue();
    for (int i=0;i<count;i++) {
        LightmapDrawEntry* entry=&gLightmapDrawQueue.entries[i];
        assert(entry->type<(u32)count && !seen[entry->type]); seen[entry->type]=1;
        assert(memcmp(entry,&original[entry->type],sizeof(*entry))==0);
        if (i) assert(gLightmapDrawQueue.entries[i-1].key>=entry->key);
    }
    if (count<1000) {
        unsigned char* next=(void*)&gLightmapDrawQueue.entries[count];
        for (size_t i=0;i<sizeof(LightmapDrawEntry);i++) assert(next[i]==0xa5);
    }
    guard(); cases++;
}
static void fullQueue(int full) {
    gLightmapDrawQueueCount=full ? 1000 : 0;
    for (int i=0;i<gLightmapDrawQueueCount;i++) {
        gLightmapDrawQueue.entries[i].key=i; gLightmapDrawQueue.entries[i].type=8;
    }
}
static void checkProducers(int full,int parent,float z,u32 selector) {
    reset(); fullQueue(full); float position[3]={2,4,z};
    lightmap_queueExternalRenderEntry(pools[79],79,position);
    LightmapDrawEntry* entry=gLightmapDrawQueue.entries;
    assert(gLightmapDrawQueueCount==1 && eventCount==(full ? 1000 : 0));
    assert(entry->arg0.effectPool==pools[79] && entry->arg1.poolIndex==79 && entry->type==7);
    assert(entry->key==(depth(z)|0x38000000)); guard();
    reset(); fullQueue(full); objects[0].anim.parent=parent ? &objects[1].anim : NULL;
    objects[0].anim.worldPosX=40; objects[0].anim.worldPosY=50; objects[0].anim.worldPosZ=z;
    renderShadowType3(objects,selector,11);
    assert(!gLightmapDrawQueueCount && eventCount==(full ? 1000 : 0));
    assert(entry->arg0.object==objects && entry->key==(depth(z-(parent ? 0 : playerMapOffsetZ)+7-11)|((selector&255)<<27)));
    assert(entry->type==(full ? 8u : 0xa5a5a5a5u)); guard();
    reset(); fullQueue(full);
    bounds[0].minZ=-40; bounds[0].maxZ=24; blocks[0].transform[2][3]=z;
    lightmapQueueShadowRow(bounds,blocks,selector&15);
    assert(!gLightmapDrawQueueCount && eventCount==(full ? 1000 : 0));
    assert(entry->arg0.bounds==bounds && entry->arg1.block==blocks);
    assert(entry->key==(depth(z+6)|((selector&15)<<27)));
    assert(entry->type==(full ? 8u : 0xa5a5a5a5u)); guard(); cases++;
}
static void setupPools(void) {
    for (int i=0;i<80;i++) {
        gExpgfxSlotPoolBases[i]=pools[i];
        gExpgfxPoolBounds[i]=(ExpgfxBounds){i,i+2,i,i+4,-i*20,-i*20+6};
        gExpgfxPoolPlaneOffsetSetIds[i]=i%2; gExpgfxStaticPoolSlotTypeIds[i]=i;
        positions[i]=(ExpgfxPoolSourcePosition){{0},i*2,i*3,-i*40};
    }
}
static void checkPoolRouting(int variant) {
    reset(); setupPools(); int queued=0,culled=0;
    for (int i=0;i<80;i++) {
        gExpgfxPoolActiveCounts[i]=(i+variant)%3 ? 1 : 0;
        gExpgfxPoolSourceModes[i]=(i+variant)/3%3;
        visible[i]=(i+variant)/9%2;
        gExpgfxTrackedPoolSourceIds[i]=(i+variant)%2 ? (ObjAnimComponent*)&positions[i] : NULL;
        if (gExpgfxPoolActiveCounts[i] && !gExpgfxPoolSourceModes[i]) culled++;
    }
    renderParticlesBody();
    for (int i=0;i<80;i++) if (gExpgfxPoolActiveCounts[i] && !gExpgfxPoolSourceModes[i] && visible[i]) {
        LightmapDrawEntry* entry=&gLightmapDrawQueue.entries[queued++];
        float z=gExpgfxTrackedPoolSourceIds[i] ? positions[i].z-(i&0x21) : -i*20+3;
        assert(entry->arg0.effectPool==pools[i] && entry->arg1.poolIndex==(u32)i && entry->type==7);
        assert(entry->key==(depth(z-playerMapOffsetZ+7)|0x38000000));
    }
    assert(gLightmapDrawQueueCount==queued && frustumCalls==culled);
    sceneDrawTransparentPolys(); assert(draws==queued); guard();
    for (int target=0;target<3;target++) for (int mode=0;mode<2;mode++) {
        reset(); int expected=0; culled=0;
        for (int i=0;i<80;i++) {
            gExpgfxTrackedPoolSourceIds[i]=&objects[(i+variant)%3].anim;
            if (gExpgfxPoolActiveCounts[i] && (i+variant)%3==target && gExpgfxPoolSourceModes[i]==mode+1) {
                culled++; if (visible[i]) expected++;
            }
        }
        expgfx_renderSourcePools(&objects[target],mode);
        assert(draws==expected && frustumCalls==culled);
        int cursor=0;
        for (int i=0;i<80;i++) if (gExpgfxPoolActiveCounts[i] && (i+variant)%3==target &&
            gExpgfxPoolSourceModes[i]==mode+1 && visible[i]) assert(drawOrder[cursor++]==i);
        guard();
    }
    cases++;
}
static void checkDispatch(int disguise) {
    reset(); disguised=disguise;
    memset(gExpgfxPoolActiveCounts,0,sizeof(gExpgfxPoolActiveCounts));
    blocks[0].transform[0][0]=blocks[0].transform[1][1]=blocks[0].transform[2][2]=1;
    gLightmapDrawQueueCount=11;
    for (int i=0;i<11;i++) {
        LightmapDrawEntry* entry=&gLightmapDrawQueue.entries[10-i];
        entry->key=100-i; entry->type=i; entry->arg0.object=objects;
        if (i>=4 && i<=6) { entry->arg0.bounds=bounds; entry->arg1.block=blocks; }
        if (i==7) { entry->arg0.effectPool=pools[37]; entry->arg1.poolIndex=37; }
    }
    sceneDrawTransparentPolys();
    assert(strcmp(events,disguise ? "ODSVDHVTWMG89" : "OPDSVDHVTWMG89")==0);
    reset(); gLightmapDrawQueueCount=1; gLightmapDrawQueue.entries[0].type=1;
    gLightmapDrawQueue.entries[0].arg0.object=objects+1; sceneDrawTransparentPolys();
    assert(strcmp(events,"F")==0); guard();
    reset(); setupPools();
    for (int i=0;i<2;i++) {
        gExpgfxPoolActiveCounts[i]=1; gExpgfxPoolSourceModes[i]=i+1;
        gExpgfxTrackedPoolSourceIds[i]=&objects[0].anim; visible[i]=1;
    }
    gLightmapDrawQueueCount=1; gLightmapDrawQueue.entries[0].type=0;
    gLightmapDrawQueue.entries[0].arg0.object=objects; sceneDrawTransparentPolys();
    assert(strcmp(events,"GOG")==0 && draws==2 && drawOrder[0]==0 && drawOrder[1]==1);
    guard(); cases++;
}
int main(void) {
    assert(sizeof(void*)==8 && (uintptr_t)objects>UINT32_MAX && (uintptr_t)pools>UINT32_MAX);
    for (int count=0;count<=1000;count++) checkSort(count);
    float depths[]={-200000000,-1000.25f,-7,0,1000};
    for (int full=0;full<2;full++) for (int parent=0;parent<2;parent++)
    for (int d=0;d<5;d++) for (u32 selector=0;selector<32;selector++) checkProducers(full,parent,depths[d],selector);
    for (int variant=0;variant<54;variant++) checkPoolRouting(variant);
    checkDispatch(0); checkDispatch(1);
    printf("%d native render-queue scenarios passed\n",cases);
}
'''


def record(path, name, kind='struct'):
    text = (ROOT / path).read_text()
    return re.search(rf'typedef {kind} {name}\s*\{{.*?\}} {name};', text, re.S)[0]


def harness():
    shader = (ROOT / 'src/main/shader.c').read_text()
    effects = (ROOT / 'src/dlls/engine/10_expgfx/expgfx.c').read_text()
    header = (ROOT / 'include/main/expgfx_internal.h').read_text()
    parts = [PRELUDE, TYPES, 'typedef struct CollisionPolygonGroup CollisionPolygonGroup; typedef struct Shader Shader;',
             record('include/main/objanim_internal.h', 'ObjAnimComponent'),
             re.search(r'struct GameObject \{.*?\n\};', (ROOT / 'include/game/objects/object.h').read_text(), re.S)[0]]
    for name in ('MapTextureRef', 'MapTriIndex', 'MapHitLine', 'MapBlockBoundsRec', 'MapBlockData'):
        parts.append(record('include/main/map_block.h', name, 'union' if name=='MapTextureRef' else 'struct'))
    for name in ('LightmapDrawEntry', 'MapRenderQueueStorage'):
        parts.append(record('include/main/lightmap_internal.h', name))
    parts.append(re.search(r'typedef union LightmapDrawItem \{.*?\} LightmapDrawItem;', shader, re.S)[0])
    for name in ('ExpgfxBounds', 'ExpgfxPlaneOffsets', 'ExpgfxPoolSourcePosition'):
        parts.append(record('include/main/expgfx_internal.h', name))
    for name in ('EXPGFX_POOL_COUNT', 'EXPGFX_POOL_SOURCE_MODE_STANDALONE',
                 'EXPGFX_POOL_SOURCE_MODE_SOURCE_OFFSET', 'EXPGFX_QUEUE_DEPTH_SLOT_TYPE_MASK'):
        parts.append(re.search(rf'^#define {name}\s+[^\n]+', header, re.M)[0])
    for name in ('gExpgfxSlotPoolBases', 'gExpgfxTrackedPoolSourceIds', 'gExpgfxPoolBounds',
                 'gExpgfxPoolPlaneOffsetSetIds', 'gExpgfxStaticPoolSlotTypeIds',
                 'gExpgfxPoolSourceModes', 'gExpgfxPoolActiveCounts'):
        parts.append(re.search(rf'^\w+\*? {name}\[[^\n]+?\]', effects, re.M)[0] + ';')
    parts += [SERVICES, function(effects, 'expgfx_renderSourcePools'), function(effects, 'renderParticlesBody')]
    for name in ('lightmap_queueExternalRenderEntry', 'lightmap_sortTransparentDrawQueue',
                 'lightmapQueueShadowRow', 'renderShadowType3', 'sceneDrawTransparentPolys'):
        parts.append(function(shader, name))
    return '\n'.join(parts + [CHECKS])


class RenderQueueTests(unittest.TestCase):
    def test_native_queue(self):
        with tempfile.TemporaryDirectory(prefix='sfa-render-queue-') as directory:
            source = Path(directory) / 'queue.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'queue'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
