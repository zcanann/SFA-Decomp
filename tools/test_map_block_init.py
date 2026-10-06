#!/usr/bin/env python3
"""Run map allocation/setup with independent native globals and production records.

Asset loading, streaming, camera/player setup and effect interfaces are spies.
This checks initialization and dispatch contracts, not native game execution.
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
TYPES = r'''
#include <math.h>
typedef struct { f32 x,y,z; } Vec3f;
typedef struct { s16 x,y,z; } Vec3s;
typedef struct GameObject GameObject;
typedef struct Texture Texture;
typedef struct MapBlockData MapBlockData;
typedef struct MapRomListPage MapRomListPage;
typedef struct MapRomListOffsets MapRomListOffsets;
typedef struct ObjDef ObjDef;
typedef struct ObjHitReactState ObjHitReactState;
typedef struct ObjHitboxTransformState ObjHitboxTransformState;
typedef struct ObjModelState ObjModelState;
typedef struct ObjTextureRuntimeSlot ObjTextureRuntimeSlot;
typedef struct ObjHitVolumeRuntimeTransform ObjHitVolumeRuntimeTransform;
typedef struct ObjHitVolumeRuntimeBounds ObjHitVolumeRuntimeBounds;
typedef struct ObjAnimBank ObjAnimBank;
typedef struct ObjMsgQueue ObjMsgQueue;
typedef void (*ObjectInterfaceCallback)(void);
typedef ObjectInterfaceCallback** ObjectInterfaceHandle;
'''
SERVICES = r'''
static u32 renderFlags,gVisibleObjectSortKeys[1024];
static MapBlockData** gMapBlocks;
static s16* gMapBlockIds;
static u8 *gMapBlockRefCounts,*gMapInfoBuffer;
static s8 *gMapBlockLayerTables[5],*gMapBlockCellStateTables[5];
static MapCellEntry* gMapBlockCellEntryTables[5];
static MapRomListPage* gLoadedRomListPages[120];
static MapRomListOffsets* gMapsTab;
static void* gHitsTab;
static u16 *gTrkBlkTab,trackTable[256];
static s16 gTrkBlkTabCount,gPendingWarpIndex,gArrivedWarpIndex;
static MapTextureOverride* gMapTextureOverrides;
static MapTextureScroll* gMapTextureScrolls;
static int allocations,assetLoads,cases;
static u8* raw[9];
static size_t sizes[9];
static void* mmAlloc(int bytes,int tag,int unused) {
    const size_t expected[]={64*sizeof(void*),128,64,0xd48,1280,1280*sizeof(MapCellEntry),1280,
                             80*sizeof(MapTextureOverride),0x3a0};
    assert(allocations<9 && bytes==(int)expected[allocations] && tag==5 && unused==0);
    raw[allocations]=malloc(bytes+64); assert(raw[allocations] && (uintptr_t)raw[allocations]>UINT32_MAX);
    sizes[allocations]=bytes; memset(raw[allocations],0xa5,bytes+64); return raw[allocations++]+32;
}
static void loadAssetFileById(void* output,int file) {
    if (assetLoads==0) { assert(file==MLDF_FILEID_MAPS_TAB && output==&gMapsTab); *(void**)output=trackTable; }
    else if (assetLoads==1) { assert(file==MLDF_FILEID_HITS_TAB && output==&gHitsTab); *(void**)output=trackTable+1; }
    else { assert(assetLoads==2 && file==MLDF_FILEID_TRKBLK_TAB && output==&gTrkBlkTab); *(void**)output=trackTable; }
    assetLoads++;
}
static u8 gWarpArrivalTimer,gMapBlockCount,gMapLoadDeferred,bEnableBlurFilter,bEnableMotionBlur;
static s8 gShaderRomListSlotCount,curMapLayer;
static int gMapBlockOriginX,gMapBlockOriginZ,gMapBlockOriginWorldX,gMapBlockOriginWorldZ;
static int gShaderCurMapEventId,gShaderGameTextLoadedMapId,gMapCurRomListSlot,gHeatEffectFadeDirection,gWarpRequested;
static f32 playerMapOffsetX,playerMapOffsetZ,gMapSavedPlayerOffsetX,gMapSavedPlayerOffsetZ;
static f32 gMotionBlurAmount,gShaderLoadCenterX,gShaderLoadCenterY,gShaderLoadCenterZ;
static WarpVec gCameraPosByTransformSpace[41];
static SaveGameCharacterPosition saved;
static SaveGameEnvState env;
static GameObject player;
static Camera camera;
static int character,present,camAction,immediateCalls,cloudCalls;
static char events[100]; static int eventCount;
static void event(char e) { assert(eventCount<99); events[eventCount++]=e; events[eventCount]=0; }
static f32 fastFloorf(f32 value) { return floorf(value); }
#define SPY(name,code) static void name(void) { event(code); }
SPY(triggerSetup,'A') SPY(trackInitCollisionBuffers,'B') SPY(setSaveGameLoadingFlag,'E')
SPY(doPendingMapLoads,'F') SPY(trackIntersect,'G') SPY(mapSetupPlayer,'I')
SPY(waterSetup,'J') SPY(projSetup,'K') SPY(modSetup,'L') SPY(expSetup,'M') SPY(partSetup,'N')
SPY(freeClouds,'O') SPY(cloudSetup,'P') SPY(sky2Setup,'Q') SPY(loadLights,'R') SPY(newCloudSetup,'S')
SPY(waterFxInit,'T') SPY(clearSaveGameLoadingFlag,'g') SPY(Pause_ResetMenuFrameCounter,'i')
static int getCurChar(void) { event('C'); return character; }
static SaveGameCharacterPosition* getCurCharPos(void) { event('D'); return &saved; }
static Camera* Camera_GetCurrent(void) { event('H'); return &camera; }
static GameObject* Obj_GetPlayerObject(void) { event('U'); return present ? &player : NULL; }
static s16 SaveGame_getCamActionNo(void) { event('V'); return camAction; }
static SaveGameEnvState* saveGameGetEnvState(void) { event('X'); return &env; }
static void loadCamAction(int a,int b,int c) { assert(a==0 && b==camAction && c==1); event('W'); }
static void getEnvfxActImmediately(void* a,void* b,u16 id,int flags) {
    assert(a==&player && b==&player && flags==0 && id>=100 && id<=103);
    immediateCalls|=1<<(id-100); event('Y');
}
static void skySetSlotFlag80(int slot,int value) {
    assert((slot==1 || slot==2) && value==((env.envFlags>>slot)&1)); event(slot==1 ? 'a' : 'b');
}
static void skySetLightIndex(int value,float blend) { assert(value==((env.envFlags>>4)&1) && blend==0); event('c'); }
static void getEnvfxAct(void* source,void* target,u16 id,int flags) {
    GameObject* object=source;
    assert(target==&player && flags==0 && id>=200 && id<=202 && (uintptr_t)source>UINT32_MAX);
    int i=id-200;
    assert(object->anim.parent==NULL && object->anim.worldPosX==0 && object->anim.worldPosY==0 && object->anim.worldPosZ==0);
    assert(object->anim.localPosX==(float)env.cloudPos[i][0] && object->anim.localPosY==(float)env.cloudPos[i][1]);
    assert(object->anim.localPosZ==(float)env.cloudPos[i][2]); cloudCalls|=1<<i; event('d');
}
static float timeOfDay;
static void setTimeOfDay(float time) { timeOfDay=time; event('e'); }
static void cloudNop(int arg) { assert(arg==1); event('f'); }
static void Pause_SetDisabled(int arg) { assert(!arg); event('h'); }
#define ON_SETUP(global,fn) static struct { void (*onMapSetup)(void); } global##Table={fn}, \
    *global##Pointer=&global##Table, **global=&global##Pointer
ON_SETUP(gObjectTriggerInterface,triggerSetup);
ON_SETUP(gWaterfxInterface,waterSetup); ON_SETUP(gProjgfxInterface,projSetup);
ON_SETUP(gModgfxInterface,modSetup); ON_SETUP(gExpgfxInterface,expSetup); ON_SETUP(gPartfxInterface,partSetup);
ON_SETUP(gSky2Interface,sky2Setup); ON_SETUP(gNewCloudsInterface,newCloudSetup);
static struct { void (*freeCloudObjects)(void); void (*onMapSetup)(void); void (*func09Nop)(int); }
    cloudTable={freeClouds,cloudSetup,cloudNop},*cloudPointer=&cloudTable,**gCloudActionInterface=&cloudPointer;
static struct { void (*loadLights)(void); void (*setTimeOfDay)(float); }
    skyTable={loadLights,setTimeOfDay},*skyPointer=&skyTable,**gSkyInterface=&skyPointer;
static struct { void (*loadTriggeredCamAction)(int,int,int); }
    camTable={loadCamAction},*camPointer=&camTable,**gCameraInterface=&camPointer;
static struct { int (*getCurChar)(void); SaveGameCharacterPosition* (*getCurCharPos)(void); }
    mapTable={getCurChar,getCurCharPos},*mapPointer=&mapTable,**gMapEventInterface=&mapPointer;
'''
CHECKS = r'''
static void guards(void) {
    for (int i=0;i<9;i++) for (int j=0;j<32;j++)
        assert(raw[i][j]==0xa5 && raw[i][32+sizes[i]+j]==0xa5);
}
static void checkAlloc(int trackCount) {
    for (int i=0;i<256;i++) trackTable[i]=i<trackCount ? i : 0xffff;
    memset(gVisibleObjectSortKeys,0xa5,sizeof(gVisibleObjectSortKeys));
    for (int i=0;i<120;i++) gLoadedRomListPages[i]=(void*)&player;
    allocations=assetLoads=0; renderFlags=~0u; initMapBlocks();
    assert(allocations==9 && assetLoads==3 && renderFlags==0);
    assert(gMapBlocks==(void*)(raw[0]+32) && gMapBlockIds==(void*)(raw[1]+32));
    assert(gMapBlockRefCounts==raw[2]+32 && gMapInfoBuffer==raw[3]+32);
    for (int i=0;i<5;i++) {
        assert(gMapBlockLayerTables[i]==(void*)(raw[4]+32+i*256));
        assert(gMapBlockCellEntryTables[i]==(void*)(raw[5]+32+i*256*sizeof(MapCellEntry)));
        assert(gMapBlockCellStateTables[i]==(void*)(raw[6]+32+i*256));
    }
    assert(gMapTextureOverrides==(void*)(raw[7]+32) && gMapTextureScrolls==(void*)(raw[8]+32));
    for (int i=0;i<120;i++) assert(gLoadedRomListPages[i]==NULL);
    for (int i=0;i<1024;i++) assert(gVisibleObjectSortKeys[i]==(!i ? ~0u : i<1000 ? 0u : 0xa5a5a5a5u));
    for (int i=0;i<9;i++) for (size_t j=0;j<sizes[i];j++) assert(raw[i][32+j]==(i<7 ? 0xa5 : 0));
    assert(gTrkBlkTabCount==trackCount-1 && gPendingWarpIndex==-1 && gArrivedWarpIndex==-2);
    assert(gMapsTab==(void*)trackTable && gHitsTab==(void*)(trackTable+1)); guards(); cases++;
}
static void checkSetup(int arrival,int who,int hasPlayer,int envFlags,int clouds,int effects,int position) {
    character=who; present=hasPlayer; camAction=effects ? 3 : -1;
    saved=(SaveGameCharacterPosition){position*640.25f,-31.5f,-position*127.25f,0,-2,0,0};
    memset(&env,0xa5,sizeof(env)); env.unk00=12345; env.envFlags=envFlags;
    env.skyEnvfxActIds[0]=effects ? 100 : -1; env.skyEnvfxActIds[1]=effects ? 101 : -1;
    env.cloudActionEnvfxActId=effects ? 102 : -1; env.sky2EnvfxActId=effects ? 103 : -1;
    for (int i=0;i<3;i++) {
        env.cloudEnvfxActIds[i]=(clouds>>i)&1 ? 200+i : -1;
        for (int j=0;j<3;j++) env.cloudPos[i][j]=(i*3+j+1)*(j==1 ? -100 : 50);
    }
    memset(&camera,0xa5,sizeof(camera)); Camera expectedCamera=camera;
    expectedCamera.x=saved.x; expectedCamera.y=saved.y; expectedCamera.z=saved.z;
    memset(gCameraPosByTransformSpace,0xa5,sizeof(gCameraPosByTransformSpace));
    WarpVec expectedPositions[41]; memcpy(expectedPositions,gCameraPosByTransformSpace,sizeof(expectedPositions));
    expectedPositions[0]=(WarpVec){saved.x,saved.y,saved.z,{.valid=1}};
    for (int i=0;i<5;i++) {
        memset(gMapBlockLayerTables[i],0xa5,256); memset(gMapBlockCellEntryTables[i],0xa5,256*sizeof(MapCellEntry));
    }
    for (int i=0;i<64;i++) { gMapBlocks[i]=(void*)&player; gMapBlockIds[i]=123; }
    gArrivedWarpIndex=arrival; gWarpArrivalTimer=99; gMapBlockCount=64; gShaderRomListSlotCount=8;
    gShaderGameTextLoadedMapId=53; gMapLoadDeferred=bEnableBlurFilter=bEnableMotionBlur=1;
    gMotionBlurAmount=0.75f; renderFlags=0x123fffff; gWarpRequested=1;
    immediateCalls=cloudCalls=eventCount=0; beginLoadingMap();
    int restore=(arrival==-1 || arrival==-2) && hasPlayer && (who==0 || who==1);
    assert(gArrivedWarpIndex==(arrival==-1 ? -2 : arrival) && gWarpArrivalTimer==(arrival==-1 ? 8 : 99));
    assert(!gMapBlockCount && !gShaderRomListSlotCount && gShaderGameTextLoadedMapId==52);
    assert(gShaderCurMapEventId==-1 && gMapCurRomListSlot==-1 && curMapLayer==-2);
    assert(!gMapLoadDeferred && !bEnableBlurFilter && !bEnableMotionBlur && !gMotionBlurAmount && !gWarpRequested);
    assert(gMapBlockOriginX==(int)floorf(saved.x/640) && gMapBlockOriginZ==(int)floorf(saved.z/640));
    assert(gMapBlockOriginWorldX==gMapBlockOriginX*640 && gMapBlockOriginWorldZ==gMapBlockOriginZ*640);
    assert(playerMapOffsetX==gMapBlockOriginWorldX && playerMapOffsetZ==gMapBlockOriginWorldZ);
    assert(gMapSavedPlayerOffsetX==playerMapOffsetX && gMapSavedPlayerOffsetZ==playerMapOffsetZ);
    assert(gShaderLoadCenterX==saved.x && gShaderLoadCenterY==saved.y && gShaderLoadCenterZ==saved.z);
    assert(memcmp(&camera,&expectedCamera,sizeof(camera))==0);
    assert(memcmp(gCameraPosByTransformSpace,expectedPositions,sizeof(expectedPositions))==0);
    MapCellEntry expectedCell; memset(&expectedCell,0xa5,sizeof(expectedCell)); expectedCell.romListIndex=-1;
    for (int layer=0;layer<5;layer++) for (int i=0;i<256;i++) {
        assert(gMapBlockLayerTables[layer][i]==-1);
        assert(memcmp(&gMapBlockCellEntryTables[layer][i],&expectedCell,sizeof(expectedCell))==0);
        assert((u8)gMapBlockCellStateTables[layer][i]==0xa5);
    }
    for (int i=0;i<64;i++) assert(gMapBlockIds[i]==-1 && gMapBlocks[i]==NULL);
    u32 expectedFlags=((0x123fffff&0x82008)|0x481F0|0x804|2)&~4;
    if (restore) expectedFlags=(envFlags&1) ? expectedFlags|0x50 : expectedFlags&~0x50;
    assert(renderFlags==expectedFlags);
    assert(env.envFlags==(restore ? (envFlags&~9)|((envFlags&1) ? 9 : 0) : envFlags));
    assert(gHeatEffectFadeDirection==(restore && (envFlags&32) ? 1 : -1));
    assert(timeOfDay==(restore ? 12345 : 43000));
    assert(immediateCalls==(restore && effects ? 15 : 0) && cloudCalls==(restore ? clouds : 0));
    char expectedEvents[100]="ABCDEFGHIJKLMNOPQRSTU";
    if (restore) {
        strcat(expectedEvents,effects ? "VWXYYYY" : "VX");
        strcat(expectedEvents,"abcXX");
        for (int i=0;i<3;i++) if ((clouds>>i)&1) strcat(expectedEvents,"d");
        strcat(expectedEvents,"e");
    } else strcat(expectedEvents,"ef");
    strcat(expectedEvents,"ghi"); assert(strcmp(events,expectedEvents)==0);
    guards(); cases++;
}
int main(void) {
    int counts[]={0,1,4,17,255};
    for (int i=0;i<5;i++) { checkAlloc(counts[i]); if (i<4) for (int j=0;j<9;j++) free(raw[j]); }
    int arrivals[]={-2,-1,0},characters[]={0,1,2};
    for (int a=0;a<3;a++) for (int who=0;who<3;who++) for (int hasPlayer=0;hasPlayer<2;hasPlayer++)
    for (int flags=0;flags<64;flags++) for (int clouds=0;clouds<8;clouds++) for (int effects=0;effects<2;effects++)
    for (int pos=-1;pos<=1;pos++) checkSetup(arrivals[a],characters[who],hasPlayer,flags,clouds,effects,pos);
    for (int i=0;i<9;i++) free(raw[i]);
    printf("%d native map-block allocation/setup scenarios passed\n",cases);
}
'''


def harness():
    shader = (ROOT / 'src/main/shader.c').read_text()
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts = [PRELUDE, TYPES, re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0]]
    for path, name in (('include/main/objanim_internal.h', 'ObjAnimComponent'),
                       ('include/main/camera.h', 'Camera'), ('include/main/warpvec.h', 'WarpVec'),
                       ('include/main/shader_api.h', 'MapCellEntry'),
                       ('include/main/map_texture_state.h', 'MapTextureOverride'),
                       ('include/main/map_texture_state.h', 'MapTextureScroll'),
                       ('include/main/dll/savegame_state.h', 'SaveGameCharacterPosition'),
                       ('include/main/dll/savegame_env_api.h', 'SaveGameEnvState')):
        text = (ROOT / path).read_text()
        parts.append(re.search(rf'typedef struct {name}\s*\{{.*?\}} {name};', text, re.S)[0])
    obj = (ROOT / 'include/game/objects/object.h').read_text()
    parts.append(re.search(r'struct GameObject \{.*?\n\};', obj, re.S)[0])
    parts += [re.search(r'^#define MAP_BLOCK_LAYER_COUNT[^\n]+', shader, re.M)[0],
              '#define ROM_LIST_PAGE_COUNT 120', SERVICES,
              function(shader, 'initMapBlocks'), function(shader, 'beginLoadingMap'), CHECKS]
    return '\n'.join(parts)


class MapBlockInitTests(unittest.TestCase):
    def test_native_setup(self):
        with tempfile.TemporaryDirectory(prefix='map-block-init-') as directory:
            source = Path(directory) / 'init.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    exe = Path(directory) / 'init'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(exe)],
                                   check=True, timeout=30)
                    subprocess.run([str(exe)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
