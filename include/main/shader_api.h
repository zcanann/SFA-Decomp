#ifndef MAIN_SHADER_API_H_
#define MAIN_SHADER_API_H_

#include "global.h"
#include "main/camera.h"
#include "main/map_romlist_page.h"
#include "main/map_texture_state.h"
#include "main/model_light.h"

struct GameObject;
struct MapBlockData;

#define ROM_LIST_PAGE_COUNT 120

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern MapRomListPage* gLoadedRomListPages[ROM_LIST_PAGE_COUNT];

typedef MapRomListPage MapRomList;

typedef struct MapCellEntry
{
    s16 mapId;
    s16 adjacentMapId1;
    s16 adjacentMapId2;
    s16 blockId;
    s8 cellIndex;
    s8 romListIndex;
    s16 unkA;
} MapCellEntry;

STATIC_ASSERT(sizeof(MapCellEntry) == 0xC);

/* MAPINFO.bin per-record map type (curMapType / getCurMapType()). */
typedef enum MapType
{
    MAPTYPE_NORMAL        = 0, /* normal outdoor map */
    MAPTYPE_SUBMAP        = 1, /* normal submap (dungeon/indoor) */
    MAPTYPE_UNLOAD_UNUSED = 2, /* unused: unloads all objects immediately on load */
    MAPTYPE_SUBMAP_UNUSED = 3, /* unused: same as MAPTYPE_UNLOAD_UNUSED; only frontend2 has this */
    MAPTYPE_NO_HUD        = 4, /* hides PDA HUD; title screen + Arwing maps; no player object spawned */
} MapType;

MapCellEntry* mapGetCellEntry(int x, int z);
MapRomList* mapGetCurrentRomList(void);
void mapGetLoadedMapFlags(u8* outFlags);
s32 getCurMapType(void);
void mapTextureOverrideSetValue(int type, Texture* texture, int frame);
int objUpdateOpacity(struct GameObject* obj);
void mapUpdateCameraPosByTransformSpace(void);
void doPendingMapLoads(void);
void mapReloadWithFadeout(void);
void mapSetup(int layerOffset, f32 x, int* outMapId, int* outMapDataFileId, f32 y, f32 z);
void initMaps(void);
void unloadMap(void);
void beginLoadingMap(void);
void goToNextMapLayer(void);
void goToPrevMapLayer(void);
void buildPlayerRelativeFrustumPlanes(void);
s32 getCurMapLayer(void);
void mapUnloadRomListPage(int pageIndex);
void mapGetBlockGridRects(int gridX, int gridZ, int* rectA, int* rectB, int* rectC, int* rectD, int layer, int useVisGrid, int slot);
int mapTextureOverrideAcquire(Texture* texture, u32 flags, int type);
void mapTextureOverrideRelease(Texture* texture, int type);
s16* mapBlockFindTextureOverrideIndex(struct MapBlockData* block, int textureSlot);
int shaderReturnZeroStub(int unused);

extern s16 gArrivedWarpIndex;
extern u8 gWarpArrivalTimer;
extern f32 gMapSavedPlayerOffsetX;
extern f32 gMapSavedPlayerOffsetZ;
extern s16* gMapBlockIds;
extern u8* gMapBlockRefCounts;
extern s16 gTrkBlkTabCount;
extern s16 gPendingWarpIndex;
extern u8 gCloudLayerTexMatrix[0x30];
extern u32 gSunFlareScissorX;
extern u32 gSunFlareScissorY;
extern u32 gSunFlareScissorWidth;
extern u32 gSunFlareScissorHeight;
extern u8 gGlowLightCount;
extern u8 gMapBlockCount;
extern int gMapBlockIndexCount;
extern int* gMapBlockIndexList;
extern f32 gSunFlareFade;
typedef struct SunOcclusionSample
{
    int x;
    int y;
} SunOcclusionSample;

extern SunOcclusionSample gSunOcclusionSampleOffsets[];
extern u16 lbl_803DCEAC;
extern s32 heatEffectIntensity;
extern u8 gLightmapScreenImageEnabled;
extern s8* gMapLayerCellStates;
extern f32 lbl_803DCE58;
extern f32 lbl_803DCE54;
extern int gLightmapDeferredObjectCount;
extern s16 gVisibleObjectSortKeyCount;
extern int gMapBlockOriginX;
extern int gMapBlockOriginZ;
extern void* gCurRomListPage;
extern u8 bEnableMotionBlur;
extern f32 gMotionBlurAmount;
extern u8 bEnableBlurFilter;
extern f32 blurFilterX;
extern f32 blurFilterY;
extern f32 blurFilterZ;
extern u8 bBlurFilterUseArea;
extern u8 bBiggerBlurFilter;
extern u8 bEnableDistortionFilter;
extern f32 distortionFilterAngle1;
extern f32 distortionFilterAngle2;
extern u8 distortionFilterColor[3];
extern u8 bEnableMonochromeFilter;
extern u8 bEnableSpiritVision;
extern u8 bEnableViewFinderHud;
extern s32 bEnableColorFilter;
extern s8 curMapType;

extern void* gHitsTab;
extern int gLightmapDrawQueueCount;
extern void* gCloudLayerTexture;
extern u8* gMapInfoBuffer;
extern int gMapsTab;
extern u16* gTrkBlkTab;
extern MapCellEntry* gMapBlockCellEntryTables[];
extern s8 gMapBlockDrawOrderFrontToBack[];
extern s8 gMapBlockDrawOrderBackToFront[];
extern s8* gMapBlockCellStateTables[];
extern int gMapCurRomListSlot;
extern int gHeatEffectFadeDirection;
extern Camera* gSceneCamera;
extern ModelLightStruct* gTexDimmedLightList[2];
extern ModelLightStruct* gTexBlockLightList[2];
extern ModelLightStruct* gGlowLightList[];

#endif /* MAIN_SHADER_API_H_ */
