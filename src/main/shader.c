#include "main/dll/partfx_interface.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/mtx.h"
#include "main/asset_load.h"
#include "main/gameloop_api.h"
#include "main/pi_data_file_api.h"
#include "main/pi_dolphin_api.h"
#include "main/pi_flush_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/debug.h"
#include "main/frustum.h"
#include "main/shader_api.h"
#include "main/shader_map_api.h"
#include "main/shader_map_text_api.h"
#include "main/map_romlist_page.h"
#include "main/textrender_api.h"
#include "main/texture.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/render_envfx_api.h"
#include "main/model_render_instrs_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/checkpoint_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/projgfx_interface.h"
#include "main/dll/cloudaction_interface.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEvent.h"
#include "main/mldf_fileid.h"
#include "main/minimap_api.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/sky_interface.h"
#include "main/sky_api.h"
#include "main/mapEventTypes.h"
#include "main/camera.h"
#include "main/object_transform.h"
#include "main/mm.h"
#include "main/voxmaps.h"
#include "main/warpvec.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/savegame.h"
#include "main/loaded_file_flags.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/fileio.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "main/objtype.h"
#include "main/obj_list.h"
#include "main/track_dolphin_api.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/mtx/vec.h"
#include "sys/objects/lifecycle.h"
#include "game/objects/object_setup.h"
#include "track/intersect_api.h"
#include "main/model.h"
#include "main/pi_dolphin.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/objprint_dolphin_api.h"
#include "main/dll/savegame_env_api.h"
#include "main/dll/tricky_api.h"
#include "main/screen_transition.h"
#include "dolphin/gx/GXCull.h"
#include "string.h"
#include "main/rcp_dolphin.h"
#include "main/gameloop_internal.h"
#include "main/lightmap_internal.h"

extern char sTrackLoadBlockOverrunError[];
extern char sShaderUnusedWordTable[];
#define MAP_BLOCK_LAYER_COUNT 5
#define FRUSTUM_PLANE_COUNT   5
static void trackLoadBlockEnd(MapBlockData* block, int blockId, int slotIdx, int layer);
/* One 0x20-byte MAPINFO.bin (fileId 0x1f) record, fetched by mapId via getTabEntry. */
typedef struct MapInfoRecord
{
    char name[0x1c]; /* NUL-padded editor name; only mapType is read at runtime */
    s8 mapType;      /* +0x1c: MapType */
    u8 unk1d;        /* always 6 in retail */
    s16 objType;     /* +0x1e: carrier object type for mapType-1 sub-maps, else 0 */
} MapInfoRecord;
extern WarpVec gCameraPosByTransformSpace[];


int lbl_803DB620 = -1;
s8 gMapLayerOffsets[8] = {0, -2, -1, 1, 2, 0, 0, 0};
f32 gMotionBlurAmount = 0.5f;

f32 gMapSavedPlayerOffsetX;
f32 gMapSavedPlayerOffsetZ;
int gShaderCurMapEventId;
int gShaderGameTextLoadedMapId;
int gMapCurRomListSlot;
u8 gWarpRequested;
u8 gRcpWarpTransitionType;
s16 gPendingWarpIndex;
s16 gArrivedWarpIndex;
s16 lbl_803DCEB6;
s16 lbl_803DCEB4;
int gMapBlockIndexCount;
s16 gVisibleObjectSortKeyCount;
u16 lbl_803DCEAC;
Camera* gSceneCamera;
s8 curMapType;
void* gCurRomListPage;
MapBlockData** gMapBlocks;
u8 gMapBlockCount;
s16* gMapBlockIds;
s16 gTrkBlkTabCount;
u8* gMapBlockRefCounts;
s8* gMapLayerCellStates;
u16* gTrkBlkTab;
void* gHitsTab;
int gMapsTab;
u8* gMapInfoBuffer;
int gMapCellRenderInstrsTable;
s16 gMapCellRenderInstrBits;
MapTextureOverride* gMapTextureOverrides;
MapTextureScroll* gMapTextureScrolls;
f32 gShaderLoadCenterX;
f32 gShaderLoadCenterY;
f32 gShaderLoadCenterZ;
f32 lbl_803DCE58;
f32 lbl_803DCE54;
f32 blurFilterX;
f32 blurFilterY;
f32 blurFilterZ;
f32 distortionFilterAngle2;
u8 distortionFilterColor[3];
f32 distortionFilterAngle1;
s32 bEnableColorFilter;
void* gCloudLayerTexture;
int gLightmapDrawQueueCount;
ModelLightStruct* gTexBlockLightList[2];
ModelLightStruct* gTexDimmedLightList[2];
int gMapPendingFileFlags;
f32 gSunFlareFade;
u32 gSunFlareScissorHeight;
u32 gSunFlareScissorWidth;
u32 gSunFlareScissorY;
u32 gSunFlareScissorX;
u8 gGlowLightCount;
u8 gLightmapScreenImageEnabled;
u8 gMapLoadDeferred;
int gHeatEffectFadeDirection;
s32 heatEffectIntensity;
u8 bBiggerBlurFilter;
u8 bEnableViewFinderHud;
u8 bEnableSpiritVision;
u8 bEnableMonochromeFilter;
u8 bEnableMotionBlur;
u8 bEnableDistortionFilter;
u8 bBlurFilterUseArea;
u8 bEnableBlurFilter;
int gLightmapDeferredObjectCount;
u8 gMapCellRenderInstrsEnabled;
s8 gShaderRomListSlotCount;
u32 renderFlags;
int* gMapBlockIndexList;
s8 curMapLayer;
u8 gWarpArrivalTimer;
f32 playerMapOffsetZ;
f32 playerMapOffsetX;
int gMapBlockOriginZ;
int gMapBlockOriginX;
int gMapBlockOriginWorldZ;
int gMapBlockOriginWorldX;

/* the ice-mountain snowbike; its map-block residency is tracked separately so the
   ride streams blocks ahead. retail OBJECTS.bin name "IMSnowBike" (DLL 0x255) */
#define SHADER_SNOWBIKE_OBJ 0x72
static void mapBuildRomListIndex(MapRomListPage* page, MapRomListIndex* romListIndex, int slot, int unloading);
int mapCoordsToId(int x, int z, int layer);
extern char gLightmapDrawQueue[];
typedef struct ShaderRomListSlot
{
    void* romlist;
    s16 slot;
    s8 flag;
    s8 pad;
} ShaderRomListSlot;
extern int gShaderMapRomBuffers[];
#define INIT_MAP_SLOT(slot)                                                                                 \
    e = (MapBounds*)((char*)gShaderMapRomBuffers[1] + (slot) * 10 + ofs[0]);                                \
    *(s8*)((char*)gShaderMapRomBuffers[3] + idx + (slot)) = -128;                                          \
    e->minX = -32768;                                                                                      \
    e->maxX = -32768;                                                                                      \
    e->minZ = -32768;                                                                                      \
    e->maxZ = -32768;                                                                                      \
    e->originX = -128;                                                                                     \
    e->originZ = -128;                                                                                     \
    ((s16*)gShaderMapRomBuffers[2])[(idx + (slot)) << 1] = -1;                                             \
    ((s16*)gShaderMapRomBuffers[2])[((idx + (slot)) << 1) + 1] = -1

typedef struct MapBounds
{
    s16 minX;
    s16 maxX;
    s16 minZ;
    s16 maxZ;
    s8 originX;
    s8 originZ;
} MapBounds;

typedef struct MapsBinHeader
{
    s16 sizeX;
    s16 sizeZ;
    s16 originX;
    s16 originZ;
    u8 unk08[4];
    u32* cells;
} MapsBinHeader;

typedef struct GlobalMapEntry
{
    s16 originX;
    s16 originZ;
    s16 layer;
    s16 mapId;
    s16 adjacentMapId1;
    s16 adjacentMapId2;
} GlobalMapEntry;

typedef struct MapLoadRec
{
    s16 x;
    s16 z;
    s16 blockId;
    s16 layer;
} MapLoadRec;

int mapProcessRomList(int slot);

u32 Rcp_GetColorFilterEnabled(void)
{
    return bEnableColorFilter;
}

void Rcp_SetColorFilterEnabled(u32 x)
{
    bEnableColorFilter = x;
}

void ObjHits_ConvertHitPositionToWorld(GameObject* object, f32* position)
{
    if (object->anim.parent != NULL)
        return;
    position[0] = position[0] + playerMapOffsetX;
    position[2] = position[2] + playerMapOffsetZ;
}

void Rcp_DisableDistortionFilter(void)
{
    bEnableDistortionFilter = 0x0;
}

extern f32 distortionFilterVector[];

void turnOnDistortionFilter(f32* vec, f32 angle2, u32* color, f32 angle1)
{
    u8* colorBytes = (u8*)color;

    distortionFilterVector[0] = vec[0];
    distortionFilterVector[1] = vec[1];
    distortionFilterVector[2] = vec[2];
    distortionFilterAngle2 = angle2;
    distortionFilterColor[0] = colorBytes[0];
    distortionFilterColor[1] = colorBytes[1];
    distortionFilterColor[2] = colorBytes[2];
    distortionFilterAngle1 = angle1;
    bEnableDistortionFilter = 1;
}

extern MapRomListIndex gMapRomListIndexes[];

void Rcp_DisableHeatEffect(void)
{
    SaveGameEnvState* p = saveGameGetEnvState();
    gHeatEffectFadeDirection = -1;
    p->envFlags = (u8)(p->envFlags & ~0x20);
}

void Rcp_EnableHeatEffect(void)
{
    SaveGameEnvState* p = saveGameGetEnvState();
    gHeatEffectFadeDirection = 1;
    p->envFlags = (u8)(p->envFlags | 0x20);
}
void Rcp_DisableBlurFilter(void)
{
    bEnableBlurFilter = 0x0;
}


void turnOnBlurFilter(f32 x, f32 y, f32 z, u8 useArea, u8 bigger)
{
    bEnableBlurFilter = 1;
    blurFilterX = x;
    blurFilterY = y;
    blurFilterZ = z;
    bBlurFilterUseArea = useArea;
    bBiggerBlurFilter = bigger;
}

u8 Rcp_GetViewFinderHudEnabled(void)
{
    return bEnableViewFinderHud;
}
void Rcp_SetViewFinderHudEnabled(u8 x)
{
    bEnableViewFinderHud = x;
}

void Rcp_SetSpiritVisionEnabled(u8 x)
{
    bEnableSpiritVision = x;
}

void Rcp_SetMonochromeFilterEnabled(u8 x)
{
    bEnableMonochromeFilter = x;
}

int Rcp_GetMotionBlurEnabled(void)
{
    return bEnableMotionBlur;
}

void setMotionBlur(u8 enabled, f32 amount)
{
    bEnableMotionBlur = enabled;
    gMotionBlurAmount = amount;
}

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2)
{
    if (x < 0)
        x = 0;
    if (y < 0)
        y = 0;
    if (x2 < 0)
        x2 = 0;
    if (y2 < 0)
        y2 = 0;
    GXSetScissor(x, y, x2 - x, y2 - y);
}

void loadNextMap(void)
{
    SaveGameCharacterPosition* pos;
    pos = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
    if (gArrivedWarpIndex != -1)
    {
        gWarpArrivalTimer -= 1;
        if ((s8)gWarpArrivalTimer < 0)
        {
            if (gArrivedWarpIndex > -1 && (s8)gRcpWarpTransitionType != 0)
            {
                (*gScreenTransitionInterface)->step(3, SCREEN_TRANSITION_BLACK);
            }
            gArrivedWarpIndex = -1;
            Pause_SetDisabled(0);
        }
    }
    if ((s8)gWarpRequested != 0)
    {
        if ((*gScreenTransitionInterface)->isFinished() != 0 || (s8)gRcpWarpTransitionType == 0)
        {
            (*gCloudActionInterface)->freeCloudObjects();
            (*gCloudActionInterface)->onMapSetup();
            (*gSky2Interface)->onMapSetup();
            (*gSkyInterface)->loadLights();
            (*gNewCloudsInterface)->onMapSetup();
            gameUiResetMenuState();
            gWarpRequested = 0;
            pos->x = gRcpPendingWarpDest.x;
            pos->y = gRcpPendingWarpDest.y;
            pos->z = gRcpPendingWarpDest.z;
            pos->mapLayer = (s8)gRcpPendingWarpDest.layer;
            pos->angle = (s8)gRcpPendingWarpDest.angle;
            mapReload();
            gArrivedWarpIndex = gPendingWarpIndex;
            gPendingWarpIndex = -1;
            gWarpArrivalTimer = 8;
            gGameLoopFullMapUnloadPending = 1;
            blankScreen(1);
        }
    }
}

void warpToMap(int idx, s8 transType)
{
    WarpDestination* p = (WarpDestination*)gMapInfoBuffer;
    getTabEntry(p, MLDF_FILEID_WARPTAB_BIN, idx << 4, 16);
    gRcpPendingWarpDest.x = p->x;
    gRcpPendingWarpDest.y = p->y;
    gRcpPendingWarpDest.z = p->z;
    gRcpPendingWarpDest.layer = p->layer;
    gRcpPendingWarpDest.angle = p->angle;
    gPendingWarpIndex = (s16)idx;
    gWarpRequested = 1;
    *(s8*)&gRcpWarpTransitionType = transType;
    if (transType != 0)
    {
        (*gScreenTransitionInterface)->start(2, SCREEN_TRANSITION_BLACK);
    }
    Pause_SetDisabled(1);
}

static inline int objIsVisibleInAct(u8* def, int act)
{
    if (act == -1)
    {
        return 0;
    }
    if (act != 0)
    {
        if (act < 9)
        {
            if ((def[3] >> (act - 1)) & 1)
                return 0;
        }
        else
        {
            if ((def[5] >> (0x10 - act)) & 1)
                return 0;
        }
    }
    return 1;
}

void mapInstantiateObjects(MapRomListPage* page, int mapId, int index, GameObject* parent)
{
    MapRomListIndex* romListIndex = &gMapRomListIndexes[mapId];
    int i;
    char* p;
    char* end;
    char* romBase;
    char* objStart;
    int objIndex;
    char* obj;
    int v;
    int flag;
    int byteIdx;
    int bit;
    s8* vis;
    int visByte;

    if (romListIndex->groupOffset[index] == -1)
        return;
    objIndex = 0;
    romBase = (char*)page->objects;
    p = romBase;
    objStart = romBase + romListIndex->groupOffset[index];
    while (p < objStart)
    {
        objIndex++;
        p += ((ObjPlacement*)p)->size * 4;
    }
    for (i = index + 1; i <= 0x20; i++)
    {
        if (romListIndex->groupOffset[i] != -1)
            break;
    }
    obj = objStart;
    end = romBase + romListIndex->groupOffset[i];

    while (obj < end)
    {
        /* i reused below as the object-visible flag */
        if (objIndex < 0)
        {
            i = 0;
        }
        else
        {
            MapRomListPage* bm = gLoadedRomListPages[mapId];
            byteIdx = objIndex >> 3;
            if (byteIdx >= 0xc4)
            {
                i = 0;
            }
            else
            {
                i = 1;
                bit = 1 << (objIndex & 7);
                vis = (s8*)bm->loadedObjectBits;
                if ((bit & vis[byteIdx]) != 0)
                    i = 1;
                else
                    i = 0;
            }
        }
        if (i == 0)
        {
            v = (*gMapEventInterface)->getMapAct(mapId);
            flag = objIsVisibleInAct((u8*)obj, v);
            if (flag != 0)
            {
                if (objIndex >= 0)
                {
                    MapRomListPage* bm2 = gLoadedRomListPages[mapId];
                    visByte = objIndex >> 3;
                    bit = 1 << (objIndex & 7);
                    vis = (s8*)bm2->loadedObjectBits;
                    vis[visByte] &= ~bit;
                    vis = (s8*)bm2->loadedObjectBits;
                    vis[visByte] |= bit;
                }
                objSetupObject((ObjPlacement*)obj, 1, mapId, objIndex, parent);
            }
        }
        objIndex++;
        obj += ((ObjPlacement*)obj)->size * 4;
    }
}

int objShouldUnload(GameObject* obj)
{
    u8* def;
    GameObject* p;
    u8* src;
    s8** tp;
    int m;
    int keep;
    int bx;
    int bz;
    int k;
    int flags;
    int idx2;
    s8 found;
    f32 x;
    f32 y;
    f32 z;
    f32 dist;

    def = (u8*)obj->anim.placementData;
    if (def == NULL)
    {
        return 0;
    }
    if (def[4] & 2)
    {
        return 0;
    }
    m = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    keep = objIsVisibleInAct(def, m);
    if (keep == 0)
    {
        return 1;
    }
    flags = def[4];
    if (flags & 1)
    {
        return 0;
    }
    if (flags & 0x10)
    {
        return !(u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, def[6]);
    }
    if (obj->pendingParentObj != NULL && obj->seqIndex < 0)
    {
        return 0;
    }
    if (obj->ownerObj != NULL)
    {
        return 0;
    }
    if (obj->anim.parent == NULL)
    {
        bx = (int)fastFloorf((obj->anim.localPosX - playerMapOffsetX) / gMapBlockWorldSize);
        bz = (int)fastFloorf((obj->anim.localPosZ - playerMapOffsetZ) / gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 0x10 || bz >= 0x10)
        {
            return 1;
        }
        found = 0;
        bx = bx + (bz << 4);
        tp = gMapBlockLayerTables;
        for (k = 0; k < MAP_BLOCK_LAYER_COUNT; k++)
        {
            if ((*tp)[bx] >= 0)
            {
                found = 1;
            }
            tp++;
        }
        if (found == 0)
        {
            return 1;
        }
    }
    flags = def[4];
    if (flags & 0x20)
    {
        return 0;
    }
    if ((flags & 4) && (p = Obj_GetPlayerObject()) != NULL && obj->anim.parent == NULL)
    {
        x = p->anim.worldPosX;
        y = p->anim.worldPosY;
        z = p->anim.worldPosZ;
    }
    else
    {
        src = *(u8**)&obj->anim.parent;
        if (src != NULL)
        {
            idx2 = (s8)src[0x35] + 1;
        }
        else
        {
            idx2 = 0;
        }
        x = gCameraPosByTransformSpace[idx2].x;
        y = gCameraPosByTransformSpace[idx2].y;
        z = gCameraPosByTransformSpace[idx2].z;
    }
    dist = obj->anim.loadDistance;
    if (obj->anim.parent != NULL)
    {
        x -= obj->anim.localPosX;
        y -= obj->anim.localPosY;
        z -= obj->anim.localPosZ;
    }
    else
    {
        x -= obj->anim.worldPosX;
        y -= obj->anim.worldPosY;
        z -= obj->anim.worldPosZ;
    }
    if (x * x + y * y + z * z < (40.0f + dist) * (40.0f + dist))
    {
        return 0;
    }
    return 1;
}

static inline int objVisibleForAct(ObjPlacement* placement, int t)
{
    if (t == -1)
    {
        return 0;
    }
    if (t != 0)
    {
        if (t < 9)
        {
            if ((placement->mapActFlagsLo >> (t - 1)) & 1)
            {
                return 0;
            }
        }
        else
        {
            if ((placement->mapActFlagsHi >> (16 - t)) & 1)
            {
                return 0;
            }
        }
    }
    return 1;
}

static int objShouldLoad(ObjPlacement* placement, s8 viewSlot, int mapEventGroup)
{
    char* strs;
    int verbose;
    int useObj;
    f32 y;
    f32 z;
    f32 x;
    int t;
    int bx;
    int bz;
    s8 found;
    s8 i;
    GameObject* player;
    int off;
    f32* p;
    f32 d;
    f32 dz;
    f32 dy;
    f32 range;

    strs = sShaderUnusedWordTable;
    if (placement->ident == 0x49054)
    {
        verbose = 1;
    }
    else
    {
        verbose = 0;
    }
    t = (*gMapEventInterface)->getMapAct(mapEventGroup);
    if (objVisibleForAct(placement, t) == 0)
    {
        return 0;
    }
    if (placement->loadFlags & 1)
    {
        if (verbose)
        {
            OSReport(strs + 0x1cc);
        }
        return 1;
    }
    if (placement->loadFlags & 2)
    {
        if (verbose)
        {
            OSReport(strs + 0x1e8);
        }
        return 0;
    }
    if (viewSlot == 0)
    {
        bx = fastFloorf((placement->posX - playerMapOffsetX) / gMapBlockWorldSize);
        bz = fastFloorf((placement->posZ - playerMapOffsetZ) / gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16)
        {
            if (verbose)
            {
                OSReport(strs + 0x200, &placement->posX, &placement->posY, &placement->posZ);
            }
            return 0;
        }
        found = 0;
        bx += bz << 4;
        for (i = 0; i < MAP_BLOCK_LAYER_COUNT; i++)
        {
            if (gMapBlockLayerTables[i][bx] >= 0)
            {
                found = 1;
            }
        }
        if (found == 0)
        {
            if (verbose)
            {
                OSReport(strs + 0x228);
            }
            return 0;
        }
    }
    if (placement->loadFlags & 0x20)
    {
        if (verbose)
        {
            OSReport(strs + 0x240);
        }
        return 1;
    }
    useObj = 0;
    if ((placement->loadFlags & 4) && viewSlot == 0)
    {
        player = Obj_GetPlayerObject();
        if (player != NULL)
        {
            x = player->anim.worldPosX;
            y = player->anim.worldPosY;
            z = player->anim.worldPosZ;
        }
        else
        {
            useObj = 1;
        }
    }
    else
    {
        useObj = 1;
    }
    if (useObj != 0)
    {
        off = viewSlot << 4;
        x = gCameraPosByTransformSpace[viewSlot].x;
        p = (f32*)((u8*)gCameraPosByTransformSpace + off);
        y = p[1];
        z = p[2];
    }
    range = (f32)(placement->loadRange << 3);
    d = x - placement->posX;
    dy = y - placement->posY;
    dz = z - placement->posZ;
    d = d * d + dy * dy + dz * dz;
    if (d < range * range)
    {
        if (verbose)
        {
            OSReport(strs + 0x25c, &d);
        }
        return 1;
    }
    if (verbose)
    {
        OSReport(strs + 0x274);
    }
    return 0;
}

void mapLoadUnloadObjects(int flag)
{
    int grpBit;
    u32 objStart;
    GameObject* obj;
    int unload;
    int bit;
    u8 mask;
    u8* bp;
    u32 bits;
    int slot;
    int i;
    int objCount;
    s16 list[8];
    s16* idPtr;
    char* base;
    ObjPlacement* fp;
    int* tp;
    u32 cur;
    u32 end;
    s16 count;
    int vis;
    int idx;

    base = gLightmapDrawQueue;
    count = 0;
    i = 0;
    tp = (int*)(base + 0x41E0);
    for (; i < 5; i++)
    {
        slot = 0;
        idPtr = (s16*)((char*)*tp + 0x594);
        for (; slot < 3; slot++)
        {
            s16 id = *idPtr;
            if (id >= 0 && id < 80 && *(void**)(base + (0x83A8 + id * 4)) != 0)
            {
                s16* w;
                s16 dup;
                int j2;

                dup = 0;
                w = list;
                for (j2 = 0; j2 < count; j2++)
                {
                    if (*w == *(s16*)(void*)idPtr)
                    {
                        dup = 1;
                        break;
                    }
                    w++;
                }
                if (dup == 0)
                    list[count++] = id;
            }
            idPtr++;
        }
        tp++;
    }
    {
        GameObject** objs = ObjList_GetObjects(&i, &objCount);
        while (i < objCount)
        {
            obj = (GameObject*)objs[i];
            fp = obj->anim.placement;
            i++;
            unload = 0;
            if (obj->anim.mapEventSlot > -1)
            {
                u8 fl = fp->loadFlags;
                if (!(fl & 2))
                {
                    if (fl & 0x10)
                    {
                        if (obj->anim.classId > -1 && objShouldUnload(obj))
                        {
                            unload = 1;
                        }
                        else if (obj->anim.mapEventSlot < 80 &&
                                 *(void**)(base + (0x83A8 + obj->anim.mapEventSlot * 4)) == 0)
                        {
                            unload = 1;
                        }
                    }
                    else
                    {
                        if (obj->anim.classId > -1 && objShouldUnload(obj))
                        {
                            unload = 1;
                        }
                        else if (obj->anim.mapEventSlot < 80 && obj->anim.mapEventSlot != gShaderCurMapEventId)
                        {
                            unload = 1;
                        }
                    }
                }
            }
            if (unload)
            {
                MapRomListPage* page = *(MapRomListPage**)(base + (0x83A8 + obj->anim.mapEventSlot * 4));
                if (page != 0)
                {
                    s16 tbit = obj->romListBit;
                    if (tbit >= 0 && tbit >= 0)
                    {
                        u8* bb = page->loadedObjectBits;
                        *(s8*)&bb[tbit >> 3] = bb[tbit >> 3] & ~(1 << (tbit & 7));
                    }
                }
                if (obj->anim.romDefNo == SHADER_SNOWBIKE_OBJ)
                {
                    s16 j3;
                    int slotId;
                    s16* w2;

                    slotId = obj->anim.mapEventSlot;
                    j3 = 0;
                    w2 = list;
                    for (; j3 < count; j3++)
                    {
                        if (slotId == *w2)
                            break;
                        w2++;
                    }
                }
                Obj_FreeObject(obj);
                i--;
                objCount--;
            }
        }
    }
    if (getLoadedFileFlags(gShaderCurMapEventId) == 0)
    {
        for (i = 0; i < 80; i++)
        {
            if (((void**)(base + 0x83A8))[i] != NULL)
            {
                bits = (*gMapEventInterface)->getObjGroups(i);
                if (bits != 0)
                {
                    grpBit = 0;
                    while (bits != 0)
                    {
                        if ((bits & 1) && SaveGame_findTransientMapBit(i, grpBit) == -1)
                        {
                            mapInstantiateObjects((MapRomListPage*)((char**)(base + 0x83A8))[i], i, grpBit, NULL);
                            mapClearBit(i, grpBit);
                        }
                        bits >>= 1;
                        grpBit++;
                    }
                }
            }
        }
        for (i = 0; i < count; i++)
        {
            if (gShaderCurMapEventId == list[i])
            {
                MapRomListPage* page = *(MapRomListPage**)(base + (0x83A8 + list[i] * 4));
                if (page != 0)
                {
                    mask = 1;
                    bit = 0;
                    cur = (u32)page->objects;
                    bp = page->loadedObjectBits;
                    end = cur + *(int*)(base + (0x4290 + list[i] * 0x8C));
                    while (cur < end)
                    {
                        objStart = cur;
                        if ((*bp & mask) == 0 && objShouldLoad((ObjPlacement*)cur, 0, list[i]) != 0)
                        {
                            s16 lid = list[i];
                            if (bit >= 0)
                            {
                                int msk;
                                int ix2;
                                MapRomListPage* pg;

                                pg = *(MapRomListPage**)(base + (0x83A8 + lid * 4));
                                ix2 = bit >> 3;
                                msk = 1 << (bit & 7);
                                *(s8*)&pg->loadedObjectBits[ix2] = pg->loadedObjectBits[ix2] & ~msk;
                                *(s8*)&pg->loadedObjectBits[ix2] = pg->loadedObjectBits[ix2] | msk;
                            }
                            objSetupObject((ObjPlacement*)objStart, 1, list[i], bit, NULL);
                        }
                        bit++;
                        mask <<= 1;
                        if (mask == 0)
                        {
                            bp++;
                            while (*bp == -1)
                            {
                                bit += 8;
                                cur = objStart + ((ObjPlacement*)objStart)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                cur += ((ObjPlacement*)cur)->size * 4;
                                objStart = cur;
                                bp++;
                            }
                            mask = 1;
                        }
                        cur = objStart + ((ObjPlacement*)objStart)->size * 4;
                    }
                }
            }
        }
        {
            GameObject** objs2 = objGetAllOfType(6, &objCount);
            for (i = 0; i < objCount; i++)
            {
                GameObject* obj2 = (GameObject*)objs2[i];
                u32 mid2 = obj2->anim.hostedMapSlot;
                MapRomListPage* page2 = ((MapRomListPage**)(base + 0x83A8))[mid2];
                if (page2 != 0)
                {
                    int lp = obj2->anim.transformMatrixIndex + 1;
                    bit = 0;
                    cur = (u32)page2->objects;
                    end = cur + *(int*)(base + (0x4290 + mid2 * 0x8C));
                    bits = (*gMapEventInterface)->getObjGroups(mid2);
                    if (bits != 0)
                    {
                        grpBit = 0;
                        while (bits != 0)
                        {
                            if ((bits & 1) && SaveGame_findTransientMapBit(mid2, grpBit) == -1)
                            {
                                mapInstantiateObjects(page2, mid2, grpBit, obj2);
                            }
                            bits >>= 1;
                            mapClearBit(mid2, grpBit);
                            grpBit++;
                        }
                    }
                    while (cur < end)
                    {
                        if (bit < 0)
                        {
                            vis = 0;
                        }
                        else
                        {
                            char* pg2 = ((char**)(base + 0x83A8))[mid2];
                            idx = bit >> 3;
                            if (idx >= 0xc4)
                            {
                                vis = 0;
                            }
                            else
                            {
                                switch (((vis = 1) << (bit & 7)) & *(s8*)(*(int*)(pg2 + 0x10) + idx))
                                {
                                case 0:
                                    vis = 0;
                                    break;
                                }
                            }
                        }
                        if (vis == 0 && objShouldLoad((ObjPlacement*)cur, lp, mid2) != 0)
                        {
                            if (bit >= 0)
                            {
                                int msk3;
                                int ix3;
                                char* pg3;

                                pg3 = ((char**)(base + 0x83A8))[mid2];
                                ix3 = bit >> 3;
                                msk3 = 1 << (bit & 7);
                                *(s8*)(*(int*)(pg3 + 0x10) + ix3) = *(u8*)(*(int*)(pg3 + 0x10) + ix3) & ~msk3;
                                *(s8*)(*(int*)(pg3 + 0x10) + ix3) = *(u8*)(*(int*)(pg3 + 0x10) + ix3) | msk3;
                            }
                            objSetupObject((ObjPlacement*)cur, 1, mid2, bit, obj2);
                        }
                        bit++;
                        cur += ((ObjPlacement*)cur)->size * 4;
                    }
                }
            }
        }
    }
}

void mapUpdateCameraPosByTransformSpace(void)
{
    int count;
    int slot;
    GameObject** objs;
    Camera* cam;
    int k;
    GameObject** e;
    int i;
    f32 lx, ly, lz;

    objs = (GameObject**)objGetAllOfType(6, &count);
    cam = Camera_GetCurrent();
    Camera_UpdateForObject(cam);
    for (k = 0; k < 31; k++)
        gCameraPosByTransformSpace[k].valid = 0;
    gCameraPosByTransformSpace[0].x = cam->worldX;
    gCameraPosByTransformSpace[0].y = cam->worldY;
    gCameraPosByTransformSpace[0].z = cam->worldZ;
    gCameraPosByTransformSpace[0].valid = 1;
    for (i = 0, e = objs; i < count; e++, i++)
    {
        GameObject* obj = *e;
        slot = obj->anim.transformMatrixIndex + 1;
        if (cam->parentObject == obj)
        {
            gCameraPosByTransformSpace[slot].x = cam->x;
            gCameraPosByTransformSpace[slot].y = cam->y;
            gCameraPosByTransformSpace[slot].z = cam->z;
        }
        else
        {
            Obj_TransformWorldPointToLocal(cam->worldX, cam->worldY, cam->worldZ, &lx, &ly, &lz, obj);
            gCameraPosByTransformSpace[slot].x = lx;
            gCameraPosByTransformSpace[slot].y = ly;
            gCameraPosByTransformSpace[slot].z = lz;
        }
        gCameraPosByTransformSpace[slot].valid = 1;
    }
}

MapTextureOverride* mapTextureOverrideGetEntry(int idx)
{
    return &gMapTextureOverrides[idx];
}

s16* mapBlockFindTextureOverrideIndex(MapBlockData* block, int textureSlot)
{
    return NULL;
}
int shaderReturnZeroStub(int unused)
{
    return 0x0;
}

void mapTextureOverrideRelease(Texture* texture, int type)
{
    int i;
    Texture* entryTexture;

    for (i = 0; i < 80; i++)
    {
        entryTexture = gMapTextureOverrides[i].texture;
        if (entryTexture == texture && gMapTextureOverrides[i].type == type &&
            gMapTextureOverrides[i].refCount > 0)
        {
            gMapTextureOverrides[i].refCount -= 1;
            if (gMapTextureOverrides[i].refCount == 0)
            {
                gMapTextureOverrides[i].frame = 0;
                gMapTextureOverrides[i].type = 0;
                gMapTextureOverrides[i].texture = NULL;
                gMapTextureOverrides[i].flags = 0;
            }
        }
    }
}

extern char sTrackGlobalTexanimOverflowError[];

int mapTextureOverrideAcquire(Texture* texture, u32 flags, int type)
{
    MapTextureOverride* base;
    int idx;
    int found;
    int idx2;

    found = -1;
    idx = 0;
    base = gMapTextureOverrides;
    for (; idx < 80; idx++)
    {
        if (base[idx].refCount != 0)
        {
            Texture* entryTexture = base[idx].texture;
            if (entryTexture == texture && type == base[idx].type)
            {
                found = idx;
                break;
            }
        }
    }
    if (found != -1)
    {
        base[found].refCount += 1;
        return found;
    }
    found = -1;
    idx2 = 0;
    base = gMapTextureOverrides;
    for (; idx2 < 80; idx2++)
    {
        if (base[idx2].refCount == 0)
        {
            found = idx2;
            break;
        }
    }
    if (found != -1)
    {
        base[found].refCount = 1;
        gMapTextureOverrides[found].frame = 0;
        gMapTextureOverrides[found].flags = flags;
        gMapTextureOverrides[found].texture = texture;
        gMapTextureOverrides[found].type = type;
        return found;
    }
    OSReport(sTrackGlobalTexanimOverflowError);
    return 0;
}


void mapTextureOverrideSetValue(int type, Texture* texture, int frame)
{
    int i;

    for (i = 0; i < 80; i++)
    {
        if (gMapTextureOverrides[i].refCount > 0 &&
            gMapTextureOverrides[i].texture == texture &&
            type == gMapTextureOverrides[i].type)
        {
            gMapTextureOverrides[i].frame = frame;
        }
    }
}

void mapTextureScrollGetOffset(int idx, float* outX, float* outY)
{
    f32 divisor;
    *outX = gMapTextureScrolls[idx].offsetX / (divisor = 1048576.0f);
    *outY = gMapTextureScrolls[idx].offsetY / divisor;
}

void mapTextureScrollSetStep(int idx, int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                             int secondaryXStep, int secondaryYStep, int texWidthFixed2, int texHeightFixed2)
{
    MapTextureScroll* e = &gMapTextureScrolls[idx];
    e->xStep = (s16)((xStep << 16) / (texWidthFixed >> 6));
    e->yStep = (s16)((yStep << 16) / (texHeightFixed >> 6));
}

extern ShaderRomListSlot gShaderRomListSlots[8];

static inline int mapFindRomListSlot(ShaderRomListSlot* slots, int id)
{
    int i2 = 0;
    ShaderRomListSlot* q2 = slots;
    int cn = gShaderRomListSlotCount;
    int k;
    for (k = 0; k < cn; k++)
    {
        if (q2->romlist != NULL && id == q2->slot)
            return i2;
        q2++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotAndAdvance(ShaderRomListSlot** slots, int id)
{
    int i2 = 0;
    int cn = gShaderRomListSlotCount;
    int k;
    for (k = 0; k < cn; k++)
    {
        if ((*slots)->romlist != NULL && id == (*slots)->slot)
            return i2;
        (*slots)++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotByIdAt(char* base, int id)
{
    ShaderRomListSlot* q2;
    int i2;
    int cn;
    int k;
    i2 = 0;
    q2 = (ShaderRomListSlot*)(base + 0x418C);
    cn = gShaderRomListSlotCount;
    for (k = 0; k < cn; k++)
    {
        if (q2->romlist != NULL && id == q2->slot)
            return i2;
        q2++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotById(int id)
{
    ShaderRomListSlot* q2;
    int i2;
    int cn;
    int k;
    i2 = 0;
    q2 = gShaderRomListSlots;
    cn = gShaderRomListSlotCount;
    for (k = 0; k < cn; k++)
    {
        if (q2->romlist != NULL && id == q2->slot)
            return i2;
        q2++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotByIdAndGetBase(ShaderRomListSlot** slots, int id)
{
    int slotIndex;
    ShaderRomListSlot* cursor;
    int slotCount;
    int i;

    slotIndex = 0;
    *slots = cursor = gShaderRomListSlots;
    slotCount = gShaderRomListSlotCount;
    for (i = 0; i < slotCount; i++)
    {
        if (cursor->romlist != NULL && id == cursor->slot)
            return slotIndex;
        cursor++;
        slotIndex++;
    }
    return -1;
}

int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed,
                            int secondaryXStep, int secondaryYStep, int texWidthFixed2, int texHeightFixed2)
{
    MapTextureScroll* base;
    MapTextureScroll* entry;
    int idx;
    int idx2;
    int slot;
    f32 init;

    idx = 0;
    entry = base = gMapTextureScrolls;
    for (; idx < 0x3a; idx++)
    {
        if (entry->xStep == xStep && entry->yStep == yStep)
        {
            entry->refCount += 1;
            return idx;
        }
        entry++;
    }
    slot = -1;
    for (idx2 = 0, entry = base; idx2 < 0x3a; entry++, idx2++)
    {
        if (entry->refCount == 0)
        {
            slot = idx2;
            break;
        }
    }
    if (slot == -1)
        return -1;
    entry = &base[slot];
    entry->xStep = (s16)((xStep << 16) / (texWidthFixed >> 6));
    entry->yStep = (s16)((yStep << 16) / (texHeightFixed >> 6));
    init = 0.0f;
    entry->offsetX = init;
    entry->offsetY = init;
    entry->refCount += 1;
    return slot;
}

static void trackLoadBlockEnd(MapBlockData* block, int blockId, int slotIdx, int layer)
{
    int i;
    s16* arr;
    int count;
    s8* statusArr;

    i = 0;
    arr = gMapBlockIds;
    count = gMapBlockCount;
    for (; i < count; i++)
    {
        if (*arr == -1)
            break;
        arr++;
    }
    if (i == count)
    {
        gMapBlockCount++;
        if (gMapBlockCount == 0x40)
        {
            OSReport(sTrackLoadBlockOverrunError);
        }
    }
    statusArr = gMapBlockLayerTables[layer];
    statusArr[slotIdx] = i;
    gMapBlocks[i] = block;
    gMapBlockIds[i] = blockId;
    gMapBlockRefCounts[i] = 1;
    setMapBlockFlag();
}



void mapFillCellEntry(int gridX, int gridZ, MapCellEntry* entry, int layer);


static int mapLoadBlock(int cellX, int cellZ, int worldX, int worldZ, int layer)
{
    int j;
    s16* arr;
    void* block[1];
    int textureCursor[2];
    int slotIdx;
    int blockId;
    s8* statusArr;
    MapCellEntry* entry;

    entry = (MapCellEntry*)gMapBlockCellEntryTables[layer];
    statusArr = gMapBlockLayerTables[layer];
    slotIdx = cellX + (cellZ << 4);
    entry += slotIdx;

    mapFillCellEntry(worldX, worldZ, entry, layer);

    blockId = entry->blockId;
    if (mapCheckCurBlocks(entry->romListIndex) == -1)
    {
        statusArr[slotIdx] = -1;
        return 0;
    }
    if (blockId < 0)
    {
        blockId = -1;
    }
    if (blockId < 0)
    {
        statusArr[slotIdx] = blockId;
        return 0;
    }
    statusArr[slotIdx] = -1;

    j = 0;
    arr = gMapBlockIds;
    for (; j < gMapBlockCount; j++)
    {
        if (blockId == *arr)
        {
            gMapBlockRefCounts[j]++;
            statusArr[slotIdx] = j;
            return 1;
        }
        arr++;
    }

    block[0] = MapBlock_loadFromFile(blockId);
    if (block[0] != NULL)
    {
        MapBlock_init(block[0]);
        textureCursor[0] = 0;
        textureCursor[1] = textureCursor[0];
        while (textureCursor[0] < ((MapBlockData*)block[0])->textureCount)
        {
            int fileId =
                -(int)((u32)((MapTextureRef*)((u8*)((MapBlockData*)block[0])->textures +
                                               textureCursor[1]))->fileId |
                       0x8000);
            ((MapTextureRef*)((u8*)((MapBlockData*)block[0])->textures + textureCursor[1]))->texture =
                textureLoad(fileId, 0);
            textureCursor[1] += sizeof(MapTextureRef);
            textureCursor[0]++;
        }
        MapBlock_initHits(block[0], blockId);
        MapBlock_initShaders(block[0]);
        trackLoadBlockEnd(block[0], blockId, slotIdx, layer);
        ((MapBlockData*)block[0])->unused00 = mapBlockGetUnused00Value(block[0]);
        DCStoreRange(block[0], ((MapBlockData*)block[0])->size);
    }
    return 1;
}

void unloadMap(void)
{
    MapBlockData* block;
    int j;
    ShaderLayer* shaderLayer;
    int i;
    int layer;
    s8* cur;
    s8 mapType;
    Shader* shader;
    int k;
    u32 scrollSlot;

    audioStopByMask(4);
    Sfx_ClearLoopedObjectSounds();
    nop_onUnloadMap(1, 0);
    for (layer = 0; layer < MAP_BLOCK_LAYER_COUNT; layer++)
    {
        cur = gMapBlockLayerTables[layer];
        for (i = 0; i < 256; i++)
        {
            mapType = cur[i];
            if (mapType >= 0)
            {
                gMapBlockRefCounts[mapType]--;
                if (gMapBlockRefCounts[mapType] == 0)
                {
                    block = gMapBlocks[mapType];
                    gMapBlockIds[mapType] = -1;
                    gMapBlocks[mapType] = NULL;
                    for (j = 0; j < block->shaderCount; j++)
                    {
                        shader = &block->shaders[j];
                        for (k = 0; k < shader->layerCount; k++)
                        {
                            shaderLayer = &shader->layers[k];
                            scrollSlot = shaderLayer->scrollMtx;
                            if (scrollSlot != 0xff)
                            {
                                if (gMapTextureScrolls[scrollSlot].refCount != 0)
                                    gMapTextureScrolls[scrollSlot].refCount -= 1;
                            }
                            if (shaderLayer->materialId != 0)
                                mapTextureOverrideRelease(shaderLayer->texture, shaderLayer->materialId);
                        }
                    }
                    for (j = 0; j < block->textureCount; j++)
                        textureFree(block->textures[j].texture);
                    if (block->auxData != NULL)
                        mm_free(block->auxData);
                    if (block->hits != NULL)
                        mm_free(block->hits);
                    setMapBlockFlag();
                    mm_free(block);
                }
            }
        }
    }
    gMapBlockCount = 0;
    Obj_ResetObjectSystem();
    for (i = 0; i < ROM_LIST_PAGE_COUNT; i++)
    {
        if (gLoadedRomListPages[i] != NULL)
        {
            mm_free(gLoadedRomListPages[i]);
            gLoadedRomListPages[i] = NULL;
        }
    }
    (*gCheckpointInterface)->reset();
    (*gRomCurveInterface)->initialise();
    gShaderRomListSlotCount = 0;
    playerMapOffsetX = 0.0f;
    playerMapOffsetZ = 0.0f;
    voxmaps_resetLoadedMaps();
    GameUI_releaseMenuResources();
    minimapFreeTexture();
    (*gNewCloudsInterface)->killSnowCloud(-1, 0);
    (*gCloudActionInterface)->freeCloudObjects();
}

s32 getCurMapLayer(void)
{
    return curMapLayer;
}

extern s8 gShaderMapTextDirTable[];

void mapLoadGameTextDir(u8 force)
{
    int curVal = gShaderCurMapEventId;
    if (curVal == -1)
        return;
    if (curVal == gShaderGameTextLoadedMapId && force == 0)
        return;
    gShaderGameTextLoadedMapId = curVal;
    if (curVal >= 0x76)
        return;
    {
        s8 entry = gShaderMapTextDirTable[curVal];
        if (entry == -1)
            return;
        gameTextLoadDir(entry);
    }
}


void mapSetup(int layerOffset, f32 x, int* outMapId, int* outMapDataFileId, f32 y, f32 z)
{
    MapInfoRecord* mapInfo;
    int gridZ;
    int mapId;
    int layerIndex;
    int mapCount;
    s8* layerOffsets;

    layerIndex = 0;
    layerOffsets = (s8*)(int)gMapLayerOffsets;
    if (layerOffsets[0] != layerOffset)
    {
        layerIndex = 1;
        if (layerOffsets[1] != layerOffset)
        {
            layerIndex = 2;
            if (layerOffsets[2] != layerOffset)
            {
                layerIndex = 3;
                if (layerOffsets[3] != layerOffset)
                {
                    layerIndex = 4;
                    if (layerOffsets[4] != layerOffset)
                    {
                        layerIndex = 5;
                    }
                }
            }
        }
    }
    curMapLayer = 0;
    gridZ = fastFloorf(z / gMapBlockWorldSize);
    mapId = mapCoordsToId((s32)fastFloorf(x / gMapBlockWorldSize), gridZ, layerIndex);
    mapCount = (s32)((u32)getDataFileSize(MLDF_FILEID_MAPINFO_BIN) >> 5);
    if (mapId < 0 || mapId >= mapCount)
    {
        curMapType = 0;
    }
    else
    {
        getTabEntry(mapInfo = (MapInfoRecord*)gMapInfoBuffer, MLDF_FILEID_MAPINFO_BIN, mapId << 5, 0x20);
        curMapType = mapInfo->mapType;
    }
    lbl_803DCEB4 = 0;
    if (curMapType == MAPTYPE_SUBMAP)
    {
        lbl_803DCEB6 = mapId;
        lbl_803DCEB4 = mapInfo->objType;
    }
    *outMapId = mapId;
    if (mapId != -1)
    {
        *outMapDataFileId = ((SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos())->mapDataFileId;
    }
}

void mapReloadWithFadeout(void)
{
    curMapType = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
}
s32 getCurMapType(void)
{
    return curMapType;
}

typedef struct
{
    Vec v[5];
} PlayerFrustumPlaneDirections;

typedef struct
{
    f32 v[5];
} PlayerFrustumPlaneScales;

STATIC_ASSERT(sizeof(PlayerFrustumPlaneDirections) == 0x3C);
STATIC_ASSERT(sizeof(PlayerFrustumPlaneScales) == 0x14);

const PlayerFrustumPlaneDirections sPlayerFrustumPlaneDirs = {
    {{0.0f, 0.0f, 1.0f},
     {1.0f, 0.0f, 0.0f},
     {-1.0f, 0.0f, 0.0f},
     {0.0f, 1.0f, 0.0f},
     {0.0f, -1.0f, 0.0f}}};
const PlayerFrustumPlaneScales sPlayerFrustumPlaneScales = {
    {0.0f, -25.0f, -25.0f, -25.0f, -25.0f}};

extern f32 gShaderDefaultTimeOfDay;
void beginLoadingMap(void)
{
    char* base;
    int i;
    int j;
    s8* a;
    s8* b;
    int currentCharacter;
    SaveGameCharacterPosition* characterPosition;
    f32 positionX, positionY, positionZ;
    Camera* camera;
    GameObject* player;
    SaveGameEnvState* environmentState;
    int enabled;
    char buf[0x110];

    base = gLightmapDrawQueue;
    if (gArrivedWarpIndex == -1)
    {
        gArrivedWarpIndex = -2;
        gWarpArrivalTimer = 8;
    }
    (*gObjectTriggerInterface)->onMapSetup();
    trackInitCollisionBuffers();
    for (i = 0; i < 5; i++)
    {
        a = ((s8**)(base + 0x41F4))[i];
        b = ((s8**)(base + 0x41E0))[i];
        for (j = 0; j < 256; j++)
        {
            a[j] = -1;
            b[j * 12 + 9] = -1;
        }
    }
    for (j = 0; j < 64; j++)
    {
        *(s16*)((char*)gMapBlockIds + j * 2) = -1;
        gMapBlocks[j] = NULL;
    }
    gMapBlockCount = 0;
    gShaderRomListSlotCount = 0;
    currentCharacter = (*gMapEventInterface)->getCurChar();
    characterPosition = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
    gMapBlockOriginX = fastFloorf(characterPosition->x / gMapBlockWorldSize);
    gMapBlockOriginZ = fastFloorf(characterPosition->z / gMapBlockWorldSize);
    *(f32*)(base + 0x8588) = characterPosition->x;
    *(f32*)(base + 0x858C) = characterPosition->y;
    *(f32*)(base + 0x8590) = characterPosition->z;
    *(int*)(base + 0x8594) = 1;
    gMapBlockOriginWorldX = gMapBlockOriginX * 640;
    gMapBlockOriginWorldZ = gMapBlockOriginZ * 640;
    playerMapOffsetX = gMapBlockOriginWorldX;
    playerMapOffsetZ = gMapBlockOriginWorldZ;
    gMapSavedPlayerOffsetX = playerMapOffsetX;
    gMapSavedPlayerOffsetZ = playerMapOffsetZ;
    gShaderCurMapEventId = -1;
    gShaderGameTextLoadedMapId = gShaderGameTextLoadedMapId - 1;
    gMapCurRomListSlot = -1;
    curMapLayer = characterPosition->mapLayer;
    renderFlags &= 0x82008;
    renderFlags |= 0x481F0LL;
    renderFlags |= 0x804;
    gMapLoadDeferred = 0;
    bEnableBlurFilter = 0;
    bEnableMotionBlur = 0;
    gMotionBlurAmount = 0.0f;
    gHeatEffectFadeDirection = -1;
    setSaveGameLoadingFlag();
    positionZ = characterPosition->z;
    positionY = characterPosition->y;
    positionX = characterPosition->x;
    if (!(renderFlags & 2) || (renderFlags & 0x800))
    {
        gShaderLoadCenterX = positionX;
        gShaderLoadCenterY = positionY;
        gShaderLoadCenterZ = positionZ;
        renderFlags |= 2;
        if (renderFlags & 0x800)
            doPendingMapLoads();
    }
    renderFlags &= ~4LL;
    trackIntersect();
    camera = Camera_GetCurrent();
    camera->x = characterPosition->x;
    camera->y = characterPosition->y;
    camera->z = characterPosition->z;
    mapSetupPlayer();
    gWarpRequested = 0;
    (*gWaterfxInterface)->onMapSetup();
    (*gProjgfxInterface)->onMapSetup();
    (*gModgfxInterface)->onMapSetup();
    (*gExpgfxInterface)->onMapSetup();
    (*gPartfxInterface)->onMapSetup();
    (*gCloudActionInterface)->freeCloudObjects();
    (*gCloudActionInterface)->onMapSetup();
    (*gSky2Interface)->onMapSetup();
    (*gSkyInterface)->loadLights();
    (*gNewCloudsInterface)->onMapSetup();
    waterFxInit();
    player = Obj_GetPlayerObject();
    if (gArrivedWarpIndex == -2 && player != NULL && (currentCharacter == 0 || currentCharacter == 1))
    {
        s16 cam2 = SaveGame_getCamActionNo();
        if (cam2 != -1)
        {
            (*gCameraInterface)->loadTriggeredCamAction(0, cam2, 1);
        }
        environmentState = saveGameGetEnvState();
        {
            s16 v = environmentState->skyEnvfxActIds[0];
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = environmentState->skyEnvfxActIds[1];
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = environmentState->cloudActionEnvfxActId;
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = environmentState->sky2EnvfxActId;
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
        }
        skySetSlotFlag80(1, (environmentState->envFlags & 2) ? 1 : 0);
        skySetSlotFlag80(2, (environmentState->envFlags & 4) ? 1 : 0);
        skySetLightIndex((environmentState->envFlags & 0x10) ? 1 : 0, 0.0f);
        if (environmentState->envFlags & 1)
            enabled = 1;
        else
            enabled = 0;
        {
            SaveGameEnvState* e2 = saveGameGetEnvState();
            if (enabled)
            {
                renderFlags |= 0x50;
                e2->envFlags = e2->envFlags | 9;
            }
            else
            {
                renderFlags &= ~0x50;
                e2->envFlags = e2->envFlags & ~9;
            }
        }
        if (environmentState->envFlags & 8)
            enabled = 1;
        else
            enabled = 0;
        {
            SaveGameEnvState* e3 = saveGameGetEnvState();
            if (enabled)
            {
                renderFlags |= 0x40;
                e3->envFlags = e3->envFlags | 8;
            }
            else
            {
                renderFlags &= ~0x40LL;
                e3->envFlags = e3->envFlags & ~8;
            }
        }
        if (environmentState->envFlags & 0x20)
            gHeatEffectFadeDirection = 1;
        else
            gHeatEffectFadeDirection = -1;
        ((GameObject*)buf)->anim.parent = NULL;
        ((GameObject*)buf)->anim.localPosX = 0.0f;
        ((GameObject*)buf)->anim.localPosY = 0.0f;
        ((GameObject*)buf)->anim.localPosZ = 0.0f;
        ((GameObject*)buf)->anim.worldPosX = 0.0f;
        ((GameObject*)buf)->anim.worldPosY = 0.0f;
        ((GameObject*)buf)->anim.worldPosZ = 0.0f;
        {
            s16 index = environmentState->cloudEnvfxActIds[0];
            if (index != -1)
            {
                ((GameObject*)buf)->anim.localPosX = (f32)environmentState->cloudPos[0][0];
                ((GameObject*)buf)->anim.localPosY = (f32)environmentState->cloudPos[0][1];
                ((GameObject*)buf)->anim.localPosZ = (f32)environmentState->cloudPos[0][2];
                getEnvfxAct(buf, player, index & 0xFFFF, 0);
            }
            index = environmentState->cloudEnvfxActIds[1];
            if (index != -1)
            {
                ((GameObject*)buf)->anim.localPosX = (f32)environmentState->cloudPos[1][0];
                ((GameObject*)buf)->anim.localPosY = (f32)environmentState->cloudPos[1][1];
                ((GameObject*)buf)->anim.localPosZ = (f32)environmentState->cloudPos[1][2];
                getEnvfxAct(buf, player, index & 0xFFFF, 0);
            }
            index = environmentState->cloudEnvfxActIds[2];
            if (index != -1)
            {
                ((GameObject*)buf)->anim.localPosX = (f32)environmentState->cloudPos[2][0];
                ((GameObject*)buf)->anim.localPosY = (f32)environmentState->cloudPos[2][1];
                ((GameObject*)buf)->anim.localPosZ = (f32)environmentState->cloudPos[2][2];
                getEnvfxAct(buf, player, index & 0xFFFF, 0);
            }
        }
        (*gSkyInterface)->setTimeOfDay(*(f32*)environmentState);
    }
    else
    {
        (*gSkyInterface)->setTimeOfDay(gShaderDefaultTimeOfDay);
        (*gCloudActionInterface)->func09Nop(1);
    }
    clearSaveGameLoadingFlag();
    Pause_SetDisabled(0);
    Pause_ResetMenuFrameCounter();
}

void mapGetBlockGridRects(int gridX, int gridZ, int* rectA, int* rectB, int* rectC, int* rectD, int layer, int useVisGrid, int slot)
{
    int base;
    MapBounds* e2;
    int aa, bb;
    MapRomListPage* page;
    u32* tbl;
    u32* tbl2;
    int index;
    int idx2;
    u32 v, v2;
    int cellVal;

    if (slot == -1)
    {
        rectA[0] = -1;
        rectA[1] = 1;
        rectA[2] = -1;
        rectA[3] = 1;
        rectB[0] = 0;
        rectB[1] = 0;
        rectB[2] = 0;
        rectB[3] = -1;
        rectC[0] = 0;
        rectC[1] = 0;
        rectC[2] = 0;
        rectC[3] = -1;
        rectD[0] = 0;
        rectD[1] = 0;
        rectD[2] = 0;
        rectD[3] = -1;
        if (layer != 0)
            rectA[3] = -2;
        return;
    }
    base = gShaderMapRomBuffers[1];
    e2 = (MapBounds*)base + gShaderRomListSlots[slot].slot;
    aa = gridX - e2->minX;
    bb = gridZ - e2->minZ;
    page = (MapRomListPage*)gShaderRomListSlots[slot].romlist;
    if (slot == -1)
    {
        rectA[0] = -1;
        rectA[1] = 1;
        rectA[2] = -1;
        rectA[3] = 1;
        rectB[0] = 0;
        rectB[1] = 0;
        rectB[2] = 0;
        rectB[3] = -1;
        rectC[0] = 0;
        rectC[1] = 0;
        rectC[2] = 0;
        rectC[3] = -1;
        rectD[0] = 0;
        rectD[1] = 0;
        rectD[2] = 0;
        rectD[3] = -1;
        if (layer != 0)
            rectA[3] = -2;
        return;
    }
    if (useVisGrid != 0)
    {
        tbl = page->visCellRects;
        tbl2 = page->visLayerRects;
    }
    else
    {
        tbl = page->cellRects;
        tbl2 = page->layerRects;
    }
    index = aa + bb * page->sizeX;
    idx2 = index * 2;
    if (layer == 0)
    {
        v = tbl[idx2];
        rectA[0] = ((v >> 12) & 0xf) - 7;
        rectA[2] = ((v >> 8) & 0xf) - 7;
        rectA[1] = ((v >> 4) & 0xf) - 7;
        rectA[3] = (v & 0xf) - 7;
        rectB[0] = (v >> 28) - 7;
        rectB[2] = ((v >> 24) & 0xf) - 7;
        rectB[1] = ((v >> 20) & 0xf) - 7;
        rectB[3] = ((v >> 16) & 0xf) - 7;
        v2 = tbl[idx2 + 1];
        rectC[0] = ((v2 >> 12) & 0xf) - 7;
        rectC[2] = ((v2 >> 8) & 0xf) - 7;
        rectC[1] = ((v2 >> 4) & 0xf) - 7;
        rectC[3] = (v2 & 0xf) - 7;
        rectD[0] = (v2 >> 28) - 7;
        rectD[2] = ((v2 >> 24) & 0xf) - 7;
        rectD[1] = ((v2 >> 20) & 0xf) - 7;
        rectD[3] = ((v2 >> 16) & 0xf) - 7;
    }
    else
    {
        rectA[0] = 0;
        rectA[1] = -1;
        rectA[2] = 0;
        rectA[3] = -1;
        rectB[0] = 0;
        rectB[1] = -1;
        rectB[2] = 0;
        rectB[3] = -1;
        rectC[0] = 0;
        rectC[1] = -1;
        rectC[2] = 0;
        rectC[3] = -1;
        rectD[0] = 0;
        rectD[1] = -1;
        rectD[2] = 0;
        rectD[3] = -1;
        cellVal = page->cells[idx2 >> 1] & 0x7f;
        if (cellVal != 127)
        {
            v2 = tbl2[layer - 1 + cellVal * 4];
            rectA[0] = ((v2 >> 12) & 0xf) - 7;
            rectA[2] = ((v2 >> 8) & 0xf) - 7;
            rectA[1] = ((v2 >> 4) & 0xf) - 7;
            rectA[3] = (v2 & 0xf) - 7;
            rectB[0] = (v2 >> 28) - 7;
            rectB[2] = ((v2 >> 24) & 0xf) - 7;
            rectB[1] = ((v2 >> 20) & 0xf) - 7;
            rectB[3] = ((v2 >> 16) & 0xf) - 7;
        }
    }
}

/* 16-byte texture-override table entry (array at gMapTextureOverrides, 80 slots). */

void goToPrevMapLayer(void)
{
    curMapLayer--;
    if (curMapLayer < -2)
    {
        curMapLayer = -2;
    }
    renderFlags |= 0x4000;
}

void goToNextMapLayer(void)
{
    curMapLayer++;
    if (curMapLayer > 2)
    {
        curMapLayer = 2;
    }
    renderFlags |= 0x4000;
}
static inline void mapMarkRectRows(char* g3, int* rect)
{
    int xx, zz;
    for (zz = rect[2]; zz <= rect[3]; zz++)
    {
        char* gp;
        xx = rect[0];
        gp = g3 + (zz + 7) * 16 + xx;
        for (; xx <= rect[1]; xx++)
        {
            gp[7] = -3;
            gp++;
        }
    }
}

extern char sTrackPiLockedFormat[];

void doPendingMapLoads(void)
{
    MapLoadRec* cellCursor;
    int gx, gz;
    s8** cBase;
    char* base;
    MapLoadRec* savedBlocks;
    int doLoad;
    u8 waited;
    int col;
    int slot;
    MapLoadRec* rowCursor;
    int layer;
    int colIdx;
    int colIdx2;
    int i2;
    int i;
    MapLoadRec* recsCursor;
    int cnt;
    f32 dz;
    char** aBase;
    char* cellGrid;
    int row;
    int n;
    int gridPass;
    MapLoadRec recs[300];
    int rectA[4], rectB[4], rectC[4], rectD[4];

    base = gLightmapDrawQueue;
    waited = 0;
    if (!(renderFlags & 0x1000))
    {
        gMapSavedPlayerOffsetX = playerMapOffsetX;
        gMapSavedPlayerOffsetZ = playerMapOffsetZ;
        if (gShaderCurMapEventId != -1 && gShaderCurMapEventId != gShaderGameTextLoadedMapId &&
            (gShaderGameTextLoadedMapId = gShaderCurMapEventId, gShaderCurMapEventId < 118) &&
            gShaderMapTextDirTable[gShaderCurMapEventId] != -1)
        {
            gameTextLoadDir(gShaderMapTextDirTable[gShaderCurMapEventId]);
        }
        if (!(renderFlags & 2) && (getLoadedFileFlags(0) != 0 || gMapPendingFileFlags == 0))
        {
            gMapPendingFileFlags = getLoadedFileFlags(0);
        }
        else
        {
            renderFlags &= ~2LL;
            dz = gShaderLoadCenterZ - playerMapOffsetZ;
            gx = fastFloorf((gShaderLoadCenterX - playerMapOffsetX) / gMapBlockWorldSize);
            gz = fastFloorf(dz / gMapBlockWorldSize);
            {
                u32 t = renderFlags;
                doLoad = t & 0x800;
                renderFlags = t & ~0x800LL;
            }
            {
                int ff = getLoadedFileFlags(0);
                if ((ff & ~0x100000) != 0)
                {
                    if (gShaderCurMapEventId != 38 && gShaderCurMapEventId != 58 && gShaderCurMapEventId != 59 &&
                        gShaderCurMapEventId != 60 && gShaderCurMapEventId != 61 && gShaderCurMapEventId != 62 &&
                        gShaderCurMapEventId != 28)
                    {
                        gMapLoadDeferred = 1;
                    }
                }
                else
                {
                    if (gMapLoadDeferred != 0)
                    {
                        gMapLoadDeferred = 0;
                        doLoad = 1;
                    }
                }
            }
            if (gx != 7 || gz != 7 || doLoad != 0 || (renderFlags & 0x4000))
            {
                MapCellEntry** eBase;

                shadowVolumesSetDirty(1);
                nop_onUnloadMap(1, 0);
                cnt = 0;
                layer = 0;
                {
                    MapCellEntry** cellTables;
                    char** gridTables;
                    s8** stateTables;
                    int k8;
                    s8 c;
                    eBase = (MapCellEntry**)(base + 0x41E0);
                    cellTables = eBase;
                    aBase = (char**)(base + 0x41F4);
                    gridTables = aBase;
                    cBase = (s8**)(base + 0x41CC);
                    stateTables = cBase;
                    savedBlocks = recs;
                    recsCursor = savedBlocks;
                    for (; layer < 5; layer++)
                    {
                        MapCellEntry* ent = *cellTables;
                        char* grid = *gridTables;
                        gMapLayerCellStates = *stateTables;
                        i = 0;
                        row = 0;
                        rowCursor = recsCursor;
                        cellGrid = grid;
                        for (; row < 16; row++)
                        {
                            colIdx = 0;
                            cellCursor = rowCursor;
                            for (k8 = 0; k8 < 8; k8++)
                            {
                                c = cellGrid[0];
                                if (c > -1)
                                {
                                    cellCursor->x = gMapBlockOriginX + colIdx;
                                    cellCursor->z = gMapBlockOriginZ + row;
                                    cellCursor->layer = layer;
                                    cellCursor->blockId = c;
                                    cellCursor++;
                                    rowCursor++;
                                    recsCursor++;
                                    cnt++;
                                }
                                cellGrid[0] = -2;
                                gMapLayerCellStates[i] = -1;
                                ent[0].blockId = -3;
                                ent[0].mapId = -1;
                                ent[0].adjacentMapId1 = -1;
                                ent[0].adjacentMapId2 = -1;
                                i2 = i + 1;
                                colIdx2 = colIdx + 1;
                                c = cellGrid[1];
                                if (c > -1)
                                {
                                    cellCursor->x = gMapBlockOriginX + colIdx2;
                                    cellCursor->z = gMapBlockOriginZ + row;
                                    cellCursor->layer = layer;
                                    cellCursor->blockId = c;
                                    cellCursor++;
                                    rowCursor++;
                                    recsCursor++;
                                    cnt++;
                                }
                                cellGrid[1] = -2;
                                gMapLayerCellStates[i2] = -1;
                                ent[1].blockId = -3;
                                ent[1].mapId = -1;
                                ent[1].adjacentMapId1 = -1;
                                ent[1].adjacentMapId2 = -1;
                                ent += 2;
                                i = i2 + 1;
                                cellGrid += 2;
                                colIdx = colIdx2 + 1;
                            }
                        }
                        cellTables++;
                        gridTables++;
                        stateTables++;
                    }
                }
                {
                    int nx = gx + gMapBlockOriginX;
                    int nz;
                    nx -= 7;
                    gMapBlockOriginX = nx;
                    nz = gz + gMapBlockOriginZ;
                    nz -= 7;
                    gMapBlockOriginZ = nz;
                }
                playerMapOffsetX = gMapBlockWorldSize * gMapBlockOriginX;
                playerMapOffsetZ = gMapBlockWorldSize * gMapBlockOriginZ;
                gMapBlockOriginWorldX = playerMapOffsetX;
                gMapBlockOriginWorldZ = playerMapOffsetZ;
                i = 0;
                {
                    int cn = gShaderRomListSlotCount;
                    for (; i < cn; i++)
                    {
                        ((ShaderRomListSlot*)(base + 0x418C))[i].flag = 0;
                    }
                }
                gShaderCurMapEventId = mapCoordsToId(gMapBlockOriginX + 7, gMapBlockOriginZ + 7, 0);
                gMapCurRomListSlot = -1;
                if (gShaderCurMapEventId == -1)
                {
                    int d = mapGetDirIdx(41);
                    setForceLoadImmediately();
                    mapLoadDataFile(d, MLDF_FILEID_TEX1_BIN_A);
                    mapLoadDataFile(d, MLDF_FILEID_TEX0_BIN_A);
                    mapLoadDataFile(d, MLDF_FILEID_ANIM_BIN_A);
                    mapLoadDataFile(d, MLDF_FILEID_MODELS_BIN_A);
                    mapLoadDataFile(d, MLDF_FILEID_TEX1_TAB_A);
                    mapLoadDataFile(d, MLDF_FILEID_MODELS_TAB_A);
                    mapLoadDataFile(d, MLDF_FILEID_ANIM_TAB_A);
                    mapLoadDataFile(d, MLDF_FILEID_TEX0_TAB_A);
                    clearForceLoadImmediately();
                    while (getLoadedFileFlags(0) != 0)
                    {
                        OSReport(sTrackPiLockedFormat, getLoadedFileFlags(0));
                        padUpdate();
                        checkReset();
                        if (waited)
                            waitNextFrame();
                        loadDataFiles();
                        dvdCheckError();
                        if (waited)
                        {
                            mmFreeTick(0);
                            gameTextRun();
                            GXFlush_(1, 0);
                        }
                        if (gDvdErrorPauseActive)
                            waited = 1;
                    }
                }
                else
                {
                    if (gShaderCurMapEventId != -1)
                    {
                        setForceLoadImmediately();
                        slot = mapFindRomListSlotByIdAt(base, gShaderCurMapEventId);
                        if (slot == -1)
                            slot = mapProcessRomList(gShaderCurMapEventId);
                        {
                            int mapId = gShaderCurMapEventId;
                            int sz = (int)((u32)getDataFileSize(MLDF_FILEID_MAPINFO_BIN) >> 5);
                            if (mapId < 0 || mapId >= sz)
                            {
                                curMapType = 0;
                            }
                            else
                            {
                                MapInfoRecord* e = (MapInfoRecord*)gMapInfoBuffer;
                                getTabEntry(e, MLDF_FILEID_MAPINFO_BIN, mapId << 5, 0x20);
                                curMapType = e->mapType;
                            }
                        }
                        ((ShaderRomListSlot*)(base + 0x418C))[slot].flag = 1;
                        gMapCurRomListSlot = slot;
                        mapCheckCurBlocks(mapGetDirIdx(gShaderCurMapEventId));
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), MLDF_FILEID_BLOCKS_TAB_A);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), MLDF_FILEID_BLOCKS_BIN_A);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), MLDF_FILEID_VOXMAP_TAB_A);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), MLDF_FILEID_VOXMAP_BIN_A);
                        gMapBlockIndexList = getCurrentDataFile(MLDF_FILEID_BLOCKS_TAB_A);
                        gMapBlockIndexCount = 0;
                        {
                            int* blockIndex;
                            for (blockIndex = gMapBlockIndexList; gMapBlockIndexList != 0 && *blockIndex != -1;)
                            {
                                blockIndex++;
                                gMapBlockIndexCount = gMapBlockIndexCount + 1;
                            }
                        }
                        gMapBlockIndexCount = gMapBlockIndexCount - 1;
                        /* Vestigial grid walk over each layer's cell table: writes only dead locals. */
                        for (i = 0; i < 5; i++)
                        {
                            cellGrid = (char*)*eBase;
                            row = 0;
                            for (gridPass = 0; gridPass < 2; gridPass++)
                            {
                                for (col = 0; col < 7; col++)
                                {
                                    for (n = 0; n < 16; n++)
                                    {
                                        cellGrid += 12;
                                    }
                                    row++;
                                }
                            }
                            eBase++;
                        }
                        {
                            int mapDir = mapGetDirIdx(gShaderCurMapEventId);
                            mapLoadDataFile(mapDir, MLDF_FILEID_TEX1_BIN_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_TEX0_BIN_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_ANIM_BIN_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_MODELS_BIN_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_ANIMCURV_BIN_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_TEX1_TAB_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_MODELS_TAB_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_ANIM_TAB_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_TEX0_TAB_A);
                            mapLoadDataFile(mapDir, MLDF_FILEID_ANIMCURV_TAB_A);
                        }
                        loadModelAndAnimTabs();
                        {
                            for (layer = 0; layer < 5; layer++)
                            {
                                char* g3;
                                mapGetBlockGridRects(gMapBlockOriginX + 7, gMapBlockOriginZ + 7, rectA, rectB, rectC, rectD,
                                               layer, 0, slot);
                                g3 = *aBase;
                                gMapLayerCellStates = *cBase;
                                mapMarkRectRows(g3, rectA);
                                mapMarkRectRows(g3, rectB);
                                mapMarkRectRows(g3, rectC);
                                mapMarkRectRows(g3, rectD);
                                {
                                    int loadedCount = 0;
                                    int zc[2];
                                    char* cellState;
                                    zc[0] = 0;
                                    zc[1] = zc[0];
                                    cellState = g3;
                                    do
                                    {
                                        for (col = 0; col < 16; col++)
                                        {
                                            int bx = gMapBlockOriginX + col;
                                            int bz = gMapBlockOriginZ + zc[1];
                                            if (*cellState == -3)
                                            {
                                                if (mapLoadBlock(col, zc[1], bx, bz, layer) == 0)
                                                {
                                                    *cellState = -2;
                                                }
                                                else
                                                {
                                                    gMapLayerCellStates[zc[0]] = (s8)loadedCount++;
                                                }
                                            }
                                            zc[0]++;
                                            cellState++;
                                        }
                                        zc[1]++;
                                    } while (zc[1] < 16);
                                }
                                aBase++;
                                cBase++;
                            }
                        }
                        clearForceLoadImmediately();
                    }
                }
                {
                    int slotIndex;
                    s8 first;
                    ShaderRomListSlot* romListSlot;

                    first = 1;
                    slotIndex = gShaderRomListSlotCount - 1;
                    romListSlot = (ShaderRomListSlot*)(base + 0x418C) + slotIndex;
                    for (; slotIndex >= 0; slotIndex--)
                    {
                        if (romListSlot->flag == 0)
                        {
                            if (romListSlot->romlist != NULL)
                            {
                                s16 sl = romListSlot->slot;
                                mapBuildRomListIndex(romListSlot->romlist, &((MapRomListIndex*)(base + 0x4208))[sl], sl, 1);
                                mm_free(romListSlot->romlist);
                                *(int*)(sl * 4 + 0x83A8 + base) = 0;
                            }
                            romListSlot->romlist = NULL;
                            romListSlot->slot = -1;
                        }
                        if (first)
                        {
                            if (romListSlot->romlist == NULL)
                                gShaderRomListSlotCount--;
                            else
                                first = 0;
                        }
                        romListSlot--;
                    }
                }
                {
                    for (i = 0; i < cnt; i++)
                    {
                        s16 blockId = savedBlocks->blockId;
                        if (blockId >= 0)
                        {
                            gMapBlockRefCounts[blockId] -= 1;
                            if (gMapBlockRefCounts[blockId] == 0)
                            {
                                MapBlockData* block = gMapBlocks[blockId];
                                Shader* shader;
                                ShaderLayer* shaderLayer;
                                int k;
                                u32 scrollSlot;
                                gMapBlockIds[blockId] = -1;
                                gMapBlocks[blockId] = NULL;
                                for (n = 0; n < block->shaderCount; n++)
                                {
                                    shader = &block->shaders[n];
                                    for (k = 0; k < shader->layerCount; k++)
                                    {
                                        shaderLayer = &shader->layers[k];
                                        scrollSlot = shaderLayer->scrollMtx;
                                        if (scrollSlot != 0xff)
                                        {
                                            if (gMapTextureScrolls[scrollSlot].refCount != 0)
                                                gMapTextureScrolls[scrollSlot].refCount -= 1;
                                        }
                                        if (shaderLayer->materialId != 0)
                                            mapTextureOverrideRelease(shaderLayer->texture,
                                                                      shaderLayer->materialId);
                                    }
                                }
                                for (n = 0; n < block->textureCount; n++)
                                    textureFree(block->textures[n].texture);
                                if (block->auxData != NULL)
                                    mm_free(block->auxData);
                                if (block->hits != NULL)
                                    mm_free(block->hits);
                                setMapBlockFlag();
                                mm_free(block);
                            }
                        }
                        savedBlocks++;
                    }
                }
                gMapCellRenderInstrBits = 0;
                gMapCellRenderInstrsEnabled = 0;
            }
            mapLoadUnloadObjects(doLoad);
            gMapPendingFileFlags = getLoadedFileFlags(0);
            renderFlags &= ~0x4000LL;
        }
    }
}

void loadMapForCameraPos(float x, float y, float z)
{
    if ((renderFlags & 2) != 0 && (renderFlags & 0x800) == 0)
        return;
    gShaderLoadCenterX = x;
    gShaderLoadCenterY = y;
    gShaderLoadCenterZ = z;
    renderFlags |= 2;
    if ((renderFlags & 0x800) != 0)
    {
        doPendingMapLoads();
    }
}

static void mapInitSetRects(MapBounds* rect, u8* bitmap, int originX, int originZ, int idx)
{
    MapsBinHeader* self = (MapsBinHeader*)gMapInfoBuffer;
    int tabOff = idx * 7 << 2;
    int offset0 = *(int*)(gMapsTab + tabOff);

    getTabEntry(self, MLDF_FILEID_MAPS_BIN, offset0, *(int*)((gMapsTab + 8) + tabOff) - offset0);
    self->cells = (u32*)((int)self + *(int*)((gMapsTab + 4) + tabOff) - *(int*)(gMapsTab + tabOff));
    rect->minX = originX - self->originX;
    rect->minZ = originZ - self->originZ;
    rect->maxX = rect->minX + self->sizeX - 1;
    rect->maxZ = rect->minZ + self->sizeZ - 1;
    rect->originX = self->originX;
    rect->originZ = self->originZ;
    for (originZ = 0; (s16)originZ < self->sizeZ; originZ++)
    {
        for (originX = 0; (s16)originX < self->sizeX; originX++)
        {
            int pixelIdx = (s16)originX + (s16)originZ * self->sizeX;
            if ((int)(self->cells[pixelIdx] >> 23 & 0xff) != 0xff)
            {
                bitmap[pixelIdx >> 3] |= 1 << (pixelIdx & 7);
            }
        }
    }
}

void initMaps(void)
{
    GlobalMapEntry* data;
    int total;
    int i;
    int ofs[1];
    int idx;
    MapBounds* e;

    data = 0;
    total = getDataFileSize(MLDF_FILEID_GLOBALMA_BIN);
    loadAssetFileById(&data, MLDF_FILEID_GLOBALMA_BIN);
    gShaderMapRomBuffers[0] = -1;
    gShaderMapRomBuffers[1] = (int)mmAlloc(1280, 5, 0);
    gShaderMapRomBuffers[2] = (int)mmAlloc(512, 5, 0);
    gShaderMapRomBuffers[3] = (int)mmAlloc(128, 5, 0);
    gShaderMapRomBuffers[4] = (int)mmAlloc(8192, 5, 0);
    memset((void*)gShaderMapRomBuffers[4], 0, 8192);
    idx = 0;
    ofs[0] = 0;
    for (i = 0; i < 16; i++)
    {
        INIT_MAP_SLOT(0);
        INIT_MAP_SLOT(1);
        INIT_MAP_SLOT(2);
        INIT_MAP_SLOT(3);
        INIT_MAP_SLOT(4);
        INIT_MAP_SLOT(5);
        INIT_MAP_SLOT(6);
        INIT_MAP_SLOT(7);
        ofs[0] += 80;
        idx += 8;
    }
    i = 0;
    total /= 12;
    while (i < total && data[i].mapId > -1)
    {
        *(s8*)((char*)gShaderMapRomBuffers[3] + data[i].mapId) =
            (s8)data[i].layer;
        mapInitSetRects((MapBounds*)gShaderMapRomBuffers[1] + data[i].mapId,
                        (u8*)((char*)gShaderMapRomBuffers[4] + data[i].mapId * 64),
                        data[i].originX, data[i].originZ,
                        data[i].mapId);
        ((s16*)gShaderMapRomBuffers[2])[data[i].mapId << 1] =
            data[i].adjacentMapId1;
        ((s16*)gShaderMapRomBuffers[2])[(data[i].mapId << 1) + 1] =
            data[i].adjacentMapId2;
        i++;
    }
    curMapType = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
    mm_free(data);
}

extern int gLastRomListPage;

MapRomList* mapGetCurrentRomList(void)
{
    char* p = (char*)gMapBlockCellEntryTables[0];
    int v = *(s16*)(p + 0x594);
    if (v < 0)
    {
        v = gLastRomListPage;
    }
    if (v < 0)
    {
        return 0;
    }
    {
        MapRomList* res = gLoadedRomListPages[v];
        if (res == 0)
        {
            return res;
        }
        gLastRomListPage = v;
        gCurRomListPage = res;
        return res;
    }
}

MapCellEntry* mapGetCellEntry(int x, int z)
{
    int* base = (int*)gMapBlockCellEntryTables[0];
    return (MapCellEntry*)((char*)base + (x + (z << 4)) * 12);
}


void mapFillCellEntry(int gridX, int gridZ, MapCellEntry* out, int layer)
{
    int id;

    id = mapCoordsToId(gridX, gridZ, layer);
    if (id != -1)
    {
        MapRomListPage* grid;
        int adjacentMapId2;
        ShaderRomListSlot* slots;
        char* activeFlags;
        int slot;
        int adjacentMapId1;
        s16* adjacentMapIds;
        MapBounds* mapBounds;
        u32 cell;

        slot = mapFindRomListSlotByIdAndGetBase(&slots, id);
        if (slot == -1)
            slot = mapProcessRomList(id);
        *(s8*)((activeFlags = (char*)gShaderRomListSlots + 6) + slot * 8) = 1;
        grid = (MapRomListPage*)gShaderRomListSlots[slot].romlist;
        adjacentMapIds = (s16*)gShaderMapRomBuffers[2];
        adjacentMapId1 = (s8)adjacentMapIds[id << 1];
        adjacentMapId2 = adjacentMapIds[(id << 1) + 1];
        adjacentMapId2 = (s8)adjacentMapId2;
        out->mapId = id;
        out->adjacentMapId1 = adjacentMapId1;
        out->adjacentMapId2 = adjacentMapId2;
        if (adjacentMapId1 != -1)
        {
            slot = mapFindRomListSlot(slots, adjacentMapId1);
            if (slot == -1)
                slot = mapProcessRomList(adjacentMapId1);
            *(s8*)(activeFlags + slot * 8) = 1;
        }
        if (adjacentMapId2 != -1)
        {
            slot = mapFindRomListSlotAndAdvance(&slots, adjacentMapId2);
            if (slot == -1)
                slot = mapProcessRomList(adjacentMapId2);
            *(s8*)(activeFlags + slot * 8) = 1;
        }
        mapBounds = (MapBounds*)gShaderMapRomBuffers[1] + id;
        gridZ = gridZ - mapBounds->minZ;
        gridX = gridX - mapBounds->minX;
        cell = grid->cells[gridX + gridZ * grid->sizeX];
        out->cellIndex = (cell >> 0x11) & 0x3f;
        out->romListIndex = (cell >> 0x17) & 0xff;
        if (out->romListIndex == 0xFF)
            out->romListIndex = -1;
        if (out->romListIndex == -1)
        {
            out->blockId = -1;
        }
        else
        {
            if (out->romListIndex >= gTrkBlkTabCount)
                out->romListIndex = gTrkBlkTabCount - 1;
            out->blockId = out->cellIndex + gTrkBlkTab[out->romListIndex];
            if (out->blockId >= gTrkBlkTab[gTrkBlkTabCount])
                out->blockId = gTrkBlkTab[gTrkBlkTabCount] - 1;
        }
    }
    else
    {
        out->mapId = -1;
        out->adjacentMapId1 = -1;
        out->adjacentMapId2 = -1;
        out->blockId = -2;
        out->romListIndex = -1;
        out->cellIndex = 0;
    }
}

MapRomListPage* mapGetRomListAndOffsets(int p1, int b);

void mapLoadForObject(int mapId, GameObject* obj)
{
    int saved = gShaderCurMapEventId;
    int slot;
    MapRomListPage* romList = mapGetRomListAndOffsets(mapId, 1);
    int i;
    slot = 0x50;

    for (i = 0; i < 40; i++)
    {
        if (gLoadedRomListPages[slot] == NULL)
        {
            gLoadedRomListPages[slot] = romList;
            break;
        }
        slot++;
    }
    obj->anim.hostedMapSlot = slot;
    (*gMapEventInterface)->setMapActLut(mapId, slot);
    mapBuildRomListIndex(romList, &gMapRomListIndexes[slot], slot, 0);
    (*gMapEventInterface)->updateObjGroups(slot);
    gShaderCurMapEventId = saved;
}

static void mapBuildRomListIndex(MapRomListPage* p, MapRomListIndex* tbl, int idx, int flag)
{
    char* cur;
    int count;
    int pos;
    u8 found;
    u32 mask;
    int* row;
    int entry;
    s16 t;
    int step;
    int n2;
    int minVal;

    found = 0;
    mask = 0;
    cur = (char*)p->objects;
    count = p->objectDataSize;
    if (count != 0)
    {
        pos = 0;
        if (flag == 0)
        {
            tbl->curvesOffset = -1;
            tbl->groupOffset[0] = -1;
            tbl->groupOffset[1] = -1;
            tbl->groupOffset[2] = -1;
            tbl->groupOffset[3] = -1;
            tbl->groupOffset[4] = -1;
            tbl->groupOffset[5] = -1;
            tbl->groupOffset[6] = -1;
            tbl->groupOffset[7] = -1;
            tbl->groupOffset[8] = -1;
            tbl->groupOffset[9] = -1;
            tbl->groupOffset[10] = -1;
            tbl->groupOffset[11] = -1;
            tbl->groupOffset[12] = -1;
            tbl->groupOffset[13] = -1;
            tbl->groupOffset[14] = -1;
            tbl->groupOffset[15] = -1;
            tbl->groupOffset[16] = -1;
            tbl->groupOffset[17] = -1;
            tbl->groupOffset[18] = -1;
            tbl->groupOffset[19] = -1;
            tbl->groupOffset[20] = -1;
            tbl->groupOffset[21] = -1;
            tbl->groupOffset[22] = -1;
            tbl->groupOffset[23] = -1;
            tbl->groupOffset[24] = -1;
            tbl->groupOffset[25] = -1;
            tbl->groupOffset[26] = -1;
            tbl->groupOffset[27] = -1;
            tbl->groupOffset[28] = -1;
            tbl->groupOffset[29] = -1;
            tbl->groupOffset[30] = -1;
            tbl->groupOffset[31] = -1;
        }
        for (; pos < count;)
        {
            if (flag != 0)
            {
                if (((ObjPlacement*)cur)->objectId == 110)
                    (*gRomCurveInterface)->remove((RomCurveDef*)cur);
                if (((ObjPlacement*)cur)->objectId == 5)
                    (*gCheckpointInterface)->removeRouteEntry((CheckpointRouteEntry*)cur);
            }
            else
            {
                t = ((ObjPlacement*)cur)->objectId;
                if (t == 110 || t == 5)
                {
                    if (t == 110)
                        (*gRomCurveInterface)->addCurveDef((RomCurveDef*)cur);
                    else
                        (*gCheckpointInterface)->addRouteEntry((CheckpointRouteEntry*)cur);
                    if (found == 0)
                    {
                        tbl->curvesOffset = (int)cur - (int)p->objects;
                        found = 1;
                    }
                }
                else if (((ObjPlacement*)cur)->loadFlags & 0x10)
                {
                    if ((mask & (1 << ((ObjPlacement*)cur)->loadRange)) == 0)
                    {
                        tbl->groupOffset[((ObjPlacement*)cur)->loadRange] = (int)cur - (int)p->objects;
                        mask |= 1 << ((ObjPlacement*)cur)->loadRange;
                    }
                }
            }
            step = ((ObjPlacement*)cur)->size * 4;
            pos += step;
            cur += step;
        }
        if (flag == 0)
        {
            minVal = count;
            entry = tbl->curvesOffset;
            if (entry != -1 && entry < count)
                minVal = entry;
            row = tbl->groupOffset;
            for (n2 = 0; n2 < 32; n2++)
            {
                entry = row[n2];
                if (entry != -1 && entry < minVal)
                    minVal = entry;
            }
            tbl->groupsStart = minVal;
            entry = tbl->curvesOffset;
            if (entry != -1)
                tbl->objectsSize = entry;
            else
                tbl->objectsSize = count;
        }
    }
}

#undef INIT_MAP_SLOT

void mapUnloadRomListPage(int pageIndex)
{
    int idx = pageIndex;
    MapRomListPage* p = gLoadedRomListPages[idx];
    if (p != 0)
    {
        mapBuildRomListIndex(p, &gMapRomListIndexes[idx], idx, 1);
        mm_free(gLoadedRomListPages[idx]);
        gLoadedRomListPages[idx] = 0;
    }
}

int mapCoordsToId(int x, int z, int layerIdx)
{
    int x0, z0;
    s8* layers;
    int x1;
    MapBounds* rects;
    u8* bits;
    int id;
    int layer;
    int idx;

    layer = curMapLayer + gMapLayerOffsets[layerIdx];
    rects = (MapBounds*)gShaderMapRomBuffers[1];
    bits = (u8*)gShaderMapRomBuffers[4];
    id = 0;
    layers = (s8*)gShaderMapRomBuffers[3];
    for (; id < 128; id++)
    {
        if (layer == layers[0])
        {
            x0 = rects->minX;
            if (x >= x0)
            {
                x1 = rects->maxX;
                if (x <= x1)
                {
                    z0 = rects->minZ;
                    if (z >= z0 && z <= rects->maxZ)
                    {
                        idx = (x - x0) + (z - z0) * ((x1 - x0) + 1);
                        if ((1 << (idx & 7)) & bits[idx >> 3])
                            return id;
                    }
                }
            }
        }
        rects++;
        bits += 0x40;
        layers += 1;
    }
    return -1;
}

char sShaderUnusedWordTable[172] = {
    0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 56, 0, 0, 0, 52, 0, 0, 0, 60,
    0, 0, 0, 56, 0, 0, 0, 60, 0, 0, 0, 64, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52,
    0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 56, 0, 0, 0, 52, 0, 0, 0, 56, 0, 0, 0, 68, 0, 0, 0, 52, 0, 0, 0, 60,
    0, 0, 0, 56, 0, 0, 0, 52, 0, 0, 0, 56, 0, 0, 0, 60, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52,
    0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 68, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52, 0, 0, 0, 52,
};

s8 gShaderMapTextDirTable[120] = {
    42, 42, 18, -1, 69, -1, -1, 44, 44, 23, 40, 71, 7,  70, 27, -1, 9,  -1, 36, 15, -1, 17, -1, 24,
    24, 24, 0,  16, 5,  8,  25, 14, 37, 20, 22, -1, -1, -1, 1,  12, 39, 72, -1, 10, 4,  -1, -1, -1,
    6,  -1, 13, 43, 19, -1, 38, -1, 29, -1, 1,  1,  1,  1,  1,  -1, -1, -1, -1, 30, 31, 32, 33, 26,
    34, 35, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4,  -1, -1, -1, -1, -1, -1, 0,  0,
};

f32 sAabbCornerDirections[24] = {
    1.0f,  1.0f, 1.0f, 1.0f,  -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, -1.0f, -1.0f, -1.0f,
    -1.0f, 1.0f, 1.0f, -1.0f, -1.0f, 1.0f, 1.0f,  1.0f, -1.0f, 1.0f,  -1.0f, -1.0f,
};

/* Screen-space (x,y) sample offsets used by the sun occlusion depth probe:
 * center plus the four corners of a 30-pixel box. */
SunOcclusionSample gSunOcclusionSampleOffsets[5] = {
    {0, 0}, {-15, -15}, {15, -15}, {15, 15}, {-15, 15},
};

/* Map-cell visit order for the opaque scene pass: outward from the two
   centre rows, i.e. front to back from a camera over the middle of the
   16x16 map-block grid. */
s8 gMapBlockDrawOrderFrontToBack[16] = {7, 6, 5, 4, 3, 2, 1, 0, 8, 9, 10, 11, 12, 13, 14, 15};

/* Map-cell visit order for the two blended scene passes: inward from both
   edges, i.e. back to front. */
s8 gMapBlockDrawOrderBackToFront[16] = {0, 15, 1, 14, 2, 13, 3, 12, 4, 11, 5, 10, 6, 9, 8, 7};

struct
{
    char passLevelObject[28];
    char failManualLoad[24];
    char failOutsideMap[40];
    char failNoBlock[24];
    char passBlockObject[28];
    char passInRange[24];
    char failOutOfRange[28];
} sShaderObjLoadMessages = {
    "LOAD PASS: Level object\n",
    "LOAD FAIL: Manual load\n",
    "LOAD FAIL: Outside map x=%f y=%f z=%f\n",
    "LOAD FAIL: No block\n",
    "LOAD PASS: Block object\n",
    "LOAD PASS: In range %f\n",
    "LOAD FAIL: Out of range\n",
};

char sTrackGlobalTexanimOverflowError[] = "TRACK ERROR: Global texanim overflow\n";

char sTrackLoadBlockOverrunError[] = "trackLoadBlockEnd: track block overrun\n";

char sTrackPiLockedFormat[] = "track piLocked %x\n";

char sTrackCellCoordFormat[] = " cellx %i celly %i cellz %i ";

void mapGetLoadedMapFlags(u8* outFlags)
{
    int i;
    int outer;
    for (outer = 0; outer < 0x78; outer++)
    {
        i = mapFindRomListSlotById(outer);
        if (i == -1)
        {
            outFlags[outer] = 0;
        }
        else
        {
            outFlags[outer] = 1;
        }
    }
}

int mapProcessRomList(int slot)
{
    char* base;
    int j;
    char* obj;
    int i;
    MapRomListPage* cur;
    u8 flag;
    ShaderRomListSlot* p;
    int count;
    ShaderRomListSlot* slots;
    ShaderRomListSlot* entry;
    s16* rects;
    int step;
    int rl;
    f32 dx, dz;

    base = gLightmapDrawQueue;
    flag = 0;
    while (isRomListLoading())
    {
        padUpdate();
        checkReset();
        if (flag)
            waitNextFrame();
        loadDataFiles();
        dvdCheckError();
        if (flag)
        {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (gDvdErrorPauseActive)
            flag = 1;
    }
    i = 0;
    p = (ShaderRomListSlot*)(base + 0x418C);
    count = gShaderRomListSlotCount;
    while (i < count && p->romlist != 0)
    {
        p++;
        i++;
    }
    if (i == count)
        gShaderRomListSlotCount++;
    rl = (int)mapGetRomListAndOffsets(slot, 0);
    slots = (ShaderRomListSlot*)(base + 0x418C);
    entry = &slots[i];
    entry->romlist = (void*)rl;
    *(int*)(slot * 4 + 0x83A8 + base) = rl;
    ((s16*)(base + 0x4190))[i * 4] = slot;
    gCurRomListPage = entry->romlist;
    rects = (s16*)(*(int*)(base + 0x417C) + slot * 10);
    ((MapRomListPage*)gCurRomListPage)->mapLayer = *(u8*)(*(int*)(base + 0x4184) + slot);
    ((MapRomListPage*)gCurRomListPage)->worldX = gMapBlockWorldSize * (f32)(rects[0] + ((MapRomListPage*)gCurRomListPage)->originX);
    ((MapRomListPage*)gCurRomListPage)->worldZ = gMapBlockWorldSize * (f32)(rects[2] + ((MapRomListPage*)gCurRomListPage)->originZ);
    cur = gCurRomListPage;
    dz = cur->worldZ;
    dx = cur->worldX;
    if (cur != 0)
    {
        obj = (char*)cur->objects;
        for (j = 0; j < cur->objectDataSize;)
        {
            if (saveGame_restoreObjectPosToRomList(obj) == 0)
            {
                ((GameObject*)obj)->anim.rootMotionScale += dx;
                ((GameObject*)obj)->anim.localPosY += dz;
            }
            step = ((ObjPlacement*)obj)->size * 4;
            j += step;
            obj += step;
        }
    }
    lbl_803DB620 = slot;
    return i;
}

MapRomListPage* mapGetRomListAndOffsets(int p1, int flag)
{
    int words = p1 * 7;
    int offset0 = *(int*)(gMapsTab + (words << 2));
    int tailLen = *(int*)((gMapsTab + 0x1c) + ((u32)words << 2)) - offset0;
    int v0, v1, v2;
    int i;

    mapsBinGetRomlistSize(offset0, &v0, &v1, &v2, words);
    gCurRomListPage = mmAlloc(tailLen + (v0 + 7 >> 3) + 0x401 + v2, 5, 0);
    fileLoadToBufferOffset(MLDF_FILEID_MAPS_BIN, gCurRomListPage, offset0, tailLen);

    ((MapRomListPage*)gCurRomListPage)->cells = (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 4) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->cellRects = (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 8) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->visCellRects = (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 0xc) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->layerRects = (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 0x10) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->visLayerRects = (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 0x14) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->objects = (ObjPlacement*)((int)gCurRomListPage + *(int*)((gMapsTab + 0x18) + (words << 2)) - offset0);

    piRomLoadSection(*(int*)((gMapsTab + 0x18) + (words << 2)), p1, ((MapRomListPage*)gCurRomListPage)->objects);
    ((MapRomListPage*)gCurRomListPage)->loadedObjectBits = (u8*)((*(int*)((gMapsTab + 0x1c) + (words << 2)) + v2) + (int)gCurRomListPage - offset0);

    for (i = 0; i < (v0 + 7 >> 3) + 1; i++)
    {
        ((MapRomListPage*)gCurRomListPage)->loadedObjectBits[i] = 0;
    }
    {
        f32 fillVal = 0.0f;
        ((MapRomListPage*)gCurRomListPage)->worldX = fillVal;
        ((MapRomListPage*)gCurRomListPage)->worldZ = fillVal;
    }
    ((MapRomListPage*)gCurRomListPage)->unk18 = 0;
    ((MapRomListPage*)gCurRomListPage)->mapLayer = 0;
    if (flag == 0)
    {
        mapBuildRomListIndex(gCurRomListPage, &gMapRomListIndexes[p1], p1, 0);
        (*gMapEventInterface)->updateObjGroups(p1);
    }
    return gCurRomListPage;
}


int ViewFrustum_IsSphereVisible(float* center, float radius)
{
    FrustumPlane* plane;
    u8 i = 0;
    f32 offZ = playerMapOffsetZ;
    f32 offX = playerMapOffsetX;
    for (; i < FRUSTUM_PLANE_COUNT; i++)
    {
        float dot;
        plane = &gViewFrustumPlanes[i];
        dot = plane->distance + (plane->normalZ * (center[2] - offZ) +
                                 (center[1] * plane->normalY + plane->normalX * (center[0] - offX)));
        if (radius + dot < 0.0f)
            return 0;
    }
    return 1;
}


int objUpdateOpacity(GameObject* obj)
{
    u8 op;
    ObjPlacement* ptr;
    int alpha;
    f32 range;
    f32 d;
    f32 near;
    GameObject* player;
    u8 i;
    f32 o1, o2, o3;
    f32 sz;
    f32 o5, o6;
    f32 prod;
    f32 offZ, offX;

    op = obj->anim.alpha;
    if (op == 0)
    {
        obj->anim.renderAlpha = 0;
        return 0;
    }
    ptr = (ObjPlacement*)obj->anim.placementData;
    if (ptr != 0 && (ptr->mapActFlagsHi & 1))
    {
        obj->anim.renderAlpha = (u8)(((op + 1) * 255) >> 8);
    }
    else
    {
        range = obj->anim.cullDistance2;
        if (range < 40.0f)
        {
            obj->anim.renderAlpha = 0;
            return 0;
        }
        player = Obj_GetPlayerObject();
        if (ptr != 0 && (ptr->mapActFlagsHi & 2) && player != 0)
        {
            d = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            d = Camera_DistanceToCurrentViewPosition(obj->anim.worldPosX,
                                                     obj->anim.worldPosY,
                                                     obj->anim.worldPosZ);
        }
        if (d > range)
        {
            obj->anim.renderAlpha = 0;
            return 0;
        }
        alpha = 255;
        near = range - 100.0f;
        if (d > near)
        {
            range = range - near;
            d = d - near;
            alpha = (int)(255.0f * (1.0f - d / range));
        }
        Camera_ProjectWorldSphere(obj->anim.worldPosX - playerMapOffsetX,
                                  obj->anim.worldPosY,
                                  obj->anim.worldPosZ - playerMapOffsetZ,
                                  obj->anim.hitboxScale * obj->anim.rootMotionScale, &o1,
                                  &o2, &o3, &sz, &o5, &o6);
        sz = __fabsf(sz);
        sz = sz * gMapBlockWorldSize;
        if (sz < 10.0f)
        {
            obj->anim.renderAlpha = 0;
            return 0;
        }
        if (sz < 15.0f)
        {
            alpha = (int)(((f32)alpha * (sz - 10.0f)) / 5.0f);
        }
        obj->anim.renderAlpha = (u8)((alpha * (obj->anim.alpha + 1)) >> 8);
    }
    if (obj->anim.renderAlpha == 0)
    {
        return 0;
    }
    else
    {
        prod = obj->anim.hitboxScale * obj->anim.rootMotionScale;
        i = 0;
        offZ = playerMapOffsetZ;
        offX = playerMapOffsetX;
        for (; i < FRUSTUM_PLANE_COUNT; i++)
        {
            FrustumPlane* plane = &gViewFrustumPlanes[i];
            if (prod + (plane->distance + (plane->normalZ * (obj->anim.worldPosZ - offZ) +
                                           (obj->anim.worldPosY * plane->normalY +
                                            plane->normalX * (obj->anim.worldPosX - offX)))) <
                0.0f)
                return 0;
        }
    }
    return 1;
}
void mapDebugRender(int* state)
{
    int y1;
    int y0;
    int sz;
    MapBlockData* blk;
    int dy;
    int sx;
    int y0a;
    int bz;
    int ci;
    int wx;
    f32 cy;
    int bx;
    int yy;
    s8* tbl;
    int h;
    int step;
    int celly;
    int cellx;
    int cellz;
    int cell;
    int v;
    int n;
    int wz;

    if (gMapCellRenderInstrsEnabled != 0)
    {
        bx = fastFloorf((gSceneCamera->x - playerMapOffsetX) / gMapBlockWorldSize);
        bz = fastFloorf((gSceneCamera->z - playerMapOffsetZ) / gMapBlockWorldSize);
        tbl = gMapBlockLayerTables[0];
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16)
        {
            blk = 0;
        }
        else
        {
            ci = tbl[bx + bz * 16];
            if (ci < 0 || ci >= gMapBlockCount)
            {
                blk = 0;
            }
            else
            {
                blk = gMapBlocks[ci];
            }
        }
        sx = (int)(gMapBlockWorldSize * fastFloorf(gSceneCamera->x / gMapBlockWorldSize));
        sz = (int)(gMapBlockWorldSize * fastFloorf(gSceneCamera->z / gMapBlockWorldSize));
        wx = (int)(gSceneCamera->x - sx);
        wz = (int)(gSceneCamera->z - sz);
        if (blk != 0)
        {
            y0 = blk->minY;
            y0a = y0;
            if (y0 & 1)
                y0a = y0 - 1;
            cy = gSceneCamera->y;
            y1 = blk->maxY;
            if (cy > y1)
                cy = (f32)(y1 - 1);
            yy = cy;
            dy = yy - y0a;
            h = y1 - y0;
            if (h / 80 < 8)
                step = h / 8;
            else
                step = 80;
            celly = dy / step;
            cellx = wx / 80;
            cellz = wz / 80;
            cell = celly * 0x40;
            cell += cellz * 8;
            cell += cellx;
            logPrintf(sTrackCellCoordFormat, cellx, celly, cellz);
            v = gMapCellRenderInstrBits;
            n = v >> 3;
            if (v & 7)
                n = n + 1;
            modelRenderInstrsState_init((ModelRenderInstrsState*)state, (void*)(gMapCellRenderInstrsTable + n * cell), v, v);
        }
    }
}

int mapBlockIsInViewFrustum(int bx, int bz, MapBlockData* block)
{
    f32 a1, a2, b1, b2, c1, c2;
    f32 p3;
    f32 fx, fz, x2, z2, y0, y1;
    f32 v;
    FrustumPlane* plane;
    int i;
    int j;
    int hit;

    fx = gMapBlockWorldSize * bx;
    fz = gMapBlockWorldSize * bz;
    x2 = gMapBlockWorldSize + fx;
    z2 = gMapBlockWorldSize + fz;
    if (block)
    {
        y0 = block->minY;
        y1 = block->maxY;
    }
    else
    {
        y0 = -100000.0f;
        y1 = 100000.0f;
    }
    plane = gViewFrustumPlanes;
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++)
    {
        f32 p0 = plane[i].normalX;
        f32 p1 = plane[i].normalY;
        f32 p2 = plane[i].normalZ;
        p3 = plane[i].distance;
        j = 0;
        hit = 0;
        a1 = fx * p0;
        a2 = x2 * p0;
        b1 = fz * p2;
        b2 = z2 * p2;
        c1 = y0 * p1;
        c2 = y1 * p1;
        while (j < 8 && hit == 0)
        {
            if (j & 1)
                v = a1;
            else
                v = a2;
            if (j & 2)
                v += b1;
            else
                v += b2;
            if (j & 4)
                v += c1;
            else
                v += c2;
            v += p3;
            if (v > 0.0f)
                hit = 1;
            j++;
        }
        if (j == 8 && hit == 0)
            return 0;
    }
    return 1;
}

void frustumPlanes_updateAabbCornerIndices(FrustumPlane* planes, int count)
{
    int k;
    int j;
    int bi;
    f32 best;
    f32 v;

    for (k = 0; k < count; k++)
    {
        best = 0.0f;
        j = 0;
        while (j < 24)
        {
            v = planes->normalX * sAabbCornerDirections[j++];
            v += planes->normalY * sAabbCornerDirections[j++];
            v += planes->normalZ * sAabbCornerDirections[j++];
            if (v > best)
            {
                best = v;
                bi = j - 3;
            }
        }
        switch (bi)
        {
        case 0:
            planes->aabbCornerIndex = 0;
            break;
        case 3:
            planes->aabbCornerIndex = 2;
            break;
        case 6:
            planes->aabbCornerIndex = 5;
            break;
        case 9:
            planes->aabbCornerIndex = 7;
            break;
        case 0xc:
            planes->aabbCornerIndex = 1;
            break;
        case 0xf:
            planes->aabbCornerIndex = 3;
            break;
        case 0x12:
            planes->aabbCornerIndex = 4;
            break;
        case 0x15:
            planes->aabbCornerIndex = 6;
            break;
        }
        planes++;
    }
}

void buildPlayerRelativeFrustumPlanes(void)
{
    Vec tmp;
    Vec camPos;
    PlayerFrustumPlaneScales scales;
    PlayerFrustumPlaneDirections planes;
    GameObject* player;
    Camera* viewSlot;
    FrustumPlane* outPtr;
    int i;
    f32* invRotMtx;
    f32 clipDist;

    planes = sPlayerFrustumPlaneDirs;
    scales = sPlayerFrustumPlaneScales;
    player = Obj_GetPlayerObject();
    viewSlot = Camera_GetCurrent();
    camPos.x = viewSlot->worldX - playerMapOffsetX;
    camPos.y = viewSlot->worldY;
    camPos.z = viewSlot->worldZ - playerMapOffsetZ;
    invRotMtx = Camera_GetInverseViewRotationMatrix();
    if (player != NULL)
    {
        clipDist = -Camera_DistanceToCurrentViewPosition(player->anim.worldPosX,
                                                         player->anim.worldPosY,
                                                         player->anim.worldPosZ);
    }
    else
    {
        clipDist = -100.0f;
    }
    scales.v[0] = clipDist;

    outPtr = gPlayerRelativeFrustumPlanes;
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++)
    {
        PSMTXMultVec((const f32 (*)[4])invRotMtx, &planes.v[i], (Vec*)&outPtr[i].normalX);
        PSVECScale(&outPtr[i].normal, &tmp, scales.v[i]);
        PSVECAdd(&camPos, &tmp, &tmp);
        outPtr[i].distance = -PSVECDotProduct(&tmp, &outPtr[i].normal);
    }
    frustumPlanes_updateAabbCornerIndices(gPlayerRelativeFrustumPlanes, FRUSTUM_PLANE_COUNT);
}

WarpVec gCameraPosByTransformSpace[0x29];
MapRomListPage* gLoadedRomListPages[ROM_LIST_PAGE_COUNT];
MapRomListIndex gMapRomListIndexes[120];
s8* gMapBlockLayerTables[MAP_BLOCK_LAYER_COUNT];
MapCellEntry* gMapBlockCellEntryTables[5];
s8* gMapBlockCellStateTables[5];
ShaderRomListSlot gShaderRomListSlots[8];
int gShaderMapRomBuffers[0x5];
f32 distortionFilterVector[0x1c];
ModelLightStruct* gGlowLightList[100];
u8 gCloudLayerTexMatrix[0x30];
char gLightmapDrawQueue[0x3F48];
