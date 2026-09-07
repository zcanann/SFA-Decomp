#include "main/lightmap_internal.h"
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
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/hud_visibility_api.h"
#include "main/render_flags.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_lifecycle_api.h"
#include "main/lightmap_render_queue_api.h"
#include "main/modellight_api.h"
#include "main/objprint_render_api.h"
#include "main/vecmath.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXManage.h"
#include "main/sky_state.h"
#include "main/newshadows.h"
#include "main/newshadows_shadow_api.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/dll_0031_minimap.h"
#include "dlls/objects/226.h"
#include "main/sky.h"
#include "track/intersect_render_setup_api.h"
#include "main/dll/cloudaction.h"
#include "main/trig.h"
#include "main/tex_dolphin.h"
#include "main/acosf_api.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTransform.h"
#include "main/lightmap.h"
#include "main/ground_shadow.h"
#include "main/lightmap_render_control_api.h"
#include "main/lightmap_text_color_api.h"
#include "dolphin/os/OSFastCast.h"
#include "main/map_block.h"
#include "main/track_dolphin_map_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/model_light.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "main/track_dolphin.h"
#define TRACK_BBOX_FLAGS_S8
#include "main/track_bbox_api.h"
#undef TRACK_BBOX_FLAGS_S8
#include "main/pause_menu_api.h"
#include "main/objmodel.h"
#include "main/newshadows_texture_api.h"
#include "dolphin/gx/GXDispList.h"
#include "track/intersect_fog_api.h"
#include "main/objseq_api.h"
#include "main/dll/FRONT/n_options.h"
#include "main/objprint_dolphin_internal.h"

extern MapRenderQueueStorage gLightmapDrawQueue;

static const GXColor sMapWhiteColor = {255, 255, 255, 255};
extern char sTrackLoadBlockOverrunError[];
extern char sShaderUnusedWordTable[];
#define MAP_BLOCK_LAYER_COUNT 5
#define FRUSTUM_PLANE_COUNT   5
static void trackLoadBlockEnd(MapBlockData* block, int blockId, int slotIdx, int layer);
/* One 0x20-byte MAPINFO.bin (fileId 0x1f) record, fetched by mapId via getTabEntry. */
typedef struct MapInfoRecord {
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
typedef struct ShaderRomListSlot {
    void* romlist;
    s16 slot;
    s8 flag;
    s8 pad;
} ShaderRomListSlot;

typedef struct ShaderRomListCursor {
    int index;
    ShaderRomListSlot* entry;
} ShaderRomListCursor;
extern int gShaderMapRomBuffers[];
#define INIT_MAP_SLOT(slot)                                                                                            \
    e = (MapBounds*)((char*)gShaderMapRomBuffers[1] + (slot) * 10 + ofs[0]);                                           \
    *(s8*)((char*)gShaderMapRomBuffers[3] + idx + (slot)) = -128;                                                      \
    e->minX = -32768;                                                                                                  \
    e->maxX = -32768;                                                                                                  \
    e->minZ = -32768;                                                                                                  \
    e->maxZ = -32768;                                                                                                  \
    e->originX = -128;                                                                                                 \
    e->originZ = -128;                                                                                                 \
    ((s16*)gShaderMapRomBuffers[2])[(idx + (slot)) << 1] = -1;                                                         \
    ((s16*)gShaderMapRomBuffers[2])[((idx + (slot)) << 1) + 1] = -1

typedef struct MapBounds {
    s16 minX;
    s16 maxX;
    s16 minZ;
    s16 maxZ;
    s8 originX;
    s8 originZ;
} MapBounds;

typedef struct MapsBinHeader {
    s16 sizeX;
    s16 sizeZ;
    s16 originX;
    s16 originZ;
    u8 unk08[4];
    u32* cells;
} MapsBinHeader;

typedef struct GlobalMapEntry {
    s16 originX;
    s16 originZ;
    s16 layer;
    s16 mapId;
    s16 adjacentMapId1;
    s16 adjacentMapId2;
} GlobalMapEntry;

typedef struct MapLoadRec {
    s16 x;
    s16 z;
    s16 blockId;
    s16 layer;
} MapLoadRec;

int mapProcessRomList(int slot);

u32 Rcp_GetColorFilterEnabled(void) {
    return bEnableColorFilter;
}

void Rcp_SetColorFilterEnabled(u32 x) {
    bEnableColorFilter = x;
}

void ObjHits_ConvertHitPositionToWorld(GameObject* object, f32* position) {
    if (object->anim.parent != NULL) {
        return;
    }
    position[0] += playerMapOffsetX;
    position[2] += playerMapOffsetZ;
}

void Rcp_DisableDistortionFilter(void) {
    bEnableDistortionFilter = 0x0;
}

extern f32 distortionFilterVector[];
extern GameObject* gLightmapDeferredObjects[];
extern ModelRenderInstrsState gMapCellRenderState;

void turnOnDistortionFilter(f32* vec, f32 angle2, u32* color, f32 angle1) {
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

void Rcp_DisableHeatEffect(void) {
    SaveGameEnvState* p = saveGameGetEnvState();
    gHeatEffectFadeDirection = -1;
    p->envFlags = (u8)(p->envFlags & ~0x20);
}

void Rcp_EnableHeatEffect(void) {
    SaveGameEnvState* p = saveGameGetEnvState();
    gHeatEffectFadeDirection = 1;
    p->envFlags = (u8)(p->envFlags | 0x20);
}
void Rcp_DisableBlurFilter(void) {
    bEnableBlurFilter = 0x0;
}

void turnOnBlurFilter(f32 x, f32 y, f32 z, u8 useArea, u8 bigger) {
    bEnableBlurFilter = 1;
    blurFilterX = x;
    blurFilterY = y;
    blurFilterZ = z;
    bBlurFilterUseArea = useArea;
    bBiggerBlurFilter = bigger;
}

u8 Rcp_GetViewFinderHudEnabled(void) {
    return bEnableViewFinderHud;
}
void Rcp_SetViewFinderHudEnabled(u8 x) {
    bEnableViewFinderHud = x;
}

void Rcp_SetSpiritVisionEnabled(u8 x) {
    bEnableSpiritVision = x;
}

void Rcp_SetMonochromeFilterEnabled(u8 x) {
    bEnableMonochromeFilter = x;
}

int Rcp_GetMotionBlurEnabled(void) {
    return bEnableMotionBlur;
}

void setMotionBlur(u8 enabled, f32 amount) {
    bEnableMotionBlur = enabled;
    gMotionBlurAmount = amount;
}

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2) {
    if (x < 0) {
        x = 0;
    }
    if (y < 0) {
        y = 0;
    }
    if (x2 < 0) {
        x2 = 0;
    }
    if (y2 < 0) {
        y2 = 0;
    }
    GXSetScissor(x, y, x2 - x, y2 - y);
}

void loadNextMap(void) {
    SaveGameCharacterPosition* pos;
    pos = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
    if (gArrivedWarpIndex != -1) {
        gWarpArrivalTimer -= 1;
        if ((s8)gWarpArrivalTimer < 0) {
            if (gArrivedWarpIndex > -1 && (s8)gRcpWarpTransitionType != 0) {
                (*gScreenTransitionInterface)->step(3, SCREEN_TRANSITION_BLACK);
            }
            gArrivedWarpIndex = -1;
            Pause_SetDisabled(0);
        }
    }
    if ((s8)gWarpRequested != 0) {
        if ((*gScreenTransitionInterface)->isFinished() != 0 || (s8)gRcpWarpTransitionType == 0) {
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

void warpToMap(int idx, s8 transType) {
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
    if (transType != 0) {
        (*gScreenTransitionInterface)->start(2, SCREEN_TRANSITION_BLACK);
    }
    Pause_SetDisabled(1);
}

static inline int objIsVisibleInAct(u8* def, int act) {
    if (act == -1) {
        return 0;
    }
    if (act != 0) {
        if (act < 9) {
            if ((def[3] >> (act - 1)) & 1) {
                return 0;
            }
        } else {
            if ((def[5] >> (0x10 - act)) & 1) {
                return 0;
            }
        }
    }
    return 1;
}

void mapInstantiateObjects(MapRomListPage* page, int mapId, int index, GameObject* parent) {
    MapRomListIndex* romListIndex = &gMapRomListIndexes[mapId];
    int i;
    char* p;
    char* obj;
    char* romBase;
    char* objStart;
    char* end;
    int objIndex;
    int v;
    int flag;
    int byteIdx;
    int bit;
    s8* vis;
    int visByte;

    if (romListIndex->groupOffset[index] == -1) {
        return;
    }
    objIndex = 0;
    romBase = (char*)page->objects;
    p = romBase;
    objStart = romBase + romListIndex->groupOffset[index];
    while (p < objStart) {
        objIndex++;
        p += ((ObjPlacement*)p)->size * 4;
    }
    for (i = index + 1; i <= 0x20; i++) {
        if (romListIndex->groupOffset[i] != -1) {
            break;
        }
    }
    obj = objStart;
    end = romBase + romListIndex->groupOffset[i];

    while (obj < end) {
        /* i reused below as the object-visible flag */
        if (objIndex < 0) {
            i = 0;
        } else {
            MapRomListPage* bm = gLoadedRomListPages[mapId];
            byteIdx = objIndex >> 3;
            if (byteIdx >= 0xc4) {
                i = 0;
            } else {
                i = 1;
                bit = 1 << (objIndex & 7);
                vis = (s8*)bm->loadedObjectBits;
                if ((bit & vis[byteIdx]) != 0) {
                    i = 1;
                } else {
                    i = 0;
                }
            }
        }
        if (i == 0) {
            v = (*gMapEventInterface)->getMapAct(mapId);
            flag = objIsVisibleInAct((u8*)obj, v);
            if (flag != 0) {
                if (objIndex >= 0) {
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

int objShouldUnload(GameObject* obj) {
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
    if (def == NULL) {
        return 0;
    }
    if (def[4] & 2) {
        return 0;
    }
    m = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    keep = objIsVisibleInAct(def, m);
    if (keep == 0) {
        return 1;
    }
    flags = def[4];
    if (flags & 1) {
        return 0;
    }
    if (flags & 0x10) {
        return !(u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, def[6]);
    }
    if (obj->pendingParentObj != NULL && obj->seqIndex < 0) {
        return 0;
    }
    if (obj->ownerObj != NULL) {
        return 0;
    }
    if (obj->anim.parent == NULL) {
        bx = (int)fastFloorf((obj->anim.localPosX - playerMapOffsetX) / 640.0f);
        bz = (int)fastFloorf((obj->anim.localPosZ - playerMapOffsetZ) / 640.0f);
        if (bx < 0 || bz < 0 || bx >= 0x10 || bz >= 0x10) {
            return 1;
        }
        found = 0;
        bx += (bz << 4);
        tp = gMapBlockLayerTables;
        for (k = 0; k < MAP_BLOCK_LAYER_COUNT; k++) {
            if ((*tp)[bx] >= 0) {
                found = 1;
            }
            tp++;
        }
        if (found == 0) {
            return 1;
        }
    }
    flags = def[4];
    if (flags & 0x20) {
        return 0;
    }
    if ((flags & 4) && (p = Obj_GetPlayerObject()) != NULL && obj->anim.parent == NULL) {
        x = p->anim.worldPosX;
        y = p->anim.worldPosY;
        z = p->anim.worldPosZ;
    } else {
        src = *(u8**)&obj->anim.parent;
        if (src != NULL) {
            idx2 = (s8)src[0x35] + 1;
        } else {
            idx2 = 0;
        }
        x = gCameraPosByTransformSpace[idx2].x;
        y = gCameraPosByTransformSpace[idx2].y;
        z = gCameraPosByTransformSpace[idx2].z;
    }
    dist = obj->anim.loadDistance;
    if (obj->anim.parent != NULL) {
        x -= obj->anim.localPosX;
        y -= obj->anim.localPosY;
        z -= obj->anim.localPosZ;
    } else {
        x -= obj->anim.worldPosX;
        y -= obj->anim.worldPosY;
        z -= obj->anim.worldPosZ;
    }
    if (x * x + y * y + z * z < (40.0f + dist) * (40.0f + dist)) {
        return 0;
    }
    return 1;
}

static inline int objVisibleForAct(ObjPlacement* placement, int t) {
    if (t == -1) {
        return 0;
    }
    if (t != 0) {
        if (t < 9) {
            if ((placement->mapActFlagsLo >> (t - 1)) & 1) {
                return 0;
            }
        } else {
            if ((placement->mapActFlagsHi >> (16 - t)) & 1) {
                return 0;
            }
        }
    }
    return 1;
}

static int objShouldLoad(ObjPlacement* placement, s8 viewSlot, int mapEventGroup) {
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
    if (placement->ident == 0x49054) {
        verbose = 1;
    } else {
        verbose = 0;
    }
    t = (*gMapEventInterface)->getMapAct(mapEventGroup);
    if (objVisibleForAct(placement, t) == 0) {
        return 0;
    }
    if (placement->loadFlags & 1) {
        if (verbose) {
            OSReport(strs + 0x1cc);
        }
        return 1;
    }
    if (placement->loadFlags & 2) {
        if (verbose) {
            OSReport(strs + 0x1e8);
        }
        return 0;
    }
    if (viewSlot == 0) {
        bx = fastFloorf((placement->posX - playerMapOffsetX) / 640.0f);
        bz = fastFloorf((placement->posZ - playerMapOffsetZ) / 640.0f);
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16) {
            if (verbose) {
                OSReport(strs + 0x200, &placement->posX, &placement->posY, &placement->posZ);
            }
            return 0;
        }
        found = 0;
        bx += bz << 4;
        for (i = 0; i < MAP_BLOCK_LAYER_COUNT; i++) {
            if (gMapBlockLayerTables[i][bx] >= 0) {
                found = 1;
            }
        }
        if (found == 0) {
            if (verbose) {
                OSReport(strs + 0x228);
            }
            return 0;
        }
    }
    if (placement->loadFlags & 0x20) {
        if (verbose) {
            OSReport(strs + 0x240);
        }
        return 1;
    }
    useObj = 0;
    if ((placement->loadFlags & 4) && viewSlot == 0) {
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            x = player->anim.worldPosX;
            y = player->anim.worldPosY;
            z = player->anim.worldPosZ;
        } else {
            useObj = 1;
        }
    } else {
        useObj = 1;
    }
    if (useObj != 0) {
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
    if (d < range * range) {
        if (verbose) {
            OSReport(strs + 0x25c, &d);
        }
        return 1;
    }
    if (verbose) {
        OSReport(strs + 0x274);
    }
    return 0;
}

void mapLoadUnloadObjects(int flag) {
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

    base = (char*)gLightmapDrawQueue.entries;
    count = 0;
    i = 0;
    tp = (int*)(base + 0x41E0);
    for (; i < 5; i++) {
        slot = 0;
        idPtr = (s16*)((char*)*tp + 0x594);
        for (; slot < 3; slot++) {
            s16 id = *idPtr;
            if (id >= 0 && id < 80 && *(void**)(base + (0x83A8 + id * 4)) != 0) {
                s16* w;
                s16 dup;
                int j2;

                dup = 0;
                w = list;
                for (j2 = 0; j2 < count; j2++) {
                    if (*w == *(s16*)(void*)idPtr) {
                        dup = 1;
                        break;
                    }
                    w++;
                }
                if (dup == 0) {
                    list[count++] = id;
                }
            }
            idPtr++;
        }
        tp++;
    }
    {
        GameObject** objs = ObjList_GetObjects(&i, &objCount);
        while (i < objCount) {
            obj = objs[i];
            fp = obj->anim.placement;
            i++;
            unload = 0;
            if (obj->anim.mapEventSlot > -1) {
                u8 fl = fp->loadFlags;
                if (!(fl & 2)) {
                    if (fl & 0x10) {
                        if (obj->anim.classId > -1 && objShouldUnload(obj)) {
                            unload = 1;
                        } else if (obj->anim.mapEventSlot < 80 &&
                                   *(void**)(base + (0x83A8 + obj->anim.mapEventSlot * 4)) == 0) {
                            unload = 1;
                        }
                    } else {
                        if (obj->anim.classId > -1 && objShouldUnload(obj)) {
                            unload = 1;
                        } else if (obj->anim.mapEventSlot < 80 && obj->anim.mapEventSlot != gShaderCurMapEventId) {
                            unload = 1;
                        }
                    }
                }
            }
            if (unload) {
                MapRomListPage* page = *(MapRomListPage**)(base + (0x83A8 + obj->anim.mapEventSlot * 4));
                if (page != 0) {
                    s16 tbit = obj->romListBit;
                    if (tbit >= 0 && tbit >= 0) {
                        u8* bb = page->loadedObjectBits;
                        *(s8*)&bb[tbit >> 3] = bb[tbit >> 3] & ~(1 << (tbit & 7));
                    }
                }
                if (obj->anim.romDefNo == SHADER_SNOWBIKE_OBJ) {
                    s16 j3;
                    int slotId;
                    s16* w2;

                    slotId = obj->anim.mapEventSlot;
                    j3 = 0;
                    w2 = list;
                    for (; j3 < count; j3++) {
                        if (slotId == *w2) {
                            break;
                        }
                        w2++;
                    }
                }
                Obj_FreeObject(obj);
                i--;
                objCount--;
            }
        }
    }
    if (getLoadedFileFlags(gShaderCurMapEventId) == 0) {
        for (i = 0; i < 80; i++) {
            if (((void**)(base + 0x83A8))[i] != NULL) {
                bits = (*gMapEventInterface)->getObjGroups(i);
                if (bits != 0) {
                    grpBit = 0;
                    while (bits != 0) {
                        if ((bits & 1) && SaveGame_findTransientMapBit(i, grpBit) == -1) {
                            mapInstantiateObjects((MapRomListPage*)((char**)(base + 0x83A8))[i], i, grpBit, NULL);
                            mapClearBit(i, grpBit);
                        }
                        bits >>= 1;
                        grpBit++;
                    }
                }
            }
        }
        for (i = 0; i < count; i++) {
            if (gShaderCurMapEventId == list[i]) {
                MapRomListPage* page = *(MapRomListPage**)(base + (0x83A8 + list[i] * 4));
                if (page != 0) {
                    mask = 1;
                    bit = 0;
                    cur = (u32)page->objects;
                    bp = page->loadedObjectBits;
                    end = cur + *(int*)(base + (0x4290 + list[i] * 0x8C));
                    while (cur < end) {
                        objStart = cur;
                        if ((*bp & mask) == 0 && objShouldLoad((ObjPlacement*)cur, 0, list[i]) != 0) {
                            s16 lid = list[i];
                            if (bit >= 0) {
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
                        if (mask == 0) {
                            bp++;
                            while (*bp == -1) {
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
            for (i = 0; i < objCount; i++) {
                GameObject* obj2 = (GameObject*)objs2[i];
                u32 mid2 = obj2->anim.hostedMapSlot;
                MapRomListPage* page2 = ((MapRomListPage**)(base + 0x83A8))[mid2];
                if (page2 != 0) {
                    int lp = obj2->anim.transformMatrixIndex + 1;
                    bit = 0;
                    cur = (u32)page2->objects;
                    end = cur + *(int*)(base + (0x4290 + mid2 * 0x8C));
                    bits = (*gMapEventInterface)->getObjGroups(mid2);
                    if (bits != 0) {
                        grpBit = 0;
                        while (bits != 0) {
                            if ((bits & 1) && SaveGame_findTransientMapBit(mid2, grpBit) == -1) {
                                mapInstantiateObjects(page2, mid2, grpBit, obj2);
                            }
                            bits >>= 1;
                            mapClearBit(mid2, grpBit);
                            grpBit++;
                        }
                    }
                    while (cur < end) {
                        if (bit < 0) {
                            vis = 0;
                        } else {
                            char* pg2 = ((char**)(base + 0x83A8))[mid2];
                            idx = bit >> 3;
                            if (idx >= 0xc4) {
                                vis = 0;
                            } else {
                                switch (((vis = 1) << (bit & 7)) & *(s8*)(*(int*)(pg2 + 0x10) + idx)) {
                                case 0:
                                    vis = 0;
                                    break;
                                }
                            }
                        }
                        if (vis == 0 && objShouldLoad((ObjPlacement*)cur, lp, mid2) != 0) {
                            if (bit >= 0) {
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

void mapUpdateCameraPosByTransformSpace(void) {
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
    for (k = 0; k < 31; k++) {
        gCameraPosByTransformSpace[k].valid = 0;
    }
    gCameraPosByTransformSpace[0].x = cam->worldX;
    gCameraPosByTransformSpace[0].y = cam->worldY;
    gCameraPosByTransformSpace[0].z = cam->worldZ;
    gCameraPosByTransformSpace[0].valid = 1;
    for (i = 0, e = objs; i < count; e++, i++) {
        GameObject* obj = *e;
        slot = obj->anim.transformMatrixIndex + 1;
        if (cam->parentObject == obj) {
            gCameraPosByTransformSpace[slot].x = cam->x;
            gCameraPosByTransformSpace[slot].y = cam->y;
            gCameraPosByTransformSpace[slot].z = cam->z;
        } else {
            Obj_TransformWorldPointToLocal(cam->worldX, cam->worldY, cam->worldZ, &lx, &ly, &lz, obj);
            gCameraPosByTransformSpace[slot].x = lx;
            gCameraPosByTransformSpace[slot].y = ly;
            gCameraPosByTransformSpace[slot].z = lz;
        }
        gCameraPosByTransformSpace[slot].valid = 1;
    }
}

MapTextureOverride* mapTextureOverrideGetEntry(int idx) {
    return &gMapTextureOverrides[idx];
}

s16* mapBlockFindTextureOverrideIndex(MapBlockData* block, int textureSlot) {
    return NULL;
}
int shaderReturnZeroStub(int unused) {
    return 0x0;
}

void mapTextureOverrideRelease(Texture* texture, int type) {
    int i;
    Texture* entryTexture;

    for (i = 0; i < 80; i++) {
        entryTexture = gMapTextureOverrides[i].texture;
        if (entryTexture == texture && gMapTextureOverrides[i].type == type && gMapTextureOverrides[i].refCount > 0) {
            gMapTextureOverrides[i].refCount -= 1;
            if (gMapTextureOverrides[i].refCount == 0) {
                gMapTextureOverrides[i].frame = 0;
                gMapTextureOverrides[i].type = 0;
                gMapTextureOverrides[i].texture = NULL;
                gMapTextureOverrides[i].flags = 0;
            }
        }
    }
}

extern char sTrackGlobalTexanimOverflowError[];

int mapTextureOverrideAcquire(Texture* texture, u32 flags, int type) {
    MapTextureOverride* base;
    int idx;
    int found;
    int idx2;

    found = -1;
    idx = 0;
    base = gMapTextureOverrides;
    for (; idx < 80; idx++) {
        if (base[idx].refCount != 0) {
            Texture* entryTexture = base[idx].texture;
            if (entryTexture == texture && type == base[idx].type) {
                found = idx;
                break;
            }
        }
    }
    if (found != -1) {
        base[found].refCount += 1;
        return found;
    }
    found = -1;
    idx2 = 0;
    base = gMapTextureOverrides;
    for (; idx2 < 80; idx2++) {
        if (base[idx2].refCount == 0) {
            found = idx2;
            break;
        }
    }
    if (found != -1) {
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

void mapTextureOverrideSetValue(int type, Texture* texture, int frame) {
    int i;

    for (i = 0; i < 80; i++) {
        if (gMapTextureOverrides[i].refCount > 0 && gMapTextureOverrides[i].texture == texture &&
            type == gMapTextureOverrides[i].type) {
            gMapTextureOverrides[i].frame = frame;
        }
    }
}

void mapTextureScrollGetOffset(int idx, float* outX, float* outY) {
    f32 divisor;
    *outX = gMapTextureScrolls[idx].offsetX / (divisor = 1048576.0f);
    *outY = gMapTextureScrolls[idx].offsetY / divisor;
}

void mapTextureScrollSetStep(int idx, int xStep, int yStep, int texWidthFixed, int texHeightFixed, int secondaryXStep,
                             int secondaryYStep, int texWidthFixed2, int texHeightFixed2) {
    MapTextureScroll* e = &gMapTextureScrolls[idx];
    e->xStep = (s16)((xStep << 16) / (texWidthFixed >> 6));
    e->yStep = (s16)((yStep << 16) / (texHeightFixed >> 6));
}

extern ShaderRomListSlot gShaderRomListSlots[8];

static inline int mapFindRomListSlot(ShaderRomListSlot* slots, int id) {
    int i2 = 0;
    ShaderRomListSlot* q2 = slots;
    int cn = gShaderRomListSlotCount;
    int k;
    for (k = 0; k < cn; k++) {
        if (q2->romlist != NULL && id == q2->slot) {
            return i2;
        }
        q2++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotAndAdvance(ShaderRomListSlot** slots, int id) {
    int i2 = 0;
    int cn = gShaderRomListSlotCount;
    int k;
    for (k = 0; k < cn; k++) {
        if ((*slots)->romlist != NULL && id == (*slots)->slot) {
            return i2;
        }
        (*slots)++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotByIdAt(char* base, int id) {
    ShaderRomListSlot* q2;
    int i2;
    int cn;
    int k;
    i2 = 0;
    q2 = (ShaderRomListSlot*)(base + 0x418C);
    cn = gShaderRomListSlotCount;
    for (k = 0; k < cn; k++) {
        if (q2->romlist != NULL && id == q2->slot) {
            return i2;
        }
        q2++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotById(int id) {
    ShaderRomListSlot* q2;
    int i2;
    int cn;
    int k;
    i2 = 0;
    q2 = gShaderRomListSlots;
    cn = gShaderRomListSlotCount;
    for (k = 0; k < cn; k++) {
        if (q2->romlist != NULL && id == q2->slot) {
            return i2;
        }
        q2++;
        i2++;
    }
    return -1;
}

static inline int mapFindRomListSlotByIdAndGetBase(ShaderRomListSlot** slots, int id) {
    int slotIndex;
    ShaderRomListSlot* cursor;
    int slotCount;
    int i;

    slotIndex = 0;
    *slots = cursor = gShaderRomListSlots;
    slotCount = gShaderRomListSlotCount;
    for (i = 0; i < slotCount; i++) {
        if (cursor->romlist != NULL && id == cursor->slot) {
            return slotIndex;
        }
        cursor++;
        slotIndex++;
    }
    return -1;
}

int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed, int secondaryXStep,
                            int secondaryYStep, int texWidthFixed2, int texHeightFixed2) {
    MapTextureScroll* base;
    MapTextureScroll* entry;
    int idx;
    int idx2;
    int slot;
    f32 init;

    idx = 0;
    entry = base = gMapTextureScrolls;
    for (; idx < 0x3a; idx++) {
        if (entry->xStep == xStep && entry->yStep == yStep) {
            entry->refCount += 1;
            return idx;
        }
        entry++;
    }
    slot = -1;
    for (idx2 = 0, entry = base; idx2 < 0x3a; entry++, idx2++) {
        if (entry->refCount == 0) {
            slot = idx2;
            break;
        }
    }
    if (slot == -1) {
        return -1;
    }
    entry = &base[slot];
    entry->xStep = (s16)((xStep << 16) / (texWidthFixed >> 6));
    entry->yStep = (s16)((yStep << 16) / (texHeightFixed >> 6));
    init = 0.0f;
    entry->offsetX = init;
    entry->offsetY = init;
    entry->refCount += 1;
    return slot;
}

static void trackLoadBlockEnd(MapBlockData* block, int blockId, int slotIdx, int layer) {
    int i;
    s16* arr;
    int count;
    s8* statusArr;

    i = 0;
    arr = gMapBlockIds;
    count = gMapBlockCount;
    for (; i < count; i++) {
        if (*arr == -1) {
            break;
        }
        arr++;
    }
    if (i == count) {
        gMapBlockCount++;
        if (gMapBlockCount == 0x40) {
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

static int mapLoadBlock(int cellX, int cellZ, int worldX, int worldZ, int layer) {
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
    if (mapCheckCurBlocks(entry->romListIndex) == -1) {
        statusArr[slotIdx] = -1;
        return 0;
    }
    if (blockId < 0) {
        blockId = -1;
    }
    if (blockId < 0) {
        statusArr[slotIdx] = blockId;
        return 0;
    }
    statusArr[slotIdx] = -1;

    j = 0;
    arr = gMapBlockIds;
    for (; j < gMapBlockCount; j++) {
        if (blockId == *arr) {
            gMapBlockRefCounts[j]++;
            statusArr[slotIdx] = j;
            return 1;
        }
        arr++;
    }

    block[0] = MapBlock_loadFromFile(blockId);
    if (block[0] != NULL) {
        MapBlock_init(block[0]);
        textureCursor[0] = 0;
        textureCursor[1] = textureCursor[0];
        while (textureCursor[0] < ((MapBlockData*)block[0])->textureCount) {
            int fileId =
                -(int)((u32)((MapTextureRef*)((u8*)((MapBlockData*)block[0])->textures + textureCursor[1]))->fileId |
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

static inline void mapReleaseBlockReference(int blockIndex) {
    if (blockIndex >= 0) {
        gMapBlockRefCounts[blockIndex]--;
        if (gMapBlockRefCounts[blockIndex] == 0) {
            int shaderOffset;
            Shader* shader;
            int textureIndex;
            int index;
            ShaderLayer* shaderLayer;
            int layerIndex;
            u32 scrollSlot;
            MapBlockData* block;

            block = gMapBlocks[blockIndex];
            gMapBlockIds[blockIndex] = -1;
            gMapBlocks[blockIndex] = NULL;
            index = 0;
            shaderOffset = 0;
            for (; index < block->shaderCount; shaderOffset += sizeof(Shader), index++) {
                shader = (Shader*)((u8*)block->shaders + shaderOffset);
                for (layerIndex = 0; layerIndex < shader->layerCount; layerIndex++) {
                    shaderLayer = &shader->layers[layerIndex];
                    scrollSlot = shaderLayer->scrollMtx;
                    if (scrollSlot != 0xff) {
                        if (gMapTextureScrolls[scrollSlot].refCount != 0) {
                            gMapTextureScrolls[scrollSlot].refCount -= 1;
                        }
                    }
                    if (shaderLayer->materialId != 0) {
                        mapTextureOverrideRelease(shaderLayer->texture, shaderLayer->materialId);
                    }
                }
            }
            for (textureIndex = 0; textureIndex < block->textureCount; textureIndex++) {
                textureFree(block->textures[textureIndex].texture);
            }
            if (block->auxData != NULL) {
                mm_free(block->auxData);
            }
            if (block->hits != NULL) {
                mm_free(block->hits);
            }
            setMapBlockFlag();
            mm_free(block);
        }
    }
}

void unloadMap(void) {
    int i;
    int layer;
    s8* cur;

    audioStopByMask(4);
    Sfx_ClearLoopedObjectSounds();
    nop_onUnloadMap(1, 0);
    for (layer = 0; layer < MAP_BLOCK_LAYER_COUNT; layer++) {
        cur = gMapBlockLayerTables[layer];
        for (i = 0; i < 256; i++) {
            mapReleaseBlockReference(cur[i]);
        }
    }
    gMapBlockCount = 0;
    Obj_ResetObjectSystem();
    for (i = 0; i < ROM_LIST_PAGE_COUNT; i++) {
        if (gLoadedRomListPages[i] != NULL) {
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

s32 getCurMapLayer(void) {
    return curMapLayer;
}

extern s8 gShaderMapTextDirTable[];

void mapLoadGameTextDir(u8 force) {
    int curVal = gShaderCurMapEventId;
    if (curVal == -1) {
        return;
    }
    if (curVal == gShaderGameTextLoadedMapId && force == 0) {
        return;
    }
    gShaderGameTextLoadedMapId = curVal;
    if (curVal >= 0x76) {
        return;
    }
    {
        s8 entry = gShaderMapTextDirTable[curVal];
        if (entry == -1) {
            return;
        }
        gameTextLoadDir(entry);
    }
}

void mapSetup(int layerOffset, f32 x, int* outMapId, int* outMapDataFileId, f32 y, f32 z) {
    MapInfoRecord* mapInfo;
    int gridZ;
    int mapId;
    int layerIndex;
    int mapCount;

    for (layerIndex = 0; layerIndex < MAP_BLOCK_LAYER_COUNT; layerIndex++) {
        if (gMapLayerOffsets[layerIndex] == layerOffset) {
            break;
        }
    }
    curMapLayer = 0;
    gridZ = fastFloorf(z / 640.0f);
    mapId = mapCoordsToId((s32)fastFloorf(x / 640.0f), gridZ, layerIndex);
    mapCount = (s32)((u32)getDataFileSize(MLDF_FILEID_MAPINFO_BIN) >> 5);
    if (mapId < 0 || mapId >= mapCount) {
        curMapType = 0;
    } else {
        getTabEntry(mapInfo = (MapInfoRecord*)gMapInfoBuffer, MLDF_FILEID_MAPINFO_BIN, mapId << 5, 0x20);
        curMapType = mapInfo->mapType;
    }
    lbl_803DCEB4 = 0;
    if (curMapType == MAPTYPE_SUBMAP) {
        lbl_803DCEB6 = mapId;
        lbl_803DCEB4 = mapInfo->objType;
    }
    *outMapId = mapId;
    if (mapId != -1) {
        *outMapDataFileId = ((SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos())->mapDataFileId;
    }
}

void mapReloadWithFadeout(void) {
    curMapType = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
}
s32 getCurMapType(void) {
    return curMapType;
}

typedef struct {
    Vec v[5];
} PlayerFrustumPlaneDirections;

typedef struct {
    f32 v[5];
} PlayerFrustumPlaneScales;

STATIC_ASSERT(sizeof(PlayerFrustumPlaneDirections) == 0x3C);
STATIC_ASSERT(sizeof(PlayerFrustumPlaneScales) == 0x14);

const PlayerFrustumPlaneDirections sPlayerFrustumPlaneDirs = {
    {{0.0f, 0.0f, 1.0f}, {1.0f, 0.0f, 0.0f}, {-1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, -1.0f, 0.0f}}};
const PlayerFrustumPlaneScales sPlayerFrustumPlaneScales = {{0.0f, -25.0f, -25.0f, -25.0f, -25.0f}};

void beginLoadingMap(void) {
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

    base = (char*)gLightmapDrawQueue.entries;
    if (gArrivedWarpIndex == -1) {
        gArrivedWarpIndex = -2;
        gWarpArrivalTimer = 8;
    }
    (*gObjectTriggerInterface)->onMapSetup();
    trackInitCollisionBuffers();
    for (i = 0; i < 5; i++) {
        a = ((s8**)(base + 0x41F4))[i];
        b = ((s8**)(base + 0x41E0))[i];
        for (j = 0; j < 256; j++) {
            a[j] = -1;
            b[j * 12 + 9] = -1;
        }
    }
    for (j = 0; j < 64; j++) {
        *(s16*)((char*)gMapBlockIds + j * 2) = -1;
        gMapBlocks[j] = NULL;
    }
    gMapBlockCount = 0;
    gShaderRomListSlotCount = 0;
    currentCharacter = (*gMapEventInterface)->getCurChar();
    characterPosition = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
    gMapBlockOriginX = fastFloorf(characterPosition->x / 640.0f);
    gMapBlockOriginZ = fastFloorf(characterPosition->z / 640.0f);
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
    gShaderGameTextLoadedMapId -= 1;
    gMapCurRomListSlot = -1;
    curMapLayer = characterPosition->mapLayer;
    renderFlags &= 0x82008;
    renderFlags |= 0x481F0;
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
    if (!(renderFlags & 2) || (renderFlags & 0x800)) {
        gShaderLoadCenterX = positionX;
        gShaderLoadCenterY = positionY;
        gShaderLoadCenterZ = positionZ;
        renderFlags |= 2;
        if (renderFlags & 0x800) {
            doPendingMapLoads();
        }
    }
    renderFlags &= ~4;
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
    if (gArrivedWarpIndex == -2 && player != NULL && (currentCharacter == 0 || currentCharacter == 1)) {
        s16 cam2 = SaveGame_getCamActionNo();
        if (cam2 != -1) {
            (*gCameraInterface)->loadTriggeredCamAction(0, cam2, 1);
        }
        environmentState = saveGameGetEnvState();
        {
            s16 v = environmentState->skyEnvfxActIds[0];
            if (v != -1) {
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            }
            v = environmentState->skyEnvfxActIds[1];
            if (v != -1) {
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            }
            v = environmentState->cloudActionEnvfxActId;
            if (v != -1) {
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            }
            v = environmentState->sky2EnvfxActId;
            if (v != -1) {
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            }
        }
        skySetSlotFlag80(1, (environmentState->envFlags & 2) ? 1 : 0);
        skySetSlotFlag80(2, (environmentState->envFlags & 4) ? 1 : 0);
        skySetLightIndex((environmentState->envFlags & 0x10) ? 1 : 0, 0.0f);
        if (environmentState->envFlags & 1) {
            enabled = 1;
        } else {
            enabled = 0;
        }
        {
            SaveGameEnvState* e2 = saveGameGetEnvState();
            if (enabled) {
                renderFlags |= 0x50;
                e2->envFlags |= 9;
            } else {
                renderFlags &= ~0x50;
                e2->envFlags &= ~9;
            }
        }
        if (environmentState->envFlags & 8) {
            enabled = 1;
        } else {
            enabled = 0;
        }
        {
            SaveGameEnvState* e3 = saveGameGetEnvState();
            if (enabled) {
                renderFlags |= 0x40;
                e3->envFlags |= 8;
            } else {
                renderFlags &= ~0x40;
                e3->envFlags &= ~8;
            }
        }
        if (environmentState->envFlags & 0x20) {
            gHeatEffectFadeDirection = 1;
        } else {
            gHeatEffectFadeDirection = -1;
        }
        ((GameObject*)buf)->anim.parent = NULL;
        ((GameObject*)buf)->anim.localPosX = 0.0f;
        ((GameObject*)buf)->anim.localPosY = 0.0f;
        ((GameObject*)buf)->anim.localPosZ = 0.0f;
        ((GameObject*)buf)->anim.worldPosX = 0.0f;
        ((GameObject*)buf)->anim.worldPosY = 0.0f;
        ((GameObject*)buf)->anim.worldPosZ = 0.0f;
        {
            s16 index = environmentState->cloudEnvfxActIds[0];
            if (index != -1) {
                ((GameObject*)buf)->anim.localPosX = (f32)environmentState->cloudPos[0][0];
                ((GameObject*)buf)->anim.localPosY = (f32)environmentState->cloudPos[0][1];
                ((GameObject*)buf)->anim.localPosZ = (f32)environmentState->cloudPos[0][2];
                getEnvfxAct(buf, player, index & 0xFFFF, 0);
            }
            index = environmentState->cloudEnvfxActIds[1];
            if (index != -1) {
                ((GameObject*)buf)->anim.localPosX = (f32)environmentState->cloudPos[1][0];
                ((GameObject*)buf)->anim.localPosY = (f32)environmentState->cloudPos[1][1];
                ((GameObject*)buf)->anim.localPosZ = (f32)environmentState->cloudPos[1][2];
                getEnvfxAct(buf, player, index & 0xFFFF, 0);
            }
            index = environmentState->cloudEnvfxActIds[2];
            if (index != -1) {
                ((GameObject*)buf)->anim.localPosX = (f32)environmentState->cloudPos[2][0];
                ((GameObject*)buf)->anim.localPosY = (f32)environmentState->cloudPos[2][1];
                ((GameObject*)buf)->anim.localPosZ = (f32)environmentState->cloudPos[2][2];
                getEnvfxAct(buf, player, index & 0xFFFF, 0);
            }
        }
        (*gSkyInterface)->setTimeOfDay(*(f32*)environmentState);
    } else {
        (*gSkyInterface)->setTimeOfDay(43000.0f);
        (*gCloudActionInterface)->func09Nop(1);
    }
    clearSaveGameLoadingFlag();
    Pause_SetDisabled(0);
    Pause_ResetMenuFrameCounter();
}

void mapGetBlockGridRects(int gridX, int gridZ, int* rectA, int* rectB, int* rectC, int* rectD, int layer,
                          int useVisGrid, int slot) {
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

    if (slot == -1) {
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
        if (layer != 0) {
            rectA[3] = -2;
        }
        return;
    }
    base = gShaderMapRomBuffers[1];
    e2 = (MapBounds*)base + gShaderRomListSlots[slot].slot;
    aa = gridX - e2->minX;
    bb = gridZ - e2->minZ;
    page = (MapRomListPage*)gShaderRomListSlots[slot].romlist;
    if (slot == -1) {
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
        if (layer != 0) {
            rectA[3] = -2;
        }
        return;
    }
    if (useVisGrid != 0) {
        tbl = page->visCellRects;
        tbl2 = page->visLayerRects;
    } else {
        tbl = page->cellRects;
        tbl2 = page->layerRects;
    }
    index = aa + bb * page->sizeX;
    idx2 = index * 2;
    if (layer == 0) {
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
    } else {
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
        if (cellVal != 127) {
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

void goToPrevMapLayer(void) {
    curMapLayer--;
    if (curMapLayer < -2) {
        curMapLayer = -2;
    }
    renderFlags |= 0x4000;
}

void goToNextMapLayer(void) {
    curMapLayer++;
    if (curMapLayer > 2) {
        curMapLayer = 2;
    }
    renderFlags |= 0x4000;
}
static inline void mapMarkRectRows(char* g3, int* rect) {
    int xx, zz;
    for (zz = rect[2]; zz <= rect[3]; zz++) {
        char* gp;
        xx = rect[0];
        gp = g3 + (zz + 7) * 16 + xx;
        for (; xx <= rect[1]; xx++) {
            gp[7] = -3;
            gp++;
        }
    }
}

extern char sTrackPiLockedFormat[];

void doPendingMapLoads(void) {
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
    MapLoadRec recs[300];
    int rectA[4], rectB[4], rectC[4], rectD[4];

    base = (char*)gLightmapDrawQueue.entries;
    waited = 0;
    if (!(renderFlags & 0x1000)) {
        gMapSavedPlayerOffsetX = playerMapOffsetX;
        gMapSavedPlayerOffsetZ = playerMapOffsetZ;
        if (gShaderCurMapEventId != -1 && gShaderCurMapEventId != gShaderGameTextLoadedMapId &&
            (gShaderGameTextLoadedMapId = gShaderCurMapEventId, gShaderCurMapEventId < 118) &&
            gShaderMapTextDirTable[gShaderCurMapEventId] != -1) {
            gameTextLoadDir(gShaderMapTextDirTable[gShaderCurMapEventId]);
        }
        if (!(renderFlags & 2) && (getLoadedFileFlags(0) != 0 || gMapPendingFileFlags == 0)) {
            gMapPendingFileFlags = getLoadedFileFlags(0);
        } else {
            renderFlags &= ~2;
            dz = gShaderLoadCenterZ - playerMapOffsetZ;
            gx = fastFloorf((gShaderLoadCenterX - playerMapOffsetX) / 640.0f);
            gz = fastFloorf(dz / 640.0f);
            {
                u32 t = renderFlags;
                doLoad = t & 0x800;
                renderFlags = t & ~0x800LL;
            }
            {
                int ff = getLoadedFileFlags(0);
                if ((ff & ~LOADED_FILE_FLAG_PI_LOCKED) != 0) {
                    if (gShaderCurMapEventId != 38 && gShaderCurMapEventId != 58 && gShaderCurMapEventId != 59 &&
                        gShaderCurMapEventId != 60 && gShaderCurMapEventId != 61 && gShaderCurMapEventId != 62 &&
                        gShaderCurMapEventId != 28) {
                        gMapLoadDeferred = 1;
                    }
                } else {
                    if (gMapLoadDeferred != 0) {
                        gMapLoadDeferred = 0;
                        doLoad = 1;
                    }
                }
            }
            if (gx != 7 || gz != 7 || doLoad != 0 || (renderFlags & 0x4000)) {
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
                    for (; layer < 5; layer++) {
                        MapCellEntry* ent = *cellTables;
                        char* grid = *gridTables;
                        gMapLayerCellStates = *stateTables;
                        i = 0;
                        row = 0;
                        rowCursor = recsCursor;
                        cellGrid = grid;
                        for (; row < 16; row++) {
                            colIdx = 0;
                            cellCursor = rowCursor;
                            for (k8 = 0; k8 < 8; k8++) {
                                c = cellGrid[0];
                                if (c > -1) {
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
                                if (c > -1) {
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
                playerMapOffsetX = 640.0f * gMapBlockOriginX;
                playerMapOffsetZ = 640.0f * gMapBlockOriginZ;
                gMapBlockOriginWorldX = playerMapOffsetX;
                gMapBlockOriginWorldZ = playerMapOffsetZ;
                i = 0;
                {
                    int cn = gShaderRomListSlotCount;
                    for (; i < cn; i++) {
                        ((ShaderRomListSlot*)(base + 0x418C))[i].flag = 0;
                    }
                }
                gShaderCurMapEventId = mapCoordsToId(gMapBlockOriginX + 7, gMapBlockOriginZ + 7, 0);
                gMapCurRomListSlot = -1;
                if (gShaderCurMapEventId == -1) {
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
                    while (getLoadedFileFlags(0) != 0) {
                        OSReport(sTrackPiLockedFormat, getLoadedFileFlags(0));
                        padUpdate();
                        checkReset();
                        if (waited) {
                            waitNextFrame();
                        }
                        loadDataFiles();
                        dvdCheckError();
                        if (waited) {
                            mmFreeTick(0);
                            gameTextRun();
                            GXFlush_(1, 0);
                        }
                        if (gDvdErrorPauseActive) {
                            waited = 1;
                        }
                    }
                } else {
                    if (gShaderCurMapEventId != -1) {
                        setForceLoadImmediately();
                        slot = mapFindRomListSlotByIdAt(base, gShaderCurMapEventId);
                        if (slot == -1) {
                            slot = mapProcessRomList(gShaderCurMapEventId);
                        }
                        {
                            int mapId = gShaderCurMapEventId;
                            int sz = (int)((u32)getDataFileSize(MLDF_FILEID_MAPINFO_BIN) >> 5);
                            if (mapId < 0 || mapId >= sz) {
                                curMapType = 0;
                            } else {
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
                            for (blockIndex = gMapBlockIndexList; gMapBlockIndexList != 0 && *blockIndex != -1;) {
                                blockIndex++;
                                gMapBlockIndexCount += 1;
                            }
                        }
                        gMapBlockIndexCount -= 1;
                        /* Vestigial grid walk over each layer's cell table: writes only dead locals. */
                        for (i = 0; i < 5; i++) {
                            cellGrid = (char*)*eBase;
                            for (row = 0; row < 16; row++) {
                                for (col = 0; col < 16; col++) {
                                    cellGrid += sizeof(MapCellEntry);
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
                            for (layer = 0; layer < 5; layer++) {
                                char* g3;
                                mapGetBlockGridRects(gMapBlockOriginX + 7, gMapBlockOriginZ + 7, rectA, rectB, rectC,
                                                     rectD, layer, 0, slot);
                                g3 = *aBase;
                                gMapLayerCellStates = *cBase;
                                mapMarkRectRows(g3, rectA);
                                mapMarkRectRows(g3, rectB);
                                mapMarkRectRows(g3, rectC);
                                mapMarkRectRows(g3, rectD);
                                {
                                    int loadedCount = 0;
                                    struct {
                                        int cellIndex;
                                        int row;
                                    } walk;
                                    char* cellState;
                                    walk.cellIndex = 0;
                                    walk.row = walk.cellIndex;
                                    cellState = g3;
                                    do {
                                        for (col = 0; col < 16; col++) {
                                            int bx = gMapBlockOriginX + col;
                                            int bz = gMapBlockOriginZ + walk.row;
                                            if (*cellState == -3) {
                                                if (mapLoadBlock(col, walk.row, bx, bz, layer) == 0) {
                                                    *cellState = -2;
                                                } else {
                                                    gMapLayerCellStates[walk.cellIndex] = (s8)loadedCount++;
                                                }
                                            }
                                            walk.cellIndex++;
                                            cellState++;
                                        }
                                        walk.row++;
                                    } while (walk.row < 16);
                                }
                                aBase++;
                                cBase++;
                            }
                        }
                        clearForceLoadImmediately();
                    }
                }
                {
                    ShaderRomListCursor cursor;
                    s8 first;

                    first = 1;
                    cursor.index = gShaderRomListSlotCount - 1;
                    cursor.entry = (ShaderRomListSlot*)(base + 0x418C) + cursor.index;
                    for (; cursor.index >= 0; cursor.index--) {
                        if (cursor.entry->flag == 0) {
                            if (cursor.entry->romlist != NULL) {
                                s16 sl = cursor.entry->slot;
                                mapBuildRomListIndex(cursor.entry->romlist, &((MapRomListIndex*)(base + 0x4208))[sl],
                                                     sl, 1);
                                mm_free(cursor.entry->romlist);
                                *(int*)(sl * 4 + 0x83A8 + base) = 0;
                            }
                            cursor.entry->romlist = NULL;
                            cursor.entry->slot = -1;
                        }
                        if (first) {
                            if (cursor.entry->romlist == NULL) {
                                gShaderRomListSlotCount--;
                            } else {
                                first = 0;
                            }
                        }
                        cursor.entry--;
                    }
                }
                {
                    for (i = 0; i < cnt; i++) {
                        s16 blockId = savedBlocks->blockId;
                        mapReleaseBlockReference(blockId);
                        savedBlocks++;
                    }
                }
                gMapCellRenderInstrBits = 0;
                gMapCellRenderInstrsEnabled = 0;
            }
            mapLoadUnloadObjects(doLoad);
            gMapPendingFileFlags = getLoadedFileFlags(0);
            renderFlags &= ~0x4000;
        }
    }
}

void loadMapForCameraPos(float x, float y, float z) {
    if ((renderFlags & 2) != 0 && (renderFlags & 0x800) == 0) {
        return;
    }
    gShaderLoadCenterX = x;
    gShaderLoadCenterY = y;
    gShaderLoadCenterZ = z;
    renderFlags |= 2;
    if ((renderFlags & 0x800) != 0) {
        doPendingMapLoads();
    }
}

static void mapInitSetRects(MapBounds* rect, u8* bitmap, int originX, int originZ, int idx) {
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
    for (originZ = 0; (s16)originZ < self->sizeZ; originZ++) {
        for (originX = 0; (s16)originX < self->sizeX; originX++) {
            int pixelIdx = (s16)originX + (s16)originZ * self->sizeX;
            if ((int)(self->cells[pixelIdx] >> 23 & 0xff) != 0xff) {
                bitmap[pixelIdx >> 3] |= 1 << (pixelIdx & 7);
            }
        }
    }
}

void initMaps(void) {
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
    for (i = 0; i < 16; i++) {
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
    while (i < total && data[i].mapId > -1) {
        *(s8*)((char*)gShaderMapRomBuffers[3] + data[i].mapId) = (s8)data[i].layer;
        mapInitSetRects((MapBounds*)gShaderMapRomBuffers[1] + data[i].mapId,
                        (u8*)((char*)gShaderMapRomBuffers[4] + data[i].mapId * 64), data[i].originX, data[i].originZ,
                        data[i].mapId);
        ((s16*)gShaderMapRomBuffers[2])[data[i].mapId << 1] = data[i].adjacentMapId1;
        ((s16*)gShaderMapRomBuffers[2])[(data[i].mapId << 1) + 1] = data[i].adjacentMapId2;
        i++;
    }
    curMapType = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
    mm_free(data);
}

extern int gLastRomListPage;

MapRomList* mapGetCurrentRomList(void) {
    char* p = (char*)gMapBlockCellEntryTables[0];
    int v = *(s16*)(p + 0x594);
    if (v < 0) {
        v = gLastRomListPage;
    }
    if (v < 0) {
        return 0;
    }
    {
        MapRomList* res = gLoadedRomListPages[v];
        if (res == 0) {
            return res;
        }
        gLastRomListPage = v;
        gCurRomListPage = res;
        return res;
    }
}

MapCellEntry* mapGetCellEntry(int x, int z) {
    int* base = (int*)gMapBlockCellEntryTables[0];
    return (MapCellEntry*)((char*)base + (x + (z << 4)) * 12);
}

void mapFillCellEntry(int gridX, int gridZ, MapCellEntry* out, int layer) {
    int id;

    id = mapCoordsToId(gridX, gridZ, layer);
    if (id != -1) {
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
        if (slot == -1) {
            slot = mapProcessRomList(id);
        }
        *(s8*)((activeFlags = (char*)gShaderRomListSlots + 6) + slot * 8) = 1;
        grid = (MapRomListPage*)gShaderRomListSlots[slot].romlist;
        adjacentMapIds = (s16*)gShaderMapRomBuffers[2];
        adjacentMapId1 = (s8)adjacentMapIds[id << 1];
        adjacentMapId2 = adjacentMapIds[(id << 1) + 1];
        adjacentMapId2 = (s8)adjacentMapId2;
        out->mapId = id;
        out->adjacentMapId1 = adjacentMapId1;
        out->adjacentMapId2 = adjacentMapId2;
        if (adjacentMapId1 != -1) {
            slot = mapFindRomListSlot(slots, adjacentMapId1);
            if (slot == -1) {
                slot = mapProcessRomList(adjacentMapId1);
            }
            *(s8*)(activeFlags + slot * 8) = 1;
        }
        if (adjacentMapId2 != -1) {
            slot = mapFindRomListSlotAndAdvance(&slots, adjacentMapId2);
            if (slot == -1) {
                slot = mapProcessRomList(adjacentMapId2);
            }
            *(s8*)(activeFlags + slot * 8) = 1;
        }
        mapBounds = (MapBounds*)gShaderMapRomBuffers[1] + id;
        gridZ -= mapBounds->minZ;
        gridX -= mapBounds->minX;
        cell = grid->cells[gridX + gridZ * grid->sizeX];
        out->cellIndex = (cell >> 0x11) & 0x3f;
        out->romListIndex = (cell >> 0x17) & 0xff;
        if (out->romListIndex == 0xFF) {
            out->romListIndex = -1;
        }
        if (out->romListIndex == -1) {
            out->blockId = -1;
        } else {
            if (out->romListIndex >= gTrkBlkTabCount) {
                out->romListIndex = gTrkBlkTabCount - 1;
            }
            out->blockId = out->cellIndex + gTrkBlkTab[out->romListIndex];
            if (out->blockId >= gTrkBlkTab[gTrkBlkTabCount]) {
                out->blockId = gTrkBlkTab[gTrkBlkTabCount] - 1;
            }
        }
    } else {
        out->mapId = -1;
        out->adjacentMapId1 = -1;
        out->adjacentMapId2 = -1;
        out->blockId = -2;
        out->romListIndex = -1;
        out->cellIndex = 0;
    }
}

MapRomListPage* mapGetRomListAndOffsets(int p1, int b);

void mapLoadForObject(int mapId, GameObject* obj) {
    int saved = gShaderCurMapEventId;
    int slot;
    MapRomListPage* romList = mapGetRomListAndOffsets(mapId, 1);
    int i;
    slot = 0x50;

    for (i = 0; i < 40; i++) {
        if (gLoadedRomListPages[slot] == NULL) {
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

static void mapBuildRomListIndex(MapRomListPage* p, MapRomListIndex* tbl, int idx, int flag) {
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
    if (count != 0) {
        pos = 0;
        if (flag == 0) {
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
        for (; pos < count;) {
            if (flag != 0) {
                if (((ObjPlacement*)cur)->objectId == 110) {
                    (*gRomCurveInterface)->remove((RomCurveDef*)cur);
                }
                if (((ObjPlacement*)cur)->objectId == 5) {
                    (*gCheckpointInterface)->removeRouteEntry((CheckpointRouteEntry*)cur);
                }
            } else {
                t = ((ObjPlacement*)cur)->objectId;
                if (t == 110 || t == 5) {
                    if (t == 110) {
                        (*gRomCurveInterface)->addCurveDef((RomCurveDef*)cur);
                    } else {
                        (*gCheckpointInterface)->addRouteEntry((CheckpointRouteEntry*)cur);
                    }
                    if (found == 0) {
                        tbl->curvesOffset = (int)(cur - (char*)p->objects);
                        found = 1;
                    }
                } else if (((ObjPlacement*)cur)->loadFlags & 0x10) {
                    if ((mask & (1 << ((ObjPlacement*)cur)->loadRange)) == 0) {
                        tbl->groupOffset[((ObjPlacement*)cur)->loadRange] = (int)(cur - (char*)p->objects);
                        mask |= 1 << ((ObjPlacement*)cur)->loadRange;
                    }
                }
            }
            step = ((ObjPlacement*)cur)->size * 4;
            pos += step;
            cur += step;
        }
        if (flag == 0) {
            minVal = count;
            entry = tbl->curvesOffset;
            if (entry != -1 && entry < count) {
                minVal = entry;
            }
            row = tbl->groupOffset;
            for (n2 = 0; n2 < 32; n2++) {
                entry = row[n2];
                if (entry != -1 && entry < minVal) {
                    minVal = entry;
                }
            }
            tbl->groupsStart = minVal;
            entry = tbl->curvesOffset;
            if (entry != -1) {
                tbl->objectsSize = entry;
            } else {
                tbl->objectsSize = count;
            }
        }
    }
}

#undef INIT_MAP_SLOT

void mapUnloadRomListPage(int pageIndex) {
    int idx = pageIndex;
    MapRomListPage* p = gLoadedRomListPages[idx];
    if (p != 0) {
        mapBuildRomListIndex(p, &gMapRomListIndexes[idx], idx, 1);
        mm_free(gLoadedRomListPages[idx]);
        gLoadedRomListPages[idx] = 0;
    }
}

int mapCoordsToId(int x, int z, int layerIdx) {
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
    for (; id < 128; id++) {
        if (layer == layers[0]) {
            x0 = rects->minX;
            if (x >= x0) {
                x1 = rects->maxX;
                if (x <= x1) {
                    z0 = rects->minZ;
                    if (z >= z0 && z <= rects->maxZ) {
                        idx = (x - x0) + (z - z0) * ((x1 - x0) + 1);
                        if ((1 << (idx & 7)) & bits[idx >> 3]) {
                            return id;
                        }
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

struct {
    char passLevelObject[28];
    char failManualLoad[24];
    char failOutsideMap[40];
    char failNoBlock[24];
    char passBlockObject[28];
    char passInRange[24];
    char failOutOfRange[28];
} sShaderObjLoadMessages = {
    "LOAD PASS: Level object\n", "LOAD FAIL: Manual load\n",  "LOAD FAIL: Outside map x=%f y=%f z=%f\n",
    "LOAD FAIL: No block\n",     "LOAD PASS: Block object\n", "LOAD PASS: In range %f\n",
    "LOAD FAIL: Out of range\n",
};

char sTrackGlobalTexanimOverflowError[] = "TRACK ERROR: Global texanim overflow\n";

char sTrackLoadBlockOverrunError[] = "trackLoadBlockEnd: track block overrun\n";

char sTrackPiLockedFormat[] = "track piLocked %x\n";

char sTrackCellCoordFormat[] = " cellx %i celly %i cellz %i ";

void mapGetLoadedMapFlags(u8* outFlags) {
    int i;
    int outer;
    for (outer = 0; outer < 0x78; outer++) {
        i = mapFindRomListSlotById(outer);
        if (i == -1) {
            outFlags[outer] = 0;
        } else {
            outFlags[outer] = 1;
        }
    }
}

int mapProcessRomList(int slot) {
    char* base;
    int j;
    char* obj;
    MapRomListPage* cur;
    u8 flag;
    ShaderRomListSlot* p;
    int count;
    ShaderRomListSlot* slots;
    s16* rects;
    ShaderRomListCursor cursor;
    int step;
    int rl;
    f32 dx, dz;

    base = (char*)gLightmapDrawQueue.entries;
    flag = 0;
    while (isRomListLoading()) {
        padUpdate();
        checkReset();
        if (flag) {
            waitNextFrame();
        }
        loadDataFiles();
        dvdCheckError();
        if (flag) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (gDvdErrorPauseActive) {
            flag = 1;
        }
    }
    cursor.index = 0;
    p = (ShaderRomListSlot*)(base + 0x418C);
    count = gShaderRomListSlotCount;
    while (cursor.index < count && p->romlist != 0) {
        p++;
        cursor.index++;
    }
    if (cursor.index == count) {
        gShaderRomListSlotCount++;
    }
    rl = (int)mapGetRomListAndOffsets(slot, 0);
    slots = (ShaderRomListSlot*)(base + 0x418C);
    cursor.entry = &slots[cursor.index];
    cursor.entry->romlist = (void*)rl;
    {
        const int cacheOffset = slot * sizeof(void*);
        const int cacheBase = (int)(base + 0x83A8);
        *(int*)(cacheOffset + cacheBase) = rl;
    }
    ((s16*)(base + 0x4190))[cursor.index * 4] = slot;
    gCurRomListPage = cursor.entry->romlist;
    rects = (s16*)(*(int*)(base + 0x417C) + slot * 10);
    ((MapRomListPage*)gCurRomListPage)->mapLayer = *(u8*)(*(int*)(base + 0x4184) + slot);
    ((MapRomListPage*)gCurRomListPage)->worldX = 640.0f * (f32)(rects[0] + ((MapRomListPage*)gCurRomListPage)->originX);
    ((MapRomListPage*)gCurRomListPage)->worldZ = 640.0f * (f32)(rects[2] + ((MapRomListPage*)gCurRomListPage)->originZ);
    cur = gCurRomListPage;
    dz = cur->worldZ;
    dx = cur->worldX;
    if (cur != 0) {
        obj = (char*)cur->objects;
        for (j = 0; j < cur->objectDataSize;) {
            if (saveGame_restoreObjectPosToRomList(obj) == 0) {
                ((ObjPlacement*)obj)->posX += dx;
                ((ObjPlacement*)obj)->posZ += dz;
            }
            step = ((ObjPlacement*)obj)->size * 4;
            j += step;
            obj += step;
        }
    }
    lbl_803DB620 = slot;
    return cursor.index;
}

MapRomListPage* mapGetRomListAndOffsets(int p1, int flag) {
    int words = p1 * 7;
    int offset0 = *(int*)(gMapsTab + (words << 2));
    int tailLen = *(int*)((gMapsTab + 0x1c) + ((u32)words << 2)) - offset0;
    int v0, v1, v2;
    int i;

    mapsBinGetRomlistSize(offset0, &v0, &v1, &v2, words);
    gCurRomListPage = mmAlloc(tailLen + (v0 + 7 >> 3) + 0x401 + v2, 5, 0);
    fileLoadToBufferOffset(MLDF_FILEID_MAPS_BIN, gCurRomListPage, offset0, tailLen);

    ((MapRomListPage*)gCurRomListPage)->cells =
        (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 4) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->cellRects =
        (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 8) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->visCellRects =
        (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 0xc) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->layerRects =
        (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 0x10) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->visLayerRects =
        (u32*)((int)gCurRomListPage + *(int*)((gMapsTab + 0x14) + (words << 2)) - offset0);
    ((MapRomListPage*)gCurRomListPage)->objects =
        (ObjPlacement*)((int)gCurRomListPage + *(int*)((gMapsTab + 0x18) + (words << 2)) - offset0);

    piRomLoadSection(*(int*)((gMapsTab + 0x18) + (words << 2)), p1, ((MapRomListPage*)gCurRomListPage)->objects);
    ((MapRomListPage*)gCurRomListPage)->loadedObjectBits =
        (u8*)((*(int*)((gMapsTab + 0x1c) + (words << 2)) + v2) + (int)gCurRomListPage - offset0);

    for (i = 0; i < (v0 + 7 >> 3) + 1; i++) {
        ((MapRomListPage*)gCurRomListPage)->loadedObjectBits[i] = 0;
    }
    {
        f32 fillVal = 0.0f;
        ((MapRomListPage*)gCurRomListPage)->worldX = fillVal;
        ((MapRomListPage*)gCurRomListPage)->worldZ = fillVal;
    }
    ((MapRomListPage*)gCurRomListPage)->unk18 = 0;
    ((MapRomListPage*)gCurRomListPage)->mapLayer = 0;
    if (flag == 0) {
        mapBuildRomListIndex(gCurRomListPage, &gMapRomListIndexes[p1], p1, 0);
        (*gMapEventInterface)->updateObjGroups(p1);
    }
    return gCurRomListPage;
}

int ViewFrustum_IsSphereVisible(float* center, float radius) {
    FrustumPlane* plane;
    u8 i = 0;
    f32 offZ = playerMapOffsetZ;
    f32 offX = playerMapOffsetX;
    for (; i < FRUSTUM_PLANE_COUNT; i++) {
        float dot;
        plane = &gViewFrustumPlanes[i];
        dot = plane->distance + (plane->normalZ * (center[2] - offZ) +
                                 (center[1] * plane->normalY + plane->normalX * (center[0] - offX)));
        if (radius + dot < 0.0f) {
            return 0;
        }
    }
    return 1;
}

int objUpdateOpacity(GameObject* obj) {
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
    if (op == 0) {
        obj->anim.renderAlpha = 0;
        return 0;
    }
    ptr = (ObjPlacement*)obj->anim.placementData;
    if (ptr != 0 && (ptr->mapActFlagsHi & 1)) {
        obj->anim.renderAlpha = (u8)(((op + 1) * 255) >> 8);
    } else {
        range = obj->anim.cullDistance2;
        if (range < 40.0f) {
            obj->anim.renderAlpha = 0;
            return 0;
        }
        player = Obj_GetPlayerObject();
        if (ptr != 0 && (ptr->mapActFlagsHi & 2) && player != 0) {
            d = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
        } else {
            d = Camera_DistanceToCurrentViewPosition(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ);
        }
        if (d > range) {
            obj->anim.renderAlpha = 0;
            return 0;
        }
        alpha = 255;
        near = range - 100.0f;
        if (d > near) {
            range -= near;
            d -= near;
            alpha = (int)(255.0f * (1.0f - d / range));
        }
        Camera_ProjectWorldSphere(obj->anim.worldPosX - playerMapOffsetX, obj->anim.worldPosY,
                                  obj->anim.worldPosZ - playerMapOffsetZ,
                                  obj->anim.hitboxScale * obj->anim.rootMotionScale, &o1, &o2, &o3, &sz, &o5, &o6);
        sz = __fabsf(sz);
        sz *= 640.0f;
        if (sz < 10.0f) {
            obj->anim.renderAlpha = 0;
            return 0;
        }
        if (sz < 15.0f) {
            alpha = (int)(((f32)alpha * (sz - 10.0f)) / 5.0f);
        }
        obj->anim.renderAlpha = (u8)((alpha * (obj->anim.alpha + 1)) >> 8);
    }
    if (obj->anim.renderAlpha == 0) {
        return 0;
    } else {
        prod = obj->anim.hitboxScale * obj->anim.rootMotionScale;
        i = 0;
        offZ = playerMapOffsetZ;
        offX = playerMapOffsetX;
        for (; i < FRUSTUM_PLANE_COUNT; i++) {
            FrustumPlane* plane = &gViewFrustumPlanes[i];
            if (prod + (plane->distance +
                        (plane->normalZ * (obj->anim.worldPosZ - offZ) +
                         (obj->anim.worldPosY * plane->normalY + plane->normalX * (obj->anim.worldPosX - offX)))) <
                0.0f) {
                return 0;
            }
        }
    }
    return 1;
}
void mapDebugRender(ModelRenderInstrsState* state) {
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

    if (gMapCellRenderInstrsEnabled != 0) {
        bx = fastFloorf((gSceneCamera->x - playerMapOffsetX) / 640.0f);
        bz = fastFloorf((gSceneCamera->z - playerMapOffsetZ) / 640.0f);
        tbl = gMapBlockLayerTables[0];
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16) {
            blk = 0;
        } else {
            ci = tbl[bx + bz * 16];
            if (ci < 0 || ci >= gMapBlockCount) {
                blk = 0;
            } else {
                blk = gMapBlocks[ci];
            }
        }
        sx = (int)(640.0f * fastFloorf(gSceneCamera->x / 640.0f));
        sz = (int)(640.0f * fastFloorf(gSceneCamera->z / 640.0f));
        wx = (int)(gSceneCamera->x - sx);
        wz = (int)(gSceneCamera->z - sz);
        if (blk != 0) {
            y0 = blk->minY;
            y0a = y0;
            if (y0 & 1) {
                y0a = y0 - 1;
            }
            cy = gSceneCamera->y;
            y1 = blk->maxY;
            if (cy > y1) {
                cy = (f32)(y1 - 1);
            }
            yy = cy;
            dy = yy - y0a;
            h = y1 - y0;
            if (h / 80 < 8) {
                step = h / 8;
            } else {
                step = 80;
            }
            celly = dy / step;
            cellx = wx / 80;
            cellz = wz / 80;
            cell = celly * 0x40;
            cell += cellz * 8;
            cell += cellx;
            logPrintf(sTrackCellCoordFormat, cellx, celly, cellz);
            v = gMapCellRenderInstrBits;
            n = v >> 3;
            if (v & 7) {
                n += 1;
            }
            modelRenderInstrsState_init(state, (void*)(gMapCellRenderInstrsTable + n * cell), v, v);
        }
    }
}

int mapBlockIsInViewFrustum(int bx, int bz, MapBlockData* block) {
    f32 a1, a2, b1, b2, c1, c2;
    f32 p3;
    f32 fx, fz, x2, z2, y0, y1;
    f32 v;
    FrustumPlane* plane;
    int i;
    int j;
    int hit;

    fx = 640.0f * bx;
    fz = 640.0f * bz;
    x2 = 640.0f + fx;
    z2 = 640.0f + fz;
    if (block) {
        y0 = block->minY;
        y1 = block->maxY;
    } else {
        y0 = -100000.0f;
        y1 = 100000.0f;
    }
    plane = gViewFrustumPlanes;
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++) {
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
        while (j < 8 && hit == 0) {
            if (j & 1) {
                v = a1;
            } else {
                v = a2;
            }
            if (j & 2) {
                v += b1;
            } else {
                v += b2;
            }
            if (j & 4) {
                v += c1;
            } else {
                v += c2;
            }
            v += p3;
            if (v > 0.0f) {
                hit = 1;
            }
            j++;
        }
        if (j == 8 && hit == 0) {
            return 0;
        }
    }
    return 1;
}

void frustumPlanes_updateAabbCornerIndices(FrustumPlane* planes, int count) {
    int k;
    int j;
    int bi;
    f32 best;
    f32 v;

    for (k = 0; k < count; k++) {
        best = 0.0f;
        j = 0;
        while (j < 24) {
            v = planes->normalX * sAabbCornerDirections[j++];
            v += planes->normalY * sAabbCornerDirections[j++];
            v += planes->normalZ * sAabbCornerDirections[j++];
            if (v > best) {
                best = v;
                bi = j - 3;
            }
        }
        switch (bi) {
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

void buildPlayerRelativeFrustumPlanes(void) {
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
    if (player != NULL) {
        clipDist = -Camera_DistanceToCurrentViewPosition(player->anim.worldPosX, player->anim.worldPosY,
                                                         player->anim.worldPosZ);
    } else {
        clipDist = -100.0f;
    }
    scales.v[0] = clipDist;

    outPtr = gPlayerRelativeFrustumPlanes;
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++) {
        PSMTXMultVec((const f32(*)[4])invRotMtx, &planes.v[i], (Vec*)&outPtr[i].normalX);
        PSVECScale(&outPtr[i].normal, &tmp, scales.v[i]);
        PSVECAdd(&camPos, &tmp, &tmp);
        outPtr[i].distance = -PSVECDotProduct(&tmp, &outPtr[i].normal);
    }
    frustumPlanes_updateAabbCornerIndices(gPlayerRelativeFrustumPlanes, FRUSTUM_PLANE_COUNT);
}

extern WarpVec gCameraPosByTransformSpace[0x29];
extern MapRomListPage* gLoadedRomListPages[ROM_LIST_PAGE_COUNT];
extern MapRomListIndex gMapRomListIndexes[120];
extern s8* gMapBlockLayerTables[MAP_BLOCK_LAYER_COUNT];
extern MapCellEntry* gMapBlockCellEntryTables[5];
extern s8* gMapBlockCellStateTables[5];
extern ShaderRomListSlot gShaderRomListSlots[8];
extern int gShaderMapRomBuffers[0x5];
extern f32 distortionFilterVector[];
extern ModelLightStruct* gGlowLightList[100];
extern u8 gCloudLayerTexMatrix[0x30];
extern MapRenderQueueStorage gLightmapDrawQueue;

u8 colorFilterColor[4] = {0xFF, 0x70, 0x40, 0};
u8 colorScale = 0xFF;

void sceneDraw(void);
void sceneDrawTransparentPolys(void);

volatile PPCWGPipe GXWGFifo : (0xCC008000);

void renderShadowType3(GameObject* obj, u32 b, s32 offset);
static inline void GXPosition3s16(const s16 x, const s16 y, const s16 z) {
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = z;
}
static inline void GXColor4u8(const u8 r, const u8 g, const u8 b, const u8 a) {
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}
static inline void GXTexCoord2s16(const s16 s, const s16 t) {
    GXWGFifo.s16 = s;
    GXWGFifo.s16 = t;
}
static inline void GXPosition1x8(const u8 x) {
    GXWGFifo.u8 = x;
}

static void updateVisibleGeometry(void) {
    Camera* cam;
    int n;
    int i;
    f32 tt, ff, ss;
    f32 scale;
    f32 xx, yy, zz;
    f32 ratio, ratio2;
    u16 fov;
    f32 ox, oy, oz;
    f32 dd;
    f32* pw;
    MatrixTransform st;
    f32 m[17];

    cam = Camera_GetCurrent();
    if ((renderFlags & RENDERFLAG_WIDESCREEN) != 0 || (renderFlags & RENDERFLAG_DRAW_DISTANCE) != 0) {
        scale = Camera_GetFovY() / 1.5f;
    } else {
        scale = Camera_GetFovY();
        scale *= 0.5f;
    }
    xx = cam->worldX - playerMapOffsetX;
    yy = cam->worldY;
    zz = cam->worldZ - playerMapOffsetZ;
    st.x = 0.0f;
    st.y = 0.0f;
    st.z = 0.0f;
    st.scale = 1.0f;
    st.rotX = 0x8000 - cam->worldYaw;
    st.rotY = -cam->worldPitch;
    st.rotZ = cam->worldRoll;
    setMatrixFromObjectPos(m, &st);
    Matrix_TransformPoint(m, 0.0f, 0.0f, -1.0f, &ox, &oy, &oz);
    gViewFrustumPlanes[0].normalX = ox;
    gViewFrustumPlanes[n = 0].normalY = oy;
    gViewFrustumPlanes[n = 0].normalZ = oz;
    dd = -(zz * oz + (xx * ox + yy * oy));
    pw = &gViewFrustumPlanes[0].distance;
    i = 0;
    pw[i * 5] = dd;
    fov = (int)(182.05f * scale) & 0xffff;
    tt = fcos16HighPrecision(fov);
    ratio = fsin16HighPrecision(fov) / tt;
    ratio2 = ratio * ratio;
    ff = 1.333333f;
    tt = ff * ratio2;
    tt = atanf(sqrtf(ff * tt + ratio2));
    ff = mathSinfHighPrecision(tt);
    ss = mathCosfHighPrecision(tt);
    Matrix_TransformPoint(m, ss, 0.0f, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 1].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, -ss, 0.0f, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 2].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, 0.0f, -ss, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 3].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, 0.0f, ss, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 4].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    frustumPlanes_updateAabbCornerIndices((FrustumPlane*)gViewFrustumPlanes, 5);
}

MapBlockData* mapGetBlock(int i) {
    if (i < 0 || i >= gMapBlockCount) {
        return 0;
    }
    return gMapBlocks[i];
}

s8* mapGetBlockIdx(int layer) {
    return gMapBlockLayerTables[layer];
}

MapBlockData* mapGetBlockAtPos(int x, int y, int layer) {
    s8* table = gMapBlockLayerTables[layer];
    s32 idx;
    if (x < 0 || y < 0 || x >= 0x10 || y >= 0x10) {
        return 0;
    }
    idx = table[x + (y << 4)];
    if (idx < 0 || idx >= gMapBlockCount) {
        return 0;
    }
    return gMapBlocks[idx];
}

void* RomList_GetLoadedPages(void) {
    return gLoadedRomListPages;
}

extern u32 gVisibleObjectSortKeys[0x400];

int coordsToMapCell(f32 x, f32 z) {
    int ix = (int)(fastFloorf(x / 640.0f) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / 640.0f) - (f32)gMapBlockOriginZ);
    if (ix < 0 || ix >= 16) {
        return -1;
    }
    if (iz < 0 || iz >= 16) {
        return -1;
    }
    return *(s16*)((char*)gMapBlockCellEntryTables[0] + (ix + iz * 16) * 12);
}

void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ) {
    s32 ix, iz;
    f32 s;
    ix = fastFloorf(x / 640.0f);
    iz = fastFloorf(z / 640.0f);
    s = 640.0f;
    *outX = s * ix;
    *outZ = s * iz;
}

int isInBounds(f32 x, f32 z) {
    int ix = (int)(fastFloorf(x / 640.0f) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / 640.0f) - (f32)gMapBlockOriginZ);
    int linear;
    s8** p;
    if (ix < 0 || ix >= 16) {
        return -1;
    }
    if (iz < 0 || iz >= 16) {
        return -1;
    }
    linear = ix + (iz << 4);
    {
        int i;
        p = gMapBlockLayerTables;
        for (i = 0; i < MAP_BLOCK_LAYER_COUNT; i++) {
            if ((*p)[linear] > -1) {
                return 1;
            }
            p++;
        }
    }
    return 0;
}

int objPosToMapBlockIdx(f32 x, f32 y, f32 z) {
    s8** tp[1];
    int ix = (int)(fastFloorf(x / 640.0f) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / 640.0f) - (f32)gMapBlockOriginZ);
    int i;
    if (ix < 0 || ix >= 16) {
        return -1;
    }
    if (iz < 0 || iz >= 16) {
        return -1;
    }
    ix += (iz << 4);
    for (tp[0] = gMapBlockLayerTables, i = 0; i < MAP_BLOCK_LAYER_COUNT; tp[0]++, i++) {
        s8* table = *tp[0];
        int idx = table[ix];
        if (idx > -1) {
            MapBlockData* block = gMapBlocks[idx];
            if (y > (f32)(block->minY - 50) && y < (f32)(block->maxY + 50)) {
                return table[ix];
            }
        }
    }
    return -1;
}

int* mapRomListFindItem(int needle, int* out_idx, int* out_outer, int* out_type, int* out_lastpage) {
    MapRomListPage* page;
    int itemIndex;
    int pageIndex;
    int pageOffset;
    ObjPlacement* item;
    u16 pageDataSize;
    int itemSize;

    for (pageIndex = 0; pageIndex < ROM_LIST_PAGE_COUNT; pageIndex++) {
        page = gLoadedRomListPages[pageIndex];
        if (page == NULL) {
            continue;
        }

        gCurRomListPage = page;
        item = page->objects;
        itemIndex = 0;
        pageOffset = 0;
        pageDataSize = page->objectDataSize;

        while (pageOffset < pageDataSize) {
            if ((u32)item->ident == (u32)needle) {
                if (out_idx != NULL) {
                    *out_idx = itemIndex;
                }
                if (out_outer != NULL) {
                    *out_outer = pageIndex;
                }
                if (out_type != NULL) {
                    *out_type = (int)(s8)((MapRomListPage*)gCurRomListPage)->mapLayer;
                }
                if (out_lastpage != NULL) {
                    *out_lastpage = (pageIndex >= 0x50) ? 1 : 0;
                }
                return (int*)item;
            }
            itemSize = (int)item->size << 2;
            pageOffset += itemSize;
            item = (ObjPlacement*)((char*)item + itemSize);
            itemIndex++;
        }
    }
    return NULL;
}

void sortVisibleObjectKeysDescending(u32* arr, int n);
void getVisibleObjects(s8* opacity);
void renderSceneGeometry(u8 renderType, s8* order);

void sortVisibleObjectKeysDescending(u32* arr, int n) {
    int i, j;
    int gap = 1;
    u32 tmp;
    while (gap <= n / 9) {
        gap = gap * 3 + 1;
    }
    while (gap > 0) {
        for (i = gap + 1; i <= n; i++) {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1] < tmp) {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}

void getVisibleObjects(s8* opacity) {
    int part;
    GameObject** objects;
    GameObject** p;
    GameObject* o;
    int i;
    u32 key;
    int depthInt;
    u8* sub;
    GameObject* att;
    int j;
    ObjModel* model;
    u32 tf;
    u32 mode;
    s16 t;
    int sortDepth;
    int count;
    f32 a, b;
    f32 depth;

    newshadows_beginFrame();
    objects = ObjList_GetObjects((int*)0, 0);
    part = ObjList_PartitionForRender(&count);
    i = 0;
    p = objects;
    for (; i < count; i++) {
        o = (GameObject*)*p;

        o->objectFlags &= ~OBJECT_OBJFLAG_RENDERED;
        j = 0;
        sub = (u8*)o;
        for (; j < o->childCount; j++) {
            att = ((GameObject*)sub)->childObjs[0];
            if (att != NULL) {
                att->objectFlags &= ~OBJECT_OBJFLAG_RENDERED;
            }
            sub += 4;
        }
        if (i >= part) {
            opacity[i] = objUpdateOpacity(o);
            if (opacity[i] != 0 || (o->anim.modelInstance->flags & OBJDEF_FLAG_RENDER_WHEN_INVISIBLE) != 0) {
                if ((o->anim.modelInstance->flags & OBJDEF_FLAG_FIXED_SORT_DEPTH) != 0) {
                    *(f32*)&o->anim.targetObj = (f32)(o->anim.modelInstance->fixedSortDepth * 100);
                    depthInt = (int)*(f32*)&o->anim.targetObj;
                } else {
                    if (o->anim.parent != NULL) {
                        Camera_ProjectWorldPoint(o->anim.worldPosX, o->anim.worldPosY, o->anim.worldPosZ, &a, &b,
                                                 &depth, (f32*)&o->anim.targetObj);
                    } else {
                        Camera_ProjectWorldPoint(o->anim.localPosX - playerMapOffsetX, o->anim.localPosY,
                                                 o->anim.localPosZ - playerMapOffsetZ, &a, &b, &depth,
                                                 (f32*)&o->anim.targetObj);
                    }
                    depthInt = (int)(1e+03f * (1.0f + depth));
                }
                if ((o->anim.flags & OBJANIM_FLAG_HIDDEN) == 0 && o->anim.modelState != NULL &&
                    (o->anim.modelState->flags & OBJ_MODEL_STATE_SHADOW_VISIBLE) != 0) {
                    t = o->anim.modelInstance->shadowType;
                    if (t == 2 || t == 1) {
                        queueObjectShadow(o);
                    } else if (t == 4) {
                        renderObjectShadowTexture(o);
                    }
                }
                if (gVisibleObjectSortKeyCount < 1000) {
                    key = 0;
                    model = Obj_GetActiveModel(o);
                    if (o->anim.renderAlpha == 0xff && (o->anim.flags & 0x80) == 0 &&
                        ((tf = o->anim.modelInstance->flags) & OBJDEF_FLAG_FORCE_ALPHA_SORT) == 0 &&
                        model->renderAttachment == NULL) {
                        key |= 0x80000000;
                        sortDepth = 1000 - (depthInt & 0xffff);
                        if ((tf & OBJDEF_FLAG_RUNTIME_BATCHABLE) != 0 &&
                            (o->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE) == 0) {
                            key |= 0x40000000;
                            key |= (o->anim.romDefNo & 0x3ff) << 20;
                        }
                        gVisibleObjectSortKeys[gVisibleObjectSortKeyCount] =
                            (i & 0x3ff) | (((sortDepth & 0x3ff) << 10) | key);
                        gVisibleObjectSortKeyCount++;
                        if ((o->anim.modelInstance->renderFlags & 0x20) != 0 &&
                            (o->objectFlags & OBJECT_OBJFLAG_SHADOW_DISABLED) == 0 &&
                            (o->anim.flags & OBJANIM_FLAG_HIDDEN) == 0) {
                            renderShadowType3(o, 7, 0x50);
                            gLightmapDrawQueue.entries[gLightmapDrawQueueCount].type = 1;
                            gLightmapDrawQueueCount++;
                        }
                    } else {
                        if ((o->anim.modelInstance->flags & OBJDEF_FLAG_DEFERRED_RENDER) != 0 ||
                            (o->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER) != 0) {
                            mode = 0x1f;
                        } else {
                            mode = 7;
                        }
                        renderShadowType3(o, mode, 0);
                        gLightmapDrawQueue.entries[gLightmapDrawQueueCount].type = 0;
                        gLightmapDrawQueueCount++;
                        if ((o->anim.modelInstance->renderFlags & 0x20) != 0 &&
                            (o->anim.flags & OBJANIM_FLAG_HIDDEN) == 0) {
                            renderShadowType3(o, 7, 0x50);
                            gLightmapDrawQueue.entries[gLightmapDrawQueueCount].type = 1;
                            gLightmapDrawQueueCount++;
                        }
                    }
                }
            } else {
                ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)o->anim.hitReactState;
                if (hitState != NULL && (hitState->shapeFlags & 0x30) != 0) {
                    hitState->resetHitboxMode = 2;
                }
            }
        }
        p++;
    }
    if (gVisibleObjectSortKeyCount > 1) {
        sortVisibleObjectKeysDescending(gVisibleObjectSortKeys, gVisibleObjectSortKeyCount);
    }
    renderShadows(0, 0, 0);
}

static void renderObjects(s8* opacity) {
    u32* kp;
    int i;
    u32 flags;
    int idx;
    GameObject* obj;
    int* p;
    int slot;
    GameObject** objects;
    LightmapDrawQueue* qbase;
    LightmapDrawQueue* dq;

    qbase = (LightmapDrawQueue*)gLightmapDrawQueue.entries;
    objects = ObjList_GetObjects((int*)0, 0);
    for (i = 1, kp = (u32*)((u8*)qbase + 0x8818) + 1; i < gVisibleObjectSortKeyCount; kp++, i++) {
        idx = *kp & 0x3ff;
        obj = objects[idx];
        flags = obj->anim.modelInstance->flags;
        if ((flags & OBJDEF_FLAG_DEFERRED_RENDER) != 0 ||
            ((obj->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER) != 0)) {
            if (opacity[idx] != 0 && gLightmapDeferredObjectCount < 0x14) {
                slot = gLightmapDeferredObjectCount;
                gLightmapDeferredObjectCount = slot + 1;
                dq = (LightmapDrawQueue*)&((u32*)qbase)[slot];
                dq->deferred[0] = (u32)obj;
            }
        } else {
            if ((flags & OBJDEF_FLAG_RUNTIME_BATCHABLE) == 0) {
                (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, obj);
            }
            objRender(0, 0, 0, 0, obj, 1);
            p = (int*)obj->anim.modelState;
            if (p != NULL && obj->anim.modelState->shadowCastSlot != NULL) {
                int qi;
                u32 shadowKind;

                renderShadowType3(obj, 0x13, 0);
                shadowKind = 2;
                qi = gLightmapDrawQueueCount;
                gLightmapDrawQueue.entries[qi].type = shadowKind;
                gLightmapDrawQueueCount = qi + 1;
            } else if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_CRASH &&
                       (obj->anim.flags & OBJANIM_FLAG_HIDDEN) == 0 &&
                       (obj->anim.modelState->flags & OBJ_MODEL_STATE_SHADOW_VISIBLE)) {
                int qi;
                u32 shadowKind;

                renderShadowType3(obj, 0x13, 0);
                shadowKind = 3;
                qi = gLightmapDrawQueueCount;
                gLightmapDrawQueue.entries[qi].type = shadowKind;
                gLightmapDrawQueueCount = qi + 1;
            }
        }
    }
}
static inline void fillBoxRows(u8* map, int* box) {
    int y, x;
    int minX, maxX;
    u8* cell;
    for (y = box[2]; y <= box[3]; y++) {
        x = minX = box[0];
        cell = map + (y + 7) * 0x10 + minX;
        maxX = box[1];
        for (; x <= maxX; x++) {
            cell[7] = 1;
            cell++;
        }
    }
}

void renderSceneGeometry(u8 renderType, s8* order) {
    u8 cellMask[256];
    int box0[4];
    int box1[4];
    int box2[4];
    int box3[4];
    u8* cellMaskPtr;
    s8** layerTablePtr;
    s8** layerFlagPtr;
    int idx;
    int k;
    int row, col;
    int oi, ii;
    int layer;
    MapBlockData* block;
    s8* table;
    f32 worldSize;
    f32 rowF, colF;
    int cellIndex;

    layer = 4;
    layerTablePtr = &gMapBlockLayerTables[4];
    layerFlagPtr = &gMapBlockCellStateTables[4];
    worldSize = 640.0f;
    do {
        table = *layerTablePtr;
        gMapLayerCellStates = *layerFlagPtr;
        mapGetBlockGridRects(gMapBlockOriginX + 7, gMapBlockOriginZ + 7, box0, box1, box2, box3, layer, 1,
                             gMapCurRomListSlot);
        cellMaskPtr = cellMask;
        for (k = 0; k != ARRAY_COUNT(cellMask); k += 4) {
            cellMaskPtr[0] = 0;
            cellMaskPtr[1] = 0;
            cellMaskPtr[2] = 0;
            cellMaskPtr[3] = 0;
            cellMaskPtr += 4;
        }
        cellMaskPtr = cellMask;
        fillBoxRows(cellMaskPtr, box0);
        fillBoxRows(cellMaskPtr, box1);
        fillBoxRows(cellMaskPtr, box2);
        fillBoxRows(cellMaskPtr, box3);
        for (oi = 0; oi < 16; oi++) {
            row = order[oi];
            ii = 0;
            rowF = worldSize * (f32)row;
            for (; ii < 16; ii++) {
                col = order[ii];
                cellIndex = row + col * 0x10;
                idx = table[cellIndex];
                if (idx < 0) {
                    block = NULL;
                } else {
                    block = gMapBlocks[idx];
                    block->flags4 ^= 1;
                    if (cellMask[cellIndex] == 0) {
                        continue;
                    }
                }
                if (idx > -1 && mapBlockIsInViewFrustum(row, col, block) != 0) {
                    lbl_803DCE58 = rowF;
                    colF = 640.0f * (f32)col;
                    lbl_803DCE54 = colF;
                    PSMTXTrans(block->transform, rowF, (f32)block->collisionYOffset, colF);
                    renderMapBlock(block, renderType);
                }
            }
        }
        layerTablePtr--;
        layerFlagPtr--;
        layer--;
    } while (layer >= 0);
}

void sceneDraw(void) {
    char* q;
    int i;
    u8* cursor;
    GameObject** deferred;
    GameObject* player;
    u8 flag;
    int t;
    GXColor c;
    f32 skyA;
    f32 skyB;
    s8 buf[616];

    q = (char*)gLightmapDrawQueue.entries;
    gCloudLayerTexture = cloudGetLayerTexture(&skyA, &skyB);
    if (gCloudLayerTexture != 0) {
        *(f32*)(q + 0x3f48) = 0.0005f;
        *(f32*)(q + 0x3f4c) = 0.0f;
        *(f32*)(q + 0x3f50) = 0.0f;
        *(f32*)(q + 0x3f54) = 0.0005f * playerMapOffsetX + skyA;
        *(f32*)(q + 0x3f58) = 0.0f;
        *(f32*)(q + 0x3f5c) = 0.0f;
        *(f32*)(q + 0x3f60) = 0.0005f;
        *(f32*)(q + 0x3f64) = 0.0005f * playerMapOffsetZ + skyB;
        *(f32*)(q + 0x3f68) = 0.0f;
        *(f32*)(q + 0x3f6c) = 0.0f;
        *(f32*)(q + 0x3f70) = 0.0f;
        *(f32*)(q + 0x3f74) = 1.0f;
        PSMTXConcat((MtxPtr)(q + 0x3f48), (MtxPtr)Camera_GetInverseViewMatrix(), (MtxPtr)(q + 0x3f48));
    }
    mapDebugRender((ModelRenderInstrsState*)(q + 0x4164));
    shadowBeginFrame();
    shadowVolumeBeginFrame();
    gVisibleObjectSortKeyCount = 1;
    lbl_803DCEAC = 0;
    gGlowLightCount = 0;
    newshadows_drawReflectionTexture();
    gLightmapDrawQueueCount = 0;
    getVisibleObjects(buf);
    Rcp_UpdateDistortionTextures();
    pauseMenuRenderSlotShadow();
    GXPixModeSync();
    Camera_UpdateProjection(NULL, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    t = 0;
    if ((renderFlags & 0x40) != 0 && (renderFlags & RENDERFLAG_HIDE_STARS) == 0) {
        t = 1;
    }
    flag = t;
    if ((renderFlags & RENDERFLAG_OVERCAST) != 0) {
        (*gSkyInterface)->renderTimeOfDayBackdrop(0, 0);
        if (flag != 0) {
            drawSkyStars();
        }
        (*gSkyInterface)->render(0, 0, 0, 0, flag);
        if ((renderFlags & RENDERFLAG_DRAW_CLOUDS) != 0) {
            (*gCloudActionInterface)->renderClouds(0, 0, 0, 0);
        }
    } else {
        (*gSkyInterface)->render(0, 0, 0, 0, flag);
        (*gCloudActionInterface)->renderClouds(0, 0, 0, 0);
        drawSkyStars();
    }
    if (gLightmapScreenImageEnabled != 0) {
        screenImageDraw(gLightmapScreenImageEnabled);
    }
    lightningRenderActive();
    (*gSky2Interface)->applyFogColor(0);
    gLightmapDeferredObjectCount = 0;
    skyGetSunColor(0, (u8*)&c, (u8*)&c + 1, (u8*)&c + 2);
    GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(GX_COLOR0, c);
    GXSetNumChans(1);
    renderSceneGeometry(0, gMapBlockDrawOrderFrontToBack);
    objRenderInvalidateStateCache();
    renderObjects(buf);
    if (CameraShake_IsActive() != 0 || (int)bEnableMotionBlur != 0) {
        renderMotionBlur(gMotionBlurAmount);
    }
    if (getHudHiddenFrameCount() == 0) {
        newshadows_captureReflectionTextures();
    }
    if (bEnableBlurFilter != 0) {
        doBlurFilter(blurFilterX, blurFilterY, blurFilterZ, bBlurFilterUseArea, bBiggerBlurFilter);
    }
    if (heatEffectIntensity != 0) {
        doHeatEffect(heatEffectIntensity & 0xff);
    }
    i = 0;
    deferred = (GameObject**)(q + 0x4114);
    for (; i < gLightmapDeferredObjectCount; i++) {
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, *deferred);
        objRender(0, 0, 0, 0, *deferred, 1);
        deferred++;
    }
    renderParticles();
    renderSceneGeometry(1, gMapBlockDrawOrderBackToFront);
    renderSceneGeometry(2, gMapBlockDrawOrderBackToFront);
    if (gLightmapDrawQueueCount == 1000) {
        sceneDrawTransparentPolys();
        gLightmapDrawQueueCount = 0;
    }
    {
        const int queueIndex = gLightmapDrawQueueCount;
        *(u32*)(((int)q + 8) + queueIndex * 16) = 0x78000000;
        *(u32*)(((int)q + 12) + queueIndex * 16) = 8;
        gLightmapDrawQueueCount = *(const int*)&gLightmapDrawQueueCount + 1;
    }
    if (gLightmapDrawQueueCount == 1000) {
        sceneDrawTransparentPolys();
        gLightmapDrawQueueCount = 0;
    }
    {
        const int queueIndex = gLightmapDrawQueueCount;
        *(u32*)(((int)q + 8) + queueIndex * 16) = 0x50000000;
        *(u32*)(((int)q + 12) + queueIndex * 16) = 9;
        gLightmapDrawQueueCount = *(const int*)&gLightmapDrawQueueCount + 1;
    }
    sceneDrawTransparentPolys();
    (*gModgfxInterface)->markSourceFrameUpdated(buf);
    (*gModgfxInterface)->renderEffects(NULL, 0, 0, 0, NULL);
    player = Obj_GetPlayerObject();
    if (player != NULL) {
        i = 0;
        cursor = (u8*)player;
        for (; i < player->childCount; i++) {
            GameObject* child = ((GameObject*)cursor)->childObjs[0];
            if (child->anim.classId == 45) {
                ((void (*)(GameObject*))(*child->anim.dll)[11])(child);
            }
            cursor += 4;
        }
    }
    staffDrawQuakeSpellRing();
    (*gNewCloudsInterface)->renderSnowClouds(0);
    if (bEnableDistortionFilter != 0) {
        newshadows_captureReflectionTextures();
        doDistortionFilter((f32*)(q + 0x4108), distortionFilterAngle2, distortionFilterColor, distortionFilterAngle1);
    }
    renderGlows();
    (*gCameraInterface)->minimapShowHelpTextForTarget(0, 0, 0, 0);
    if (bEnableMonochromeFilter != 0) {
        doColorFilter(colorFilterColor);
    } else if (bEnableSpiritVision != 0) {
        doSpiritVisionFilter();
    }
    if (bEnableViewFinderHud != 0) {
        drawViewFinderAperture(3.1e+02f, 2.3e+02f, 0x40, 0);
    }
    if (bEnableColorFilter == 1) {
        doColorFilter(colorFilterColor);
    }
    shadowVolumesSetDirty(0);
}

void sceneRender(int wpad0, int wpad1, int wpad2, int wpad3, int wpad4, int wpad5) {
    renderFlags |= 0x21;
    if (curMapType == MAPTYPE_SUBMAP || curMapType == MAPTYPE_SUBMAP_UNUSED) {
        renderFlags &= ~1;
    }
    Camera_UpdateProjection(NULL, 0);
    updateVisibleGeometry();
    buildPlayerRelativeFrustumPlanes();
    CameraShake_Enable();
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    updateLights();
    gSceneCamera = Camera_GetCurrent();
    sceneDraw();
    Camera_SetupFullscreenViewport(NULL);
    renderFlags &= ~2;
}

void doNothing_beforeTitleScreen(void) {
}

static inline void mapUpdateTextureAnimations(void) {
    MapTextureOverride* textureOverride;
    Texture* texture;
    int i;

    i = 0;
    for (; i < 80; i++) {
        textureOverride = &gMapTextureOverrides[i];
        if (textureOverride->refCount != 0 && (texture = textureOverride->texture) != NULL &&
            texture->animationFrameCountFixed != 0x100 && texture->animationFrameStep != 0) {
            textureUpdateAnimationFrame(texture, &textureOverride->flags, &textureOverride->frame);
        }
    }
}

static inline void mapUpdateTextureScrolls(void) {
    MapTextureScroll* textureScroll;
    int byteOffset;
    int i;
    f32 offsetX;
    f32 deltaTime;
    f32 deltaX;
    f32 deltaY;

    i = 0;
    byteOffset = 0;
    for (; i < 58; i++) {
        textureScroll = (MapTextureScroll*)((u8*)gMapTextureScrolls + byteOffset);
        if (textureScroll->refCount != 0) {
            deltaY = textureScroll->yStep * (deltaTime = timeDelta);
            offsetX = textureScroll->offsetX;
            deltaX = textureScroll->xStep * deltaTime;
            textureScroll->offsetX = offsetX + deltaX;
            textureScroll->offsetY += deltaY;
        }
        byteOffset += sizeof(MapTextureScroll);
    }
}

void updateEnvironment(int mode) {
    if (mode == 0) {
        skyUpdateEnvFx();
        (*gCloudActionInterface)->scrollTexture();
        (*gSky2Interface)->run();
        (*gSkyInterface)->updateTimeOfDay();
        (*gNewCloudsInterface)->run();

        mapUpdateTextureAnimations();
        mapUpdateTextureScrolls();

        loadNextMap();
        if (gEnvironmentUpdateInterface != NULL) {
            (*gEnvironmentUpdateInterface)->update();
        }
        gMinimapInterface->vtable->frameStart();

        if (gHeatEffectFadeDirection != 0) {
            heatEffectIntensity += gHeatEffectFadeDirection;
            if (heatEffectIntensity < 0) {
                heatEffectIntensity = 0;
                gHeatEffectFadeDirection = 0;
            } else if (heatEffectIntensity > 255) {
                heatEffectIntensity = 255;
                gHeatEffectFadeDirection = 0;
            }
        }
    }
}

void lightmapDrawQueuedObject(GameObject* obj);
void mapBlockRenderMain(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void mapBlockRenderWater(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void mapBlockRenderTransparent(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void lightmap_sortTransparentDrawQueue(void);

void renderShadowType3(GameObject* obj, u32 b, s32 offset);

void lightmap_sortTransparentDrawQueue(void);

void mapBlockRenderMain(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void mapBlockRenderWater(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void mapBlockRenderTransparent(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);

void lightmapDrawQueuedObject(GameObject* obj);

void sceneDrawTransparentPolys(void);

void initMapBlocks(void) {
    u8* mb = (u8*)gLightmapDrawQueue.entries;
    MapLayerBuffers* buffers = (MapLayerBuffers*)gLightmapDrawQueue.entries;
    MapRomListPage** romListPage;
    u16* p;
    void* tmp;
    int i;

    renderFlags = 0;
    gMapBlocks = mmAlloc(64 * sizeof(MapBlockData*), 5, 0);
    gMapBlockIds = mmAlloc(0x80, 5, 0);
    gMapBlockRefCounts = mmAlloc(0x40, 5, 0);
    gMapInfoBuffer = mmAlloc(0xd48, 5, 0);
    buffers->blockIndices[0] = mmAlloc(0x500, 5, 0);
    buffers->blockDescriptors[0] = mmAlloc(0x3c00, 5, 0);
    buffers->cellStates[0] = mmAlloc(0x500, 5, 0);

    for (i = 1; i < MAP_BLOCK_LAYER_COUNT; i++) {
        buffers->blockIndices[i] = buffers->blockIndices[i - 1] + 0x100;
        buffers->blockDescriptors[i] = buffers->blockDescriptors[i - 1] + 0xc00;
        buffers->cellStates[i] = buffers->cellStates[i - 1] + 0x100;
    }

    loadAssetFileById(&gMapsTab, MLDF_FILEID_MAPS_TAB);
    loadAssetFileById(&gHitsTab, MLDF_FILEID_HITS_TAB);

    romListPage = (MapRomListPage**)((u8*)(mb + 0x10000) - 0x7c58);
    for (i = 0; i < ROM_LIST_PAGE_COUNT; i++) {
        *romListPage++ = NULL;
    }

    loadAssetFileById(&gTrkBlkTab, MLDF_FILEID_TRKBLK_TAB);

    gTrkBlkTabCount = 0;
    p = gTrkBlkTab;
    while (*p != 0xffff) {
        p++;
        gTrkBlkTabCount++;
    }
    gTrkBlkTabCount--;
    gPendingWarpIndex = -1;
    gArrivedWarpIndex = -2;

    tmp = mmAlloc(80 * sizeof(MapTextureOverride), 5, 0);
    gMapTextureOverrides = tmp;
    memset(tmp, 0, 80 * sizeof(MapTextureOverride));

    tmp = mmAlloc(0x3a0, 5, 0);
    gMapTextureScrolls = tmp;
    memset(tmp, 0, 0x3a0);

    memset(mb + 0x8818, 0, 0xfa0);
    *(u32*)(mb + 0x8818) = -1;
}

void sceneDraw(void);
void sceneDrawTransparentPolys(void);

void renderShadowType3(GameObject* obj, u32 b, s32 offset);

typedef struct LightmapDrawEntry {
    union {
        u32 value;
        GameObject* object;
        MapBlockBoundsRec* bounds;
    } arg0;
    union {
        u32 value;
        MapBlockData* block;
    } arg1;
    u32 sortKey;
    s32 type;
} LightmapDrawEntry;

typedef union LightmapDrawItem {
    GameObject* object;
    MapBlockData* block;
} LightmapDrawItem;

void sortVisibleObjectKeysDescending(u32* arr, int n);

void sortVisibleObjectKeysDescending(u32* arr, int n);
void getVisibleObjects(s8* opacity);

void renderSceneGeometry(u8 renderType, s8* order);

void sceneDraw(void);

void setRenderFlag20000(int v) {
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_20000) : (renderFlags & ~RENDERFLAG_20000);
}

int isDrawDistanceEnabled(void) {
    return renderFlags & RENDERFLAG_DRAW_DISTANCE;
}

int setWidescreen(u8 v) {
    if (v != 0) {
        renderFlags |= RENDERFLAG_WIDESCREEN;
        Camera_SetAspectRatio((16.0f / 9.0f));
    } else {
        renderFlags &= ~RENDERFLAG_WIDESCREEN;
        Camera_SetAspectRatio(gStandardAspectRatio);
    }
    return 0;
}
int isWidescreen(void) {
    return renderFlags & RENDERFLAG_WIDESCREEN;
}
u32 shouldDrawShadows(void) {
    return renderFlags & RENDERFLAG_DRAW_SHADOWS;
}
int shouldDrawClouds(void) {
    return renderFlags & RENDERFLAG_DRAW_CLOUDS;
}

void setTitleScreenActive(int active) {
    if (active != 0) {
        renderFlags &= ~0x2000;
    } else {
        renderFlags |= 0x2000;
    }
}

void setDrawLights(int v) {
    SaveGameEnvState* env = saveGameGetEnvState();
    if (v != 0) {
        renderFlags |= 0x40;
        env->envFlags |= 0x8;
    } else {
        renderFlags &= ~0x40;
        env->envFlags &= ~0x8;
    }
}

void setDisableAntiAlias(int v) {
    renderFlags =
        (v != 0) ? (renderFlags | RENDERFLAG_DISABLE_ANTI_ALIAS) : (renderFlags & ~RENDERFLAG_DISABLE_ANTI_ALIAS);
}

u8 isOvercast(void) {
    u32 v = renderFlags & RENDERFLAG_OVERCAST;
    u32 t = ((u32) - (s32)v | v) >> 31;
    return t;
}

void setIsOvercast(int v) {
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_OVERCAST) : (renderFlags & ~RENDERFLAG_OVERCAST);
}

void setStarsHidden(int v) {
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_HIDE_STARS) : (renderFlags & ~RENDERFLAG_HIDE_STARS);
}

void setDrawCloudsAndLights(int v) {
    SaveGameEnvState* env = saveGameGetEnvState();
    if (v != 0) {
        renderFlags |= 0x50;
        env->envFlags |= 0x9;
    } else {
        renderFlags &= ~0x50;
        env->envFlags &= ~0x9;
    }
}

void setPendingMapLoad(int v) {
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_PENDING_MAP_LOAD) : (renderFlags & ~RENDERFLAG_PENDING_MAP_LOAD);
}

void lightmapDrawTriangleList(const void* vertexBase, u8* triList, int triCount) {
    const LightmapVertex* vertices = vertexBase;
    const LightmapVertex* vertex;
    int tri, vtx;

    /* Emit triCount triangles as GX_TRIANGLES; each vertex is 16 bytes:
       s16 pos[3] @0x0, u8 color[4] @0xc, s16 texcoord[2] @0x8. */
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXBegin(GX_TRIANGLES, GX_VTXFMT0, triCount * 3 & 0xffff);
    for (tri = 0; tri < triCount; tri++) {
        u8* list = triList;
        for (vtx = 0; vtx < 3; vtx++) {
            GXPosition1x8(0);
            vertex = &vertices[list[vtx + 1]];
            GXPosition3s16(vertex->x, vertex->y, vertex->z);
            vertex = &vertices[list[vtx + 1]];
            GXColor4u8(vertex->r, vertex->g, vertex->b, vertex->a);
            vertex = &vertices[list[vtx + 1]];
            GXTexCoord2s16(vertex->s, vertex->t);
        }
        triList += 0x10;
    }
}

void setFogColorCallback(int unused, u8 red, u8 green, u8 blue, int wpad0) {
    setFogColorRgb(red, green, blue);
}

void _textSetColor(void* context, int red, int green, int blue, int alpha) {
    _gxSetTevColor1(red, green, blue, alpha);
}

void setTextColor(void* context, int a, int b, int c, int d) {
    _gxSetTevColor2(a, b, c, d);
}

void lightmapObjectRenderBegin(int arg0, int arg1) {
}

void lightmapDrawQueuedObject(GameObject* obj);
void mapBlockRenderMain(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void mapBlockRenderWater(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void mapBlockRenderTransparent(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx);
void lightmap_sortTransparentDrawQueue(void);

void getVisibleObjects(s8* opacity);

void renderSceneGeometry(u8 renderType, s8* order);

void lightmapObjectRenderEnd(int arg0, int arg1) {
}
void renderShadowType3(GameObject* obj, u32 b, s32 offset) {
    Vec stk;
    s32 t;
    if (gLightmapDrawQueueCount == 1000) {
        sceneDrawTransparentPolys();
        gLightmapDrawQueueCount = 0;
    }
    if (obj->anim.parent != NULL) {
        stk.x = obj->anim.worldPosX;
        stk.y = obj->anim.worldPosY;
        stk.z = obj->anim.worldPosZ;
    } else {
        stk.x = obj->anim.worldPosX - playerMapOffsetX;
        stk.y = obj->anim.worldPosY;
        stk.z = obj->anim.worldPosZ - playerMapOffsetZ;
    }
    PSMTXMultVec((MtxPtr)Camera_GetViewMatrix(), &stk, &stk);
    t = (s32)-stk.z + offset;
    t = t < 0 ? 0 : (t > 0x7ffffff ? 0x7ffffff : t);
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].a = (u32)obj;
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].key = t | ((b & 0xff) << 27);
}

void lightmap_sortTransparentDrawQueue(void) {
    int i, j;
    int gap = 1;
    LightSortEntry tmp;
    while (gap <= (gLightmapDrawQueueCount - 1) / 9) {
        gap = gap * 3 + 1;
    }
    while (gap > 0) {
        for (i = gap + 1; i <= gLightmapDrawQueueCount; i++) {
            tmp = gLightmapDrawQueue.entries[i - 1];
            j = i;
            while (j > gap && gLightmapDrawQueue.entries[j - gap - 1].key < tmp.key) {
                gLightmapDrawQueue.entries[j - 1] = gLightmapDrawQueue.entries[j - gap - 1];
                j -= gap;
            }
            gLightmapDrawQueue.entries[j - 1] = tmp;
        }
        gap /= 3;
    }
}

void lightmapQueueShadowRow(MapBlockBoundsRec* bounds, MapBlockData* block, s32 selector) {
    Vec center;
    s32 depthKey;
    f32 worldMinX;
    f32 worldMinY;
    f32 worldMinZ;
    f32 worldMaxX;
    f32 worldMaxY;
    f32 worldMaxZ;

    if (gLightmapDrawQueueCount == 1000) {
        sceneDrawTransparentPolys();
        gLightmapDrawQueueCount = 0;
    }
    OSs16tof32(&bounds->maxX, &worldMaxX);
    worldMaxX = worldMaxX / 8.0f + block->transform[0][3];
    OSs16tof32(&bounds->minX, &worldMinX);
    worldMinX = worldMinX / 8.0f + block->transform[0][3];
    OSs16tof32(&bounds->maxY, &worldMaxY);
    worldMaxY = worldMaxY / 8.0f + block->transform[1][3];
    OSs16tof32(&bounds->minY, &worldMinY);
    worldMinY = worldMinY / 8.0f + block->transform[1][3];
    OSs16tof32(&bounds->maxZ, &worldMaxZ);
    worldMaxZ = worldMaxZ / 8.0f + block->transform[2][3];
    OSs16tof32(&bounds->minZ, &worldMinZ);
    worldMinZ = worldMinZ / 8.0f + block->transform[2][3];
    center.x = 0.5f * (worldMinX + worldMaxX);
    center.y = 0.5f * (worldMinY + worldMaxY);
    center.z = 0.5f * (worldMinZ + worldMaxZ);
    PSMTXMultVec((MtxPtr)Camera_GetViewMatrix(), &center, &center);
    depthKey = (s32)-center.z;
    depthKey = depthKey < 0 ? 0 : (depthKey > 0x7ffffff ? 0x7ffffff : depthKey);
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].a = (u32)bounds;
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].b = (u32)block;
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].key = depthKey | ((selector & 0xff) << 27);
}

void sortVisibleObjectKeysDescending(u32* arr, int n);

void mapBlockRenderMain(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx) {
    ModelRenderInstrsState state;
    int countShifted;
    int bitCursor;
    u32 instructionBits;
    u8* instructionCursor;
    struct Shader* shader;
    int entryCount;
    int i;
    u8* instructionBytes;

    countShifted = block->nRenderInstrsMain << 3;
    modelRenderInstrsState_init(&state, block->renderInstrsMain, countShifted, countShifted);
    modelRenderInstrsState_setBit(&state, bounds->renderBitOffset);
    state.bit += 4;
    mapBlockRender_drawDimmedAabbLights(bounds, block, viewMtx);
    shader = mapBlockRender_setLightmapShader(block, &state);
    state.bit += 4;
    mapBlockRender_setVtxDcrs(1, block, shader, &state);
    bitCursor = state.bit + 4;
    state.bit = bitCursor;
    countShifted = bitCursor >> 3;
    instructionBytes = state.instrs;
    instructionBits = instructionBytes[countShifted];
    instructionCursor = (u8*)((int)state.instrs + countShifted);
    instructionBits = instructionBits | ((u32)instructionCursor[1] << 8);
    instructionBits = instructionBits | ((u32)instructionCursor[2] << 16);
    state.bit += 4;
    entryCount = (instructionBits >> (bitCursor & 7)) & 0xf;
    for (i = 0; i < entryCount; i++) {
        *(int*)&state.bit = state.bit + 8;
    }
    state.bit += 4;
    mapBlockRender_drawLightmapIndirectPasses(block, shader, &state, (float (*)[4])viewMtx);
}
void mapBlockRenderWater(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx) {
    ModelRenderInstrsState state;
    Mtx m;
    int countShifted;
    struct Shader* shader;
    int bitCursor;
    u32 instructionBits;
    u8* instructionCursor;
    int entryCount;
    int i;
    u8* instructionBytes;

    PSMTXConcat((MtxPtr)gCameraLightPerspectiveScaledMatrix, (MtxPtr)viewMtx, m);
    GXLoadTexMtxImm(m, GX_TEXMTX0, GX_MTX3x4);
    PSMTXConcat((MtxPtr)gCameraLightPerspectiveFlipYMatrix, (MtxPtr)viewMtx, m);
    GXLoadTexMtxImm(m, GX_TEXMTX1, GX_MTX3x4);
    setupWaterCausticTev();
    countShifted = block->nRenderInstrsWater << 3;
    modelRenderInstrsState_init(&state, block->renderInstrsWater, countShifted, countShifted);
    modelRenderInstrsState_setBit(&state, bounds->renderBitOffset);
    state.bit += 4;
    shader = mapBlockRender_setShader(1, block, &state);
    state.bit += 4;
    mapBlockRender_setVtxDcrs(1, block, shader, &state);
    bitCursor = state.bit + 4;
    state.bit = bitCursor;
    countShifted = bitCursor >> 3;
    instructionBytes = state.instrs;
    instructionBits = instructionBytes[countShifted];
    instructionCursor = (u8*)((int)state.instrs + countShifted);
    instructionBits = instructionBits | ((u32)instructionCursor[1] << 8);
    instructionBits = instructionBits | ((u32)instructionCursor[2] << 16);
    state.bit += 4;
    entryCount = (instructionBits >> (bitCursor & 7)) & 0xf;
    for (i = 0; i < entryCount; i++) {
        *(int*)&state.bit = state.bit + 8;
    }
    state.bit += 4;
    mapBlockRender_callList(1, 1, block, shader, &state, viewMtx);
}
void mapBlockRenderTransparent(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx) {
    ModelRenderInstrsState state;
    int countShifted;
    struct Shader* shader;
    int bitCursor;
    u32 instructionBits;
    u8* instructionCursor;
    int entryCount;
    int i;
    u8* instructionBytes;

    Camera_ApplyTransparentViewport();
    countShifted = block->nRenderInstrsTransp << 3;
    modelRenderInstrsState_init(&state, block->renderInstrsTransp, countShifted, countShifted);
    modelRenderInstrsState_setBit(&state, bounds->renderBitOffset);
    state.bit += 4;
    shader = mapBlockRender_setShader(1, block, &state);
    state.bit += 4;
    mapBlockRender_setVtxDcrs(1, block, shader, &state);
    bitCursor = state.bit + 4;
    state.bit = bitCursor;
    countShifted = bitCursor >> 3;
    instructionBytes = state.instrs;
    instructionBits = instructionBytes[countShifted];
    instructionCursor = (u8*)((int)state.instrs + countShifted);
    instructionBits = instructionBits | ((u32)instructionCursor[1] << 8);
    instructionBits = instructionBits | ((u32)instructionCursor[2] << 16);
    state.bit += 4;
    entryCount = (instructionBits >> (bitCursor & 7)) & 0xf;
    for (i = 0; i < entryCount; i++) {
        *(int*)&state.bit = state.bit + 8;
    }
    state.bit += 4;
    mapBlockRender_callList(1, 1, block, shader, &state, viewMtx);
    Camera_ApplyFullViewport();
}

void lightmapDrawQueuedObject(GameObject* obj) {
    ObjModel* model = Obj_GetActiveModel(obj);
    if (model->renderAttachment != NULL) {
        objRenderAttachment(obj, (int*)model);
    } else {
        ObjModelState* shadow;
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, obj);
        objRenderInvalidateStateCache();
        objRender(0, 0, 0, 0, obj, 1);
        Camera_ApplyDecalViewport();
        shadow = (ObjModelState*)(obj->anim.modelState);
        if (shadow != NULL && shadow->shadowCastSlot != NULL) {
            objShadowRender(obj, 0, 0, framesThisStep);
        } else if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_CRASH) {
            objDrawGroundShadow(obj, model);
        }
        Camera_ApplyFullViewport();
    }
}

static inline void lightmapSetObjAmbColor(void) {
    GXColor color;

    objGetSunColor(0, (u8*)&color, (u8*)&color + 1, (u8*)&color + 2);
    GXSetChanAmbColor(GX_COLOR0, color);
    GXSetNumChans(1);
}

void sceneDrawTransparentPolys(void) {
    int i;
    LightmapDrawItem item;
    GameObject* player;
    LightmapDrawEntry* entries;
    f32 m[16];

    lightmap_sortTransparentDrawQueue();
    i = 0;
    entries = (LightmapDrawEntry*)gLightmapDrawQueue.entries;
    for (; i < gLightmapDrawQueueCount; i++) {
        switch (entries[i].type) {
        case 0:
            expgfx_renderSourcePools(entries[i].arg0.value, 0);
            lightmapDrawQueuedObject(entries[i].arg0.object);
            expgfx_renderSourcePools(entries[i].arg0.value, 1);
            break;
        case 1:
            item.object = entries[i].arg0.object;
            Obj_GetActiveModel(item.object);
            player = Obj_GetPlayerObject();
            if (item.object == player) {
                if (playerIsDisguised(item.object) == 0) {
                    playerRenderFuzz(item.object, 1, 1);
                }
            } else {
                objRenderFuzz(item.object);
            }
            break;
        case 2:
            Camera_ApplyDecalViewport();
            objShadowRender(entries[i].arg0.object, 0, 0, framesThisStep);
            Camera_ApplyFullViewport();
            break;
        case 3:
            Camera_ApplyDecalViewport();
            objDrawGroundShadow(entries[i].arg0.object, Obj_GetActiveModel(entries[i].arg0.object));
            Camera_ApplyFullViewport();
            break;
        case 4:
            item.block = entries[i].arg1.block;
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            lightmapSetObjAmbColor();
            PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), item.block->transform, (MtxPtr)m);
            setupToRenderMapBlock(item.block, m);
            mapBlockRenderTransparent(entries[i].arg0.bounds, entries[i].arg1.block, m);
            break;
        case 5:
            item.block = entries[i].arg1.block;
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            lightmapSetObjAmbColor();
            PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), item.block->transform, (MtxPtr)m);
            setupToRenderMapBlock(item.block, m);
            mapBlockRenderWater(entries[i].arg0.bounds, entries[i].arg1.block, m);
            break;
        case 6:
            item.block = entries[i].arg1.block;
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            lightmapSetObjAmbColor();
            PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), item.block->transform, (MtxPtr)m);
            setupToRenderMapBlock(item.block, m);
            mapBlockRenderMain(entries[i].arg0.bounds, entries[i].arg1.block, m);
            break;
        case 7:
            drawGlow(entries[i].arg0.value, entries[i].arg1.value);
            break;
        case 8:
            waterFxDraw();
            break;
        case 9:
            (*gWaterfxInterface)->render(0, 0);
        }
    }
}

void lightmap_queueExternalRenderEntry(u32 a, u32 b, f32* p) {
    s32 t;
    if (gLightmapDrawQueueCount == 1000) {
        sceneDrawTransparentPolys();
        gLightmapDrawQueueCount = 0;
    }
    t = (s32)-p[2];
    t = t < 0 ? 0 : (t > 0x7ffffff ? 0x7ffffff : t);
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].a = a;
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].b = b;
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].key = t | 0x38000000;
    gLightmapDrawQueue.entries[gLightmapDrawQueueCount].type = 7;
    gLightmapDrawQueueCount++;
}

u8 gCloudLayerOverlayColor[4] = {0x20, 0x20, 0x20, 0};
GXColor gTexShaderAmbColor = {0xFF, 0xFF, 0xFF, 0xFF};
GXColor gTexLightmapAmbColor = {0xff, 0xff, 0xff, 0xff};
s8 gTexIndMtxScaleExp = -2;
const f32 gTexIndMtxScale = 0.0625f;
extern const GXColor gTexShaderFogColor;
extern const GXColor gTexLightmapFogColor;

extern IndTexMtx23 gTexIndMtxTable;
extern WarpDestination gRcpPendingWarpDest;

static u8 mapBlockBounds_HasCornerPastDepthThreshold(MapBlockBoundsRec* bounds, float* xform) {
    Vec v;
    u32 i;
    f32 fbset;
    f32 timing;

    i = 0;
    timing = 0.125f;
    fbset = -250.0f;
    while (1) {
        {
            switch (i) {
            case 0:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->minZ;
                break;
            case 1:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->minZ;
                break;
            case 2:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->minZ;
                break;
            case 3:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->minZ;
                break;
            case 4:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->maxZ;
                break;
            case 5:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->maxZ;
                break;
            case 6:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->maxZ;
                break;
            case 7:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->maxZ;
                break;
            }
        }
        v.x *= timing;
        v.y *= timing;
        v.z *= timing;
        PSMTXMultVec((MtxPtr)xform, &v, &v);
        if (v.z >= fbset) {
            return 1;
        }
        i += 1;
        if ((int)i < 8) {
            continue;
        }
        return 0;
    }
}

#define SHADER_FLAGS(s) ((s)->flags)

void mapBlockRender_drawLightmapIndirectPasses(struct MapBlockData* blockData, Shader* shader,
                                               ModelRenderInstrsState* state, f32 (*viewMtx)[4]) {
    f32 passMtx[3][4];
    IndTexMtx23 indMtx;
    int noiseFrameCount;
    Texture** noiseTextures;
    MapBlockBoundsRec* bounds[1];
    u8 passCount;
    u8* byteBase;
    u32 bits;
    int bitPos;
    u32 flags;
    int i;

    bitPos = state->bit;
    {
        int off = bitPos >> 3;
        byteBase = state->instrs;
        bits = byteBase[off];
        byteBase += off;
        bits = bits | (u32)(byteBase[1] << 8);
        bits = bits | (u32)(byteBase[2] << 16);
    }
    state->bit = bitPos + 8;
    /* extract this cursor's 8-bit field (LSB-first: shift out the bits already
     * consumed within the byte, then mask the width) -> bounds-record index */
    bounds[0] = &blockData->displayLists[(bits >> (bitPos & 7)) & 0xff];
    flags = SHADER_FLAGS(shader);
    if ((flags & 0x4000) != 0) {
        passCount = 4;
    } else if ((flags & 0x8000) != 0) {
        passCount = 8;
    } else if ((flags & 0x10000) != 0) {
        passCount = 0x10;
    } else {
        return;
    }
    i = 0;
    for (; i < passCount; i = i + 1) {
        PSMTXTrans(passMtx, 0.0f, 0.4f * (f32)(i + 1), 0.0f);
        PSMTXConcat(viewMtx, passMtx, passMtx);
        GXLoadPosMtxImm(passMtx, GX_PNMTX0);
        indMtx = gTexIndMtxTable;
        newshadows_getNoiseTextureFrames(&noiseTextures, &noiseFrameCount);
        selectTexture(noiseTextures[(u8)i], 1);
        {
            const f32* scale = &gTexIndMtxScale;
            f32 s = (f32)((i & 0xff) + 1) * *scale;
            indMtx.m[0][0] = s / 2.0f;
        }
        indMtx.m[1][1] = indMtx.m[0][0];
        GXSetIndTexMtx(GX_ITM_0, indMtx.m, gTexIndMtxScaleExp);
        GXCallDisplayList(bounds[0]->dlist, bounds[0]->dlistSize);
    }
}

Shader* mapBlockRender_setLightmapShader(struct MapBlockData* blockData, ModelRenderInstrsState* state) {
    Shader* shader;
    u32 shaderIdx;
    u8* byteBase;
    GXColor fogColor = gTexLightmapFogColor;
    u32 bits;
    u32 bitPos;
    u8 ambColor[3];

    bitPos = state->bit;
    {
        int off = (int)bitPos >> 3;
        byteBase = state->instrs;
        bits = byteBase[off];
        byteBase += off;
        bits |= (u32)byteBase[1] << 8;
        bits |= (u32)byteBase[2] << 16;
        state->bit = bitPos + 6;
        shaderIdx = (bits >> (bitPos & 7)) & 0x3f;
        shader = &blockData->shaders[shaderIdx];
    }
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    selectTexture(((ShaderLayer*)Shader_getLayer(shader, 0))->texture, 0);
    if ((SHADER_FLAGS(shader) & 4) != 0) {
        _gxSetFogParams();
    } else {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogColor);
    }
    if ((SHADER_FLAGS(shader) & 1) != 0 || (SHADER_FLAGS(shader) & 0x40000) != 0 ||
        (SHADER_FLAGS(shader) & 0x800) != 0 || (SHADER_FLAGS(shader) & 0x1000) != 0) {
        GXSetChanAmbColor(GX_COLOR0, gTexLightmapAmbColor);
        if ((SHADER_FLAGS(shader) & 0x40000) != 0) {
            GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        } else {
            GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        }
    } else {
        objGetSunColor(0, &ambColor[0], &ambColor[1], &ambColor[2]);
        GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&ambColor[0]);
    }
    return shader;
}

void mapBlockRender_drawDimmedAabbLights(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx) {
    ModelLightStruct** lightPtr;
    f32 posZ;
    f32 posY;
    f32 posX;
    int lightCount;
    u8 colorA;
    u8 colorB;
    u8 colorG;
    u8 colorR;

    {
        f32 fz = *(f32*)&playerMapOffsetZ;
        f32 fldZ = block->transform[2][3];
        f32 fldY = block->transform[1][3];
        f32 fx = *(f32*)&playerMapOffsetX;
        f32 fldX = block->transform[0][3];
        f32 ax0 = (f32)(bounds->minX >> 3) + fldX;
        f32 az0 = (f32)(bounds->minZ >> 3) + fldZ;
        f32 ax1 = (f32)(bounds->maxX >> 3) + fldX;
        f32 az1 = (f32)(bounds->maxZ >> 3) + fldZ;
        modelLightStruct_selectBrightestAabbLights(ax0 + fx, (f32)(bounds->minY >> 3) + fldY, az0 + fz, ax1 + fx,
                                                   (f32)(bounds->maxY >> 3) + fldY, az1 + fz, gTexDimmedLightList, 2,
                                                   &lightCount);
    }
    Rcp_ResetTextureStageState();
    setupCausticBaseTevStages(viewMtx);
    {
        u8* pColorA;
        u8* pColorB;
        u8* pColorG;
        f32* pPosZ;
        f32* pPosY;
        int i;

        i = 0;
        lightPtr = gTexDimmedLightList;
        pColorA = &colorA;
        pColorB = &colorB;
        pColorG = &colorG;
        pPosZ = &posZ;
        pPosY = &posY;
        for (; i < lightCount; lightPtr = lightPtr + 1, i = i + 1) {
            modelLightStruct_getDiffuseColor(*lightPtr, &colorR, pColorG, pColorB, pColorA);
            colorR = ((int)colorR >> 1) + ((int)colorR >> 2);
            colorG = ((int)colorG >> 1) + ((int)colorG >> 2);
            colorB = ((int)colorB >> 1) + ((int)colorB >> 2);
            modelLightStruct_getPosition(*lightPtr, &posX, pPosY, pPosZ);
            addPointLightDirectStages(modelLightStruct_getRadius(*lightPtr), (int*)&colorR, &posX);
        }
    }
    Rcp_ApplyTextureStageCounts();
    GXSetNumChans(1);
    GXSetCullMode(GX_CULL_BACK);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return;
}

u32 frustumTestAabbWithPlaneOffsets(f32 minX, f32 maxX, f32 minY, f32 maxY, f32 minZ, f32 maxZ, f32* planeOffsets) {
    FrustumPlane* plane;
    int cornerIndex;
    int i;
    float nearX;
    float nearY;
    float nearZ;
    float farX;
    float farY;
    float farZ;

    plane = gViewFrustumPlanes;
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++) {
        cornerIndex = plane[i].aabbCornerIndex;
        if ((cornerIndex & 1) != 0) {
            nearX = maxX;
            farX = minX;
        } else {
            nearX = minX;
            farX = maxX;
        }
        if ((cornerIndex & 2) != 0) {
            nearY = maxY;
            farY = minY;
        } else {
            nearY = minY;
            farY = maxY;
        }
        if ((cornerIndex & 4) != 0) {
            nearZ = maxZ;
            farZ = minZ;
        } else {
            nearZ = minZ;
            farZ = maxZ;
        }
        if ((nearX * plane[i].normalX + nearY * plane[i].normalY + nearZ * plane[i].normalZ + plane[i].distance +
                 planeOffsets[i] <
             0.0f) &&
            (farX * plane[i].normalX + farY * plane[i].normalY + farZ * plane[i].normalZ + plane[i].distance +
                 planeOffsets[i] <
             0.0f)) {
            return 0;
        }
    }
    return 1;
}

static u8 mapBlockBounds_ComputeAndTestPlanes(MapBlockBoundsRec* bounds, struct MapBlockData* block,
                                              FrustumPlane* planes, int planeCount, f32* minX, f32* minY, f32* minZ,
                                              f32* maxX, f32* maxY, f32* maxZ) {
    u8 cornerIndex;
    float nearX;
    float nearY;
    float nearZ;
    float farX;
    float farY;
    float farZ;
    int i;
    *maxX = (f32)(bounds->maxX >> 3) + block->transform[0][3];
    *minX = (f32)(bounds->minX >> 3) + block->transform[0][3];
    *maxY = (f32)(bounds->maxY >> 3) + block->transform[1][3];
    *minY = (f32)(bounds->minY >> 3) + block->transform[1][3];
    *maxZ = (f32)(bounds->maxZ >> 3) + block->transform[2][3];
    *minZ = (f32)(bounds->minZ >> 3) + block->transform[2][3];
    for (i = 0; i < planeCount; i = i + 1) {
        cornerIndex = planes->aabbCornerIndex;
        if ((cornerIndex & 1) != 0) {
            nearX = *maxX;
            farX = *minX;
        } else {
            nearX = *minX;
            farX = *maxX;
        }
        if ((cornerIndex & 2) != 0) {
            nearY = *maxY;
            farY = *minY;
        } else {
            nearY = *minY;
            farY = *maxY;
        }
        if ((cornerIndex & 4) != 0) {
            nearZ = *maxZ;
            farZ = *minZ;
        } else {
            nearZ = *minZ;
            farZ = *maxZ;
        }
        if ((planes->distance + (nearX * planes->normalX + nearY * planes->normalY + nearZ * planes->normalZ) < 0.0f) &&
            (planes->distance + (farX * planes->normalX + farY * planes->normalY + farZ * planes->normalZ) < 0.0f)) {
            return 0;
        }
        planes++;
    }
    return 1;
}

void mapBlockRender_callList(u8 passSelect, u32 visArg, MapBlockData* block, Shader* shader,
                             ModelRenderInstrsState* state, float* mtx) {
    int lightPos[3];
    int count;
    float minX;
    float minY;
    float minZ;
    float maxX;
    float maxY;
    float maxZ;
    u8 lightColor[4];
    GXColor chanColor;
    int i;
    u32 visible;
    u32 flags;
    u32 bits;
    int bitPos;
    u8* byteBase;

    {
        LightSortEntry* texGlobals;
        MapBlockBoundsRec* bounds[1];

        texGlobals = (LightSortEntry*)gLightmapDrawQueue.entries;
        bitPos = state->bit;
        {
            int off = bitPos >> 3;
            byteBase = state->instrs;
            bits = byteBase[off];
            byteBase += off;
            bits = bits | (u32)(byteBase[1] << 8);
            bits = bits | (u32)(byteBase[2] << 16);
        }
        state->bit = bitPos + 8;
        bounds[0] = &block->displayLists[(bits >> (bitPos & 7)) & 0xff];
        if ((shader != NULL) && ((SHADER_FLAGS(shader) & 2) != 0)) {
            return;
        }
        if (mapBlockBounds_ComputeAndTestPlanes(bounds[0], block, (FrustumPlane*)((u8*)texGlobals + 0x987c),
                                                FRUSTUM_PLANE_COUNT, &minX, &minY, &minZ, &maxX, &maxY, &maxZ) == 0) {
            return;
        }
        if (passSelect == 0) {
            flags = SHADER_FLAGS(shader);
            if ((flags & 0x80000000) != 0) {
                int shadowType;

                lightmapQueueShadowRow(bounds[0], block, bounds[0]->selector);
                shadowType = 5;
                texGlobals[gLightmapDrawQueueCount].type = shadowType;
                gLightmapDrawQueueCount += 1;
            } else if (((flags & 0x40000000) != 0) || ((flags & 0x2000) != 0)) {
                int shadowType;

                lightmapQueueShadowRow(bounds[0], block, bounds[0]->selector);
                shadowType = 4;
                texGlobals[gLightmapDrawQueueCount].type = shadowType;
                gLightmapDrawQueueCount += 1;
            }
        } else {
            if (shader != NULL) {
                flags = SHADER_FLAGS(shader);
                if (((flags & 0x80000000) == 0) && ((flags & 0x20000) == 0)) {
                    if ((shader != NULL) && ((flags & 0x80000) != 0)) {
                        count = 0;
                    } else {
                        modelLightStruct_selectBrightestAabbLights(
                            minX + playerMapOffsetX, minY, minZ + playerMapOffsetZ, maxX + playerMapOffsetX, maxY,
                            maxZ + playerMapOffsetZ, gTexBlockLightList, 2, &count);
                    }
                    if ((shader != NULL) &&
                        (((SHADER_FLAGS(shader) & 0x800) != 0 || ((SHADER_FLAGS(shader) & 0x1000) != 0)))) {
                        ObjSeq_copyDefaultColor(&chanColor);
                        chanColor.a = 0;
                        chanColor.b = 0;
                        chanColor.g = 0;
                        chanColor.r = 0;
                        if (count == 0) {
                            if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x800) != 0)) {
                                addLightColorModulateStage((int*)&chanColor);
                            } else {
                                addVertexAlphaDimStage((u8*)&chanColor);
                            }
                        } else {
                            modelLightStruct_getDiffuseColor(gTexBlockLightList[0], &lightColor[0], &lightColor[1],
                                                             &lightColor[2], &lightColor[3]);
                            modelLightStruct_getPosition(gTexBlockLightList[0], (f32*)&lightPos[0], (f32*)&lightPos[1],
                                                         (f32*)&lightPos[2]);
                            addFirstPointLightStages(modelLightStruct_getRadius(gTexBlockLightList[0]),
                                                     (int*)lightColor, (f32*)&lightPos[0], (u8*)&chanColor);
                            for (i = 1; i < count; i = i + 1) {
                                modelLightStruct_getDiffuseColor(gTexBlockLightList[i], &lightColor[0], &lightColor[1],
                                                                 &lightColor[2], &lightColor[3]);
                                modelLightStruct_getPosition(gTexBlockLightList[i], (f32*)&lightPos[0],
                                                             (f32*)&lightPos[1], (f32*)&lightPos[2]);
                                addPointLightAccumStages(modelLightStruct_getRadius(gTexBlockLightList[i]),
                                                         (int*)lightColor, (f32*)&lightPos[0]);
                            }
                            if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x800) != 0)) {
                                addAccumulatedLightModulateStage();
                            } else {
                                addAccumulatedLightBlendStages();
                            }
                        }
                    } else {
                        for (i = 0; i < count; i = i + 1) {
                            modelLightStruct_getDiffuseColor(gTexBlockLightList[i], &lightColor[0], &lightColor[1],
                                                             &lightColor[2], &lightColor[3]);
                            modelLightStruct_getPosition(gTexBlockLightList[i], (f32*)&lightPos[0], (f32*)&lightPos[1],
                                                         (f32*)&lightPos[2]);
                            addPointLightDirectStages(modelLightStruct_getRadius(gTexBlockLightList[i]),
                                                      (int*)lightColor, (f32*)&lightPos[0]);
                        }
                    }
                    if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x2000) != 0)) {
                        if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x40000000) != 0)) {
                            visible = visArg;
                        } else {
                            u8 mirrorVisible = mapBlockBounds_ComputeAndTestPlanes(
                                bounds[0], block, (FrustumPlane*)((u8*)texGlobals + 0x9818), FRUSTUM_PLANE_COUNT, &minX,
                                &minY, &minZ, &maxX, &maxY, &maxZ);
                            if ((mirrorVisible != 0 && (u8)visArg != 0) || (mirrorVisible == 0 && (u8)visArg == 0)) {
                                visible = 1;
                            } else {
                                visible = 0;
                            }
                            if ((u8)visArg != 0) {
                                GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                                gxSetZMode_(1, GX_LEQUAL, 0);
                                gxSetPeControl_ZCompLoc_(1);
                                GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                            }
                        }
                        if ((u8)visible == 0) {
                            return;
                        }
                        addShadowFalloffTevStages();
                    }
                    Rcp_ApplyTextureStageCounts();
                }
            }
            GXCallDisplayList(bounds[0]->dlist, bounds[0]->dlistSize);
            flags = SHADER_FLAGS(shader);
            if ((((flags & 0x4000) != 0) || ((flags & 0x8000) != 0) || ((flags & 0x10000) != 0)) &&
                (mapBlockBounds_HasCornerPastDepthThreshold(bounds[0], mtx) != 0)) {
                int shadowType;

                lightmapQueueShadowRow(bounds[0], block, 0x17);
                shadowType = 6;
                texGlobals[gLightmapDrawQueueCount].type = shadowType;
                gLightmapDrawQueueCount += 1;
            }
        }
    }
}

static void mapBlockRender_setupShaderTextures(Shader* shader, int mode) {
    int layerIdx;
    ShaderLayer* layer;
    Texture* texture;
    f32(*texMtx)[4];
    int overrideIdx;
    int remain;
    MapTextureOverride* overrideEntry;
    u8 layerByte;
    GXColor kColor;
    f32 tx;
    f32 texMatrix[3][4];

    kColor = sMapWhiteColor;
    if ((shader->layerCount == 2) &&
        (texture = (Texture*)Shader_getLayer(shader, 1), (((ShaderLayer*)texture)->typeBits & 0x7f) == 9u)) {
        layer = Shader_getLayer(shader, 0);
        {
            u8 overrideType;
            if ((overrideType = layer->materialId) != '\0') {
                Texture* layerTextureId = layer->texture;
                MapTextureOverride* overrides;
                overrideIdx = 0;
                overrides = (MapTextureOverride*)(int)gMapTextureOverrides;
                overrideEntry = overrides;
                for (remain = 0x50; remain != 0 || (texture = layerTextureId, 0); remain--) {
                    if (((overrideEntry->refCount > 0) && (overrideEntry->texture == layerTextureId)) &&
                        ((int)overrideType == overrideEntry->type)) {
                        texture = textureGetAnimationFrame(layerTextureId, overrides[overrideIdx].frame);
                        break;
                    }
                    overrideEntry += 1;
                    overrideIdx += 1;
                }
            } else {
                texture = layer->texture;
            }
        }
        if (layer->scrollMtx != 0xff) {
            tx = gMapTextureScrolls[layer->scrollMtx].offsetX / 1048576.0f;
            PSMTXTrans(texMatrix, tx, gMapTextureScrolls[layer->scrollMtx].offsetY / 1048576.0f, 0.0f);
            texMtx = texMatrix;
        } else {
            texMtx = NULL;
        }
        addTexLayerStageKColor(texture, texMtx, 0, &kColor);
        if ((SHADER_FLAGS(shader) & 0x100) != 0) {
            addSmallReflectionTevStage();
        }
        layer = Shader_getLayer(shader, 1);
        {
            u8 overrideType;
            if ((overrideType = layer->materialId) != '\0') {
                Texture* layerTextureId = layer->texture;
                MapTextureOverride* overrides;
                overrideIdx = 0;
                overrides = (MapTextureOverride*)(int)gMapTextureOverrides;
                overrideEntry = overrides;
                for (remain = 0x50; remain != 0 || (texture = layerTextureId, 0); remain--) {
                    if (((overrideEntry->refCount > 0) && (overrideEntry->texture == layerTextureId)) &&
                        ((int)overrideType == overrideEntry->type)) {
                        texture = textureGetAnimationFrame(layerTextureId, overrides[overrideIdx].frame);
                        break;
                    }
                    overrideEntry += 1;
                    overrideIdx += 1;
                }
            } else {
                texture = layer->texture;
            }
        }
        if (layer->scrollMtx != 0xff) {
            tx = gMapTextureScrolls[layer->scrollMtx].offsetX / 1048576.0f;
            PSMTXTrans(texMatrix, tx, gMapTextureScrolls[layer->scrollMtx].offsetY / 1048576.0f, 0.0f);
            texMtx = texMatrix;
        } else {
            texMtx = NULL;
        }
        addTexLayerStage(texture, texMtx, 9);
        addVertexColorKAlphaStage(&kColor);
    } else {
        for (layerIdx = 0; layerIdx < (int)(u32)shader->layerCount; layerIdx = layerIdx + 1) {
            Texture* layerTextureId;
            layer = Shader_getLayer(shader, layerIdx);
            layerTextureId = layer->texture;
            if (layerTextureId != NULL) {
                u8 overrideType;
                {
                    if ((overrideType = layer->materialId) != '\0') {
                        MapTextureOverride* overrides;
                        overrideIdx = 0;
                        overrides = (MapTextureOverride*)(int)gMapTextureOverrides;
                        overrideEntry = overrides;
                        for (remain = 0x50; remain != 0 || (texture = layerTextureId, 0); remain--) {
                            if (((overrideEntry->refCount > 0) && (overrideEntry->texture == layerTextureId)) &&
                                ((int)overrideType == overrideEntry->type)) {
                                texture = textureGetAnimationFrame(layerTextureId, overrides[overrideIdx].frame);
                                break;
                            }
                            overrideEntry += 1;
                            overrideIdx += 1;
                        }
                    } else {
                        texture = layerTextureId;
                    }
                    if (layer->scrollMtx != 0xff) {
                        int scrollOffset = (u32)layer->scrollMtx * 0x10;
                        tx = ((MapTextureScroll*)((u8*)gMapTextureScrolls + scrollOffset))->offsetX / 1048576.0f;
                        PSMTXTrans(texMatrix, tx,
                                   ((MapTextureScroll*)((u8*)gMapTextureScrolls + scrollOffset))->offsetY / 1048576.0f,
                                   0.0f);
                        texMtx = texMatrix;
                    } else {
                        texMtx = NULL;
                    }
                    layerByte = layer->typeBits & 0x7f;
                    if ((SHADER_FLAGS(shader) & 0x40000) != 0) {
                        addTexLayerStagesLit((void*)texture, texMtx);
                    } else {
                        addTexLayerStage(texture, texMtx, layerByte);
                    }
                }
            } else {
                addVertexColorStage();
            }
        }
        if ((SHADER_FLAGS(shader) & 0x100) != 0) {
            addSmallReflectionTevStage();
        }
    }
    return;
}

Shader* mapBlockRender_setShader(u8 doSetup, MapBlockData* blockData, ModelRenderInstrsState* state) {
    Shader* shader;
    u32 shaderIdx;
    GXColor fogColor = gTexShaderFogColor;
    u8* instructionBytes;
    u32 flags;
    int* cloudTex;
    u8 ambColor[3];
    u8 fogRgba[4];
    u32 bits;
    u32 bitPos;

    bitPos = state->bit;
    {
        int byteOffset = (int)bitPos >> 3;
        instructionBytes = state->instrs;
        bits = instructionBytes[byteOffset];
        bits |= (u32)instructionBytes[byteOffset + 1] << 8;
        bits |= (u32)instructionBytes[byteOffset + 2] << 16;
        state->bit = bitPos + 6;
        shaderIdx = (bits >> (bitPos & 7)) & 0x3f;
        shader = &blockData->shaders[shaderIdx];
    }

    if (doSetup == 0) {
        return shader;
    }

    if ((SHADER_FLAGS(shader) & 4) != 0) {
        _gxSetFogParams();
    } else {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogColor);
    }
    if ((shader != 0) && ((SHADER_FLAGS(shader) & 0x80000000) != 0)) {
        return shader;
    }
    if ((shader != 0) && ((SHADER_FLAGS(shader) & 0x20000) != 0)) {
        u32 res;
        res = AttractMovie_DrawTextureCallback(0, 0, 0);
        if ((res & 0xff) != 0) {
            return shader;
        }
    }
    Rcp_ResetTextureStageState();
    if ((SHADER_FLAGS(shader) & 0x80) != 0) {
        setupHeatShimmerTevStages((char*)shader);
    } else {
        mapBlockRender_setupShaderTextures(shader, 0x80);
    }
    flags = SHADER_FLAGS(shader);
    if ((flags & 0x20) != 0 && (cloudTex = gCloudLayerTexture) != 0) {
        addSignedOverlayTexStage((u8*)cloudTex, &gCloudLayerTexMatrix, gCloudLayerOverlayColor);
    } else if ((flags & 0x40) != 0) {
        addWarpedRingTevStages();
    } else if (isHeavyFogEnabled()) {
        getFogColorRgb(fogRgba);
        renderHeavyFog(fogRgba);
    }
    if (((SHADER_FLAGS(shader) & 0x40000000) != 0) || ((SHADER_FLAGS(shader) & 0x20000000) != 0)) {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 0);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    } else if ((SHADER_FLAGS(shader) & 0x400) != 0 && (SHADER_FLAGS(shader) & 0x80) == 0) {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
        gxSetPeControl_ZCompLoc_(0);
        GXSetAlphaCompare(GX_GREATER, 0, GX_AOP_AND, GX_GREATER, 0);
    } else {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    }
    if ((SHADER_FLAGS(shader) & 1) != 0 || (SHADER_FLAGS(shader) & 0x40000) != 0 ||
        (SHADER_FLAGS(shader) & 0x800) != 0 || (SHADER_FLAGS(shader) & 0x1000) != 0) {
        GXSetChanAmbColor(GX_COLOR0, gTexShaderAmbColor);
        if ((SHADER_FLAGS(shader) & 0x40000) != 0) {
            GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        } else {
            GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        }
    } else {
        objGetSunColor(0, &ambColor[0], &ambColor[1], &ambColor[2]);
        GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&ambColor[0]);
    }
    if ((SHADER_FLAGS(shader) & 0x8) != 0) {
        GXSetCullMode(GX_CULL_BACK);
    } else {
        GXSetCullMode(GX_CULL_NONE);
    }
    return shader;
}

extern int sSynthFadeUnit;

static inline void GXPosition3f32(const f32 x, const f32 y, const f32 z) {
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void GXTexCoord2f32(const f32 s, const f32 t) {
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

void mapBlockRender_setVtxDcrs(u8 doSetup, MapBlockData* block, Shader* shader, ModelRenderInstrsState* state) {
    int* stateWords;
    u32 val;
    int pos;
    int off;
    u8* p;
    int bit;
    u32 val2;
    int pos2;
    int off2;
    u8* q;
    int bit2;
    u32 val3;
    int pos3;
    int off3;
    u8* r;
    int bit3;
    int i;

    stateWords = (int*)state;
    if (doSetup != 0) {
        GXClearVtxDesc();
    }
    pos = state->bit;
    off = pos >> 3;
    val = *(u8*)(stateWords[0] + off);
    p = (u8*)stateWords[0] + off;
    val |= p[1] << 8;
    val |= p[2] << 16;
    state->bit = pos + 1;
    bit = (val >> (pos & 7)) & 1;
    if (doSetup != 0) {
        GXSetVtxDesc(GX_VA_POS, bit ? GX_INDEX16 : GX_INDEX8);
    }
    pos2 = state->bit;
    off2 = pos2 >> 3;
    val2 = *(u8*)(stateWords[0] + off2);
    q = (u8*)stateWords[0] + off2;
    val2 |= q[1] << 8;
    val2 |= q[2] << 16;
    state->bit = pos2 + 1;
    bit2 = (val2 >> (pos2 & 7)) & 1;
    if (doSetup != 0) {
        GXSetVtxDesc(GX_VA_CLR0, bit2 ? GX_INDEX16 : GX_INDEX8);
    }
    pos3 = state->bit;
    off3 = pos3 >> 3;
    val3 = *(u8*)(stateWords[0] + off3);
    r = (u8*)stateWords[0] + off3;
    val3 |= r[1] << 8;
    val3 |= r[2] << 16;
    state->bit = pos3 + 1;
    bit3 = (val3 >> (pos3 & 7)) & 1;
    if (doSetup != 0) {
        if (shader != NULL && (shader->flags & 0x80000000) == 0) {
            for (i = 0; i < shader->layerCount; i++) {
                GXSetVtxDesc(i + GX_VA_TEX0, bit3 ? GX_INDEX16 : GX_INDEX8);
            }
        } else {
            GXSetVtxDesc(GX_VA_TEX0, bit3 ? GX_INDEX16 : GX_INDEX8);
        }
    }
}

void setupToRenderMapBlock(MapBlockData* block, void* posMtx) {
    Mtx out;
    Mtx tmp;
    f32 fc;

    GXLoadPosMtxImm((const f32(*)[4])posMtx, GX_PNMTX0);
    PSMTXCopy((MtxPtr)posMtx, tmp);
    fc = 0.0f;
    tmp[0][3] = fc;
    tmp[1][3] = fc;
    tmp[2][3] = fc;
    GXLoadNrmMtxImm(tmp, GX_PNMTX0);
    PSMTXConcat((MtxPtr)gCameraLightPerspectiveMatrix, (MtxPtr)posMtx, out);
    GXLoadTexMtxImm(out, GX_TEXMTX2, GX_MTX3x4);
    GXSetArray(GX_VA_POS, block->vertices, 6);
    GXSetArray(GX_VA_CLR0, block->vertexColors, 2);
    GXSetArray(GX_VA_TEX0, block->vertexTexCoords, 4);
    GXSetArray(GX_VA_TEX1, block->vertexTexCoords, 4);
}

void renderMapBlock(MapBlockData* block, u8 type) {
    ModelRenderInstrsState state;
    f32 m[16];
    void* instructions;
    int done;
    Shader* shader;
    u8 doSetup;
    u16 instructionCount;
    void* viewMtx;

    shader = NULL;
    doSetup = FALSE;
    if (type == 1) {
        instructions = block->renderInstrsTransp;
        instructionCount = block->nRenderInstrsTransp;
    } else if (type == 2) {
        instructions = block->renderInstrsWater;
        instructionCount = block->nRenderInstrsWater;
    } else {
        instructions = block->renderInstrsMain;
        instructionCount = block->nRenderInstrsMain;
        doSetup = TRUE;
    }
    if (instructionCount == 0) {
        return;
    }
    viewMtx = Camera_GetViewMatrix();
    PSMTXConcat((MtxPtr)viewMtx, block->transform, (MtxPtr)m);
    if (doSetup) {
        setupToRenderMapBlock(block, m);
    }
    modelRenderInstrsState_init(&state, instructions, instructionCount << 3, instructionCount << 3);
    done = FALSE;
    while (!done) {
        u32 word;
        int op;
        int pos;
        int off = (pos = state.bit) >> 3;
        u8* base;
        u8* bp;

        base = state.instrs;
        bp = base + off;
        word = bp[0];
        word |= bp[1] << 8;
        word |= bp[2] << 16;
        state.bit = pos + 4;
        op = (word >> (pos & 7)) & 0xf;
        switch (op) {
        case 3:
            mapBlockRender_setVtxDcrs(doSetup, block, shader, &state);
            break;
        case 1:
            shader = mapBlockRender_setShader(doSetup, block, &state);
            break;
        case 2:
            mapBlockRender_callList(doSetup, 0, block, shader, &state, m);
            break;
        case 4: {
            u32 word2;
            int cnt;
            int i;
            u8* bp2;
            ModelRenderInstrsState* sp = &state;
            int pos2 = pos + 4;
            bp2 = base + (pos2 >> 3);
            word2 = bp2[0];
            word2 |= bp2[1] << 8;
            word2 |= bp2[2] << 16;
            state.bit = pos2 + 4;
            cnt = (word2 >> (pos2 & 7)) & 0xf;
            for (i = 0; i < cnt; i++) {
                modelRenderInstrsState_advance(sp, 8);
            }
            break;
        }
        case 5:
            done = TRUE;
            break;
        }
    }
}

void renderGlows(void) {
    f32 px, py, pz;
    s32 sx, sy, sz;
    u8 amb[3];
    GXColor fogCol;
    Mtx sunMtx;
    Vec dir;
    Vec cam;
    MtxPtr viewMtx;
    u8 alpha;
    u8 sunAlpha;
    f32 sunDot;
    f32 zero;
    f32 one;
    int i;
    ModelLightStruct* e;

    fogCol = *(GXColor*)&sSynthFadeUnit;
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    gxTevResetStages();
    gxTevColor1TexAlphaStage();
    gxTevCommitStages();
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogCol);
    gxSetAdditiveBlendNoZTest();
    alpha = 0xff;
    gSunFlareScissorWidth = 0;
    gSunFlareScissorHeight = 0;
    sunAlpha = skyGetSunRenderAlpha(2);
    if (sunAlpha != 0 && ((int)renderFlags & 0x40)) {
        viewMtx = (MtxPtr)Camera_GetViewMatrix();
        skyGetSunLightDirection(0, &dir.x, &dir.y, &dir.z);
        cam.x = viewMtx[2][0];
        cam.y = viewMtx[2][1];
        cam.z = viewMtx[2][2];
        sunDot = PSVECDotProduct(&dir, &cam);
        if (sunDot > 0.0f) {
            int occ;
            f32 fade;
            skyBuildSunModelMatrix(sunMtx);
            Camera_ProjectWorldPointWithOffset(sunMtx[0][3], sunMtx[1][3], sunMtx[2][3], 100.0f, &px, &py, &pz);
            Camera_ClipToScreen(px, py, pz, &sx, &sy, &sz);
            gSunFlareScissorX = sx - 0x10;
            gSunFlareScissorWidth = 0x20;
            gSunFlareScissorY = sy - 0x10;
            gSunFlareScissorHeight = 0x20;
            if ((int)gSunFlareScissorX < 0) {
                gSunFlareScissorX = 0;
            } else if ((int)gSunFlareScissorX > 0x280) {
                gSunFlareScissorX = 0x280;
            }
            if ((int)gSunFlareScissorY < 0) {
                gSunFlareScissorY = 0;
            } else if ((int)gSunFlareScissorY > 0x1e0) {
                gSunFlareScissorY = 0x1e0;
            }
            if ((int)gSunFlareScissorX + 0x20 > 0x280) {
                gSunFlareScissorWidth = 0x280 - gSunFlareScissorX;
            }
            if ((int)gSunFlareScissorY + 0x20 > 0x1e0) {
                gSunFlareScissorHeight = 0x1e0 - gSunFlareScissorY;
            }
            occ = 0;
            for (i = 0; i < 5; i++) {
                int d = depthReadRequestPoll(sx + gSunOcclusionSampleOffsets[i].x, sy + gSunOcclusionSampleOffsets[i].y,
                                             (void*)i);
                if (sz <= d && pauseMenuGetState() == 0) {
                    occ++;
                }
            }
            fade = (f32)(u32)occ / 5.0f - gSunFlareFade;
            if (fade > 0.0125f) {
                fade = 0.0125f;
            } else if (fade < -0.0125f) {
                fade = -0.0125f;
            }
            gSunFlareFade += fade;
            sunDot *= gSunFlareFade;
            if (sunDot > 0.0f) {
                PSMTXConcat(viewMtx, sunMtx, sunMtx);
                GXLoadPosMtxImm((const f32(*)[4])sunMtx, GX_PNMTX0);
                GXSetCurrentMtx(GX_PNMTX0);
                selectTexture(skyGetSkyTexture(), 0);
                skyGetSunColor(0, &amb[0], &amb[1], &amb[2]);
                sunDot = (f32)(u32)sunAlpha * sunDot;
                _gxSetTevColor2(amb[0], amb[1], amb[2], (int)(0.5f * sunDot));
                alpha = 255.0f - 0.9f * sunDot;
                fade = 20000.0f * sunDot;
                sunDot = fade / 256.0f;
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                zero = 0.0f;
                one = 1.0f;
                GXPosition3f32(-sunDot, -sunDot, zero);
                GXTexCoord2f32(zero, zero);
                GXPosition3f32(sunDot, -sunDot, zero);
                GXTexCoord2f32(one, zero);
                GXPosition3f32(sunDot, sunDot, zero);
                GXTexCoord2f32(one, one);
                GXPosition3f32(-sunDot, sunDot, zero);
                GXTexCoord2f32(zero, one);
            }
        }
    }
    colorScale = alpha;
    if (gGlowLightCount != 0) {
        for (i = 0; i < gGlowLightCount; i++) {
            int d;
            e = gGlowLightList[i];
            Camera_ProjectWorldPointWithOffset(e->worldX - playerMapOffsetX, e->worldY, e->worldZ - playerMapOffsetZ,
                                               e->glowProjectionRadius, &px, &py, &pz);
            Camera_ClipToScreen(px, py, pz, &sx, &sy, &sz);
            d = depthReadRequestPoll(sx, sy, e);
            if (sz <= d && pauseMenuGetState() == 0) {
                e->glowAlphaStep = 0x10;
            } else {
                e->glowAlphaStep = -0x10;
            }
        }
        GXSetCurrentMtx(GX_IDENTITY);
        gxTevColor1TexAlphaStage();
        gxSetAdditiveBlendNoZTest();
        for (i = 0; i < gGlowLightCount; i++) {
            e = gGlowLightList[i];
            if (e->glowAlpha != 0) {
                selectTexture((Texture*)e->glowTexture, 0);
                _gxSetTevColor2((int)((f32)(u32)e->glowColor[0] * e->activeIntensity),
                                (int)((f32)(u32)e->glowColor[1] * e->activeIntensity),
                                (int)((f32)(u32)e->glowColor[2] * e->activeIntensity),
                                (u8)((int)(e->glowColor[3] * e->glowAlpha) >> 8));
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                zero = 0.0f;
                one = 1.0f;
                GXPosition3f32(e->viewX - e->glowScale, e->viewY - e->glowScale, e->viewZ);
                GXTexCoord2f32(zero, zero);
                GXPosition3f32(e->viewX + e->glowScale, e->viewY - e->glowScale, e->viewZ);
                GXTexCoord2f32(one, zero);
                GXPosition3f32(e->viewX + e->glowScale, e->viewY + e->glowScale, e->viewZ);
                GXTexCoord2f32(one, one);
                GXPosition3f32(e->viewX - e->glowScale, e->viewY + e->glowScale, e->viewZ);
                GXTexCoord2f32(zero, one);
            }
        }
        GXSetCurrentMtx(GX_PNMTX0);
    }
}

void getSunFlareScissorRect(int* outX, int* outY, int* outWidth, int* outHeight) {
    *outX = gSunFlareScissorX;
    *outY = gSunFlareScissorY;
    *outWidth = gSunFlareScissorWidth;
    *outHeight = gSunFlareScissorHeight;
}

static inline int isGlowInFrustum(ModelLightStruct* light) {
    u8 i;
    f32 offsetX;
    f32 offsetZ;
    f32 bias;

    i = 0;
    offsetZ = playerMapOffsetZ;
    offsetX = playerMapOffsetX;
    bias = 0.0f;
    for (; i < 5; i++) {
        f32 dot;
        dot = light->worldY * gViewFrustumPlanes[i].normalY +
              gViewFrustumPlanes[i].normalX * (light->worldX - offsetX) +
              gViewFrustumPlanes[i].normalZ * (light->worldZ - offsetZ) + gViewFrustumPlanes[i].distance + bias;
        if (dot < bias) {
            return 0;
        }
    }
    return 1;
}

void queueGlowRender(ModelLightStruct* light) {
    int visible;
    u8 idx;

    if (gGlowLightCount >= 100) {
        return;
    }

    visible = isGlowInFrustum(light);
    {
        u8 vis = visible;
        if (vis == 0 && light->glowAlpha == 0) {
            return;
        }
        if (vis == 0) {
            light->glowAlphaStep = -0x10;
        }
    }
    idx = gGlowLightCount++;
    gGlowLightList[idx] = light;
}

void trackPackVector(short* out, float* vec) {
    int yScaled;
    int zScaled;

    yScaled = (int)(8.0f * vec[1]);
    zScaled = (int)(8.0f * vec[2]);
    *out = (short)(int)(8.0f * *vec);
    out[1] = yScaled;
    out[2] = zScaled;
}

void trackUnpackVector(s16* in, f32* out) {
    out[0] = (f32)(s32)in[0] / 8.0f;
    out[1] = (f32)(s32)in[1] / 8.0f;
    out[2] = (f32)(s32)in[2] / 8.0f;
}

/* trackBuildModelTriangles -- gather model triangles overlapping a swept bbox into the
 * hit-detect triangle buffer at cur (0x4c-byte records); returns advanced
 * cursor. */

u32 trackGetPackedSurfaceType(CollisionPolygonGroup* group) {
    u32 v = group->flags;
    v &= 0x00FF0000;
    return v >> 16;
}

int mapBlockGetPolygonGroupType(void* obj) {
    return (((CollisionPolygonGroup*)obj)->flags & 0xff000000) >> 24;
}

int mapBlockCountTrianglesByType(MapBlockData* block, int type) {
    CollisionPolygonGroup* entry;
    int offset;
    int total;
    int i;
    int count;
    total = 0;
    offset = 0;
    count = block->polyGroupCount;
    for (i = 0; i < count; i++) {
        entry = (CollisionPolygonGroup*)((u8*)block->polygonGroups + offset);
        if (type == (int)((entry->flags & 0xff000000) >> 24)) {
            total += entry[1].firstTri - entry->firstTri;
        }
        offset += sizeof(CollisionPolygonGroup);
    }
    return total;
}

MapTriIndex* mapBlockGetPolygon(MapBlockData* obj, int idx) {
    return &obj->gcPolygons[idx];
}

CollisionPolygonGroup* mapBlockGetPolygonGroup(MapBlockData* obj, int idx) {
    return &obj->polygonGroups[idx];
}

MapBlockBoundsRec* mapBlockGetDisplayListBounds(MapBlockData* obj, int idx) {
    return &obj->displayLists[idx];
}

Shader* mapBlockGetShader(MapBlockData* obj, int idx) {
    return obj->shaders + idx;
}

void MapBlock_initShaders(MapBlockData* block) {
    int i;
    int j;
    int ref;
    Shader* sh;
    for (i = 0; i < block->shaderCount; i++) {
        sh = &block->shaders[i];
        for (j = 0; j < sh->layerCount; j++) {
            ref = sh->layers[j].textureIndex;
            if (ref != -1) {
                sh->layers[j].texture = block->textures[ref].texture;
                ref = sh->layers[j].materialId;
                if ((u32)ref != 0u) {
                    mapTextureOverrideAcquire(sh->layers[j].texture, 0, ref);
                }
            } else {
                sh->layers[j].texture = NULL;
            }
            sh->layers[j].scrollMtx = 0xff;
        }
        ref = sh->auxTextureIndex;
        if (ref != -1) {
            sh->auxTexture = block->textures[ref].texture;
        } else {
            sh->auxTexture = NULL;
        }
    }
}

static inline void* mapBlockRelocatePointer(MapBlockData* block, void* offset) {
    return (u8*)block + (u32)offset;
}

void MapBlock_init(MapBlockData* block) {
    int i;

    if (block->textures != NULL) {
        block->textures = mapBlockRelocatePointer(block, block->textures);
    }
    if (block->gcPolygons != NULL) {
        block->gcPolygons = mapBlockRelocatePointer(block, block->gcPolygons);
    }
    if (block->polygonGroups != NULL) {
        block->polygonGroups = mapBlockRelocatePointer(block, block->polygonGroups);
    }
    block->vertices = mapBlockRelocatePointer(block, block->vertices);
    block->vertexColors = mapBlockRelocatePointer(block, block->vertexColors);
    block->vertexTexCoords = mapBlockRelocatePointer(block, block->vertexTexCoords);
    if (block->renderInstrsMain != NULL) {
        block->renderInstrsMain = mapBlockRelocatePointer(block, block->renderInstrsMain);
    }
    if (block->renderInstrsTransp != NULL) {
        block->renderInstrsTransp = mapBlockRelocatePointer(block, block->renderInstrsTransp);
    }
    if (block->renderInstrsWater != NULL) {
        block->renderInstrsWater = mapBlockRelocatePointer(block, block->renderInstrsWater);
    }
    block->displayLists = mapBlockRelocatePointer(block, block->displayLists);
    if (block->shaders != NULL) {
        block->shaders = mapBlockRelocatePointer(block, block->shaders);
    }

    for (i = 0; i < block->displayListCount; i++) {
        block->displayLists[i].dlist = mapBlockRelocatePointer(block, block->displayLists[i].dlist);
    }
}

void MapBlock_initHits(MapBlockData* block, int index) {
    int i;
    int* table = (int*)gHitsTab;
    int fileOff = table[index];
    int size = table[index + 1] - fileOff;
    MapHitLine* entry;
    s16 value;

    if (size > 0) {
        block->hits = mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(MLDF_FILEID_HITS_BIN, block->hits, fileOff, size);
    }
    block->hitCount = (u32)size / sizeof(MapHitLine);
    i = 0;
    while (i < block->hitCount) {
        entry = &block->hits[i];
        if (entry->x[0] < 0 || (value = entry->x[1]) < 0 || entry->x[0] > 0x280 || value > 0x280) {
            entry->kind = 0x40;
        }
        entry = &block->hits[i];
        if (entry->z[0] < 0 || (value = entry->z[1]) < 0 || entry->z[0] > 0x280 || value > 0x280) {
            entry->kind = 0x40;
        }
        i++;
    }
    block->auxData = NULL;
    block->unk9E = 0;
    block->flags4 &= ~0x40;
}

MapBlockData* MapBlock_loadFromFile(int blockId) {
    int compressedLen;
    int decompressedSize;
    void* buf;
    int blockOff = 0;
    int* table;
    int tableEntry;
    if (blockId <= gMapBlockIndexCount) {
        table = gMapBlockIndexList;
        if (table != 0) {
            tableEntry = table[blockId];
            if (tableEntry != -1) {
                if (tableEntry != 0 || table[blockId + 1] != 0) {
                    blockOff = tableEntry;
                    checkLoadBlock(tableEntry, &compressedLen, &decompressedSize);
                } else {
                    return 0;
                }
            }
        }
    } else {
        return 0;
    }
    if (compressedLen <= 0) {
        return 0;
    }
    if (decompressedSize > 0x32000) {
        return 0;
    }
    buf = mmAlloc(decompressedSize, 5, 0);
    if (buf == 0) {
        return 0;
    }
    loadAndDecompressDataFile(MLDF_FILEID_BLOCKS_BIN_A, buf, blockOff, compressedLen, 0, 0, 0);
    return buf;
}

void mapBlockGpuRecoveryHook(void) {
    int n;
    int i;

    i = 0;
    n = gMapBlockCount;
    for (; i < n; i++) {
    }
}

void* mapBlockGetUnused00Value(MapBlockData* block) {
    return NULL;
}

void mapGetBlocks(void** outLayerTables, u32* outBlocks) {
    *outLayerTables = gMapBlockLayerTables;
    *outBlocks = (u32)gMapBlocks;
}

void mapClearBlockEdgeFlags(void) {
    int i;
    int j;
    MapBlockData* block;

    for (i = 0; i < gMapBlockCount; i++) {
        block = gMapBlocks[i];
        if (block != NULL) {
            for (j = 0; j < block->displayListCount; j++) {
                block->displayLists[j].flags = 0;
            }
        }
    }
}

int collectShadowTrackTriangles(GameObject* obj, TrackTriangle* triangles, TrackShadowTriangle* planesOut,
                                Vec3f* verticesOut, int unusedTriangleCount, f32 offX, f32 offZ, int unusedRenderMode,
                                int kindSelector) {
    int j;
    f32 localMatrix[12];
    int triangleCount;
    TrackBlockDescriptor* desc = trackGetBlockDescriptors((u32*)&j);
    TrackBlockDescriptor* end = desc + j;
    int vertexCount;
    int triangleFlag;

    j = triangleCount = 0;
    vertexCount = 0;
    if (kindSelector) {
        triangleFlag = 4;
    } else {
        triangleFlag = 8;
    }
    for (; desc < end; desc++) {
        void* owner = desc->object;
        if (owner == NULL || owner == obj->anim.parent) {
            f32 fx = obj->anim.localPosX;
            f32 fz = obj->anim.localPosZ;
            TrackShadowTriangle* outputTriangle;

            if (owner == NULL) {
                fx -= offX;
                fz -= offZ;
            }
            j = desc->firstTriangle;
            outputTriangle = &planesOut[triangleCount];
            while (j < desc[1].firstTriangle && triangleCount < 0x4b0 && vertexCount < 0xe10) {
                if (triangleFlag & triangles[j].flags) {
                    verticesOut[0].x = __OSs16tof32(&triangles[j].vx[0]) - fx;
                    verticesOut[0].y = __OSs16tof32(&triangles[j].vy[0]) - obj->anim.localPosY;
                    verticesOut[0].z = __OSs16tof32(&triangles[j].vz[0]) - fz;
                    verticesOut[1].x = __OSs16tof32(&triangles[j].vx[1]) - fx;
                    verticesOut[1].y = __OSs16tof32(&triangles[j].vy[1]) - obj->anim.localPosY;
                    verticesOut[1].z = __OSs16tof32(&triangles[j].vz[1]) - fz;
                    verticesOut[2].x = __OSs16tof32(&triangles[j].vx[2]) - fx;
                    verticesOut[2].y = __OSs16tof32(&triangles[j].vy[2]) - obj->anim.localPosY;
                    verticesOut[2].z = __OSs16tof32(&triangles[j].vz[2]) - fz;
                    outputTriangle->normal.x = triangles[j].planeN[0];
                    outputTriangle->normal.y = triangles[j].planeN[1];
                    outputTriangle->normal.z = triangles[j].planeN[2];
                    outputTriangle->flags = triangles[j].flags;
                    verticesOut += 3;
                    vertexCount += 3;
                    outputTriangle++;
                    triangleCount += 1;
                }
                j++;
            }
        } else {
            f32* m = desc->currentCollisionMatrix;
            f32* firstOutputVertex;
            int firstVertex;
            TrackShadowTriangle* outputTriangle;

            localMatrix[0] = m[0];
            localMatrix[1] = m[4];
            localMatrix[2] = m[8];
            localMatrix[3] = m[12] - obj->anim.localPosX;
            localMatrix[4] = m[1];
            localMatrix[5] = m[5];
            localMatrix[6] = m[9];
            localMatrix[7] = m[13] - obj->anim.localPosY;
            localMatrix[8] = m[2];
            localMatrix[9] = m[6];
            localMatrix[10] = m[10];
            localMatrix[11] = m[14] - obj->anim.localPosZ;
            firstOutputVertex = (f32*)verticesOut;
            firstVertex = vertexCount;
            j = desc->firstTriangle;
            outputTriangle = &planesOut[triangleCount];
            while (j < desc[1].firstTriangle && triangleCount < 0x4b0 && vertexCount < 0xe10) {
                if (triangleFlag & triangles[j].flags) {
                    verticesOut[0].x = __OSs16tof32(&triangles[j].vx[0]);
                    verticesOut[0].y = __OSs16tof32(&triangles[j].vy[0]);
                    verticesOut[0].z = __OSs16tof32(&triangles[j].vz[0]);
                    verticesOut[1].x = __OSs16tof32(&triangles[j].vx[1]);
                    verticesOut[1].y = __OSs16tof32(&triangles[j].vy[1]);
                    verticesOut[1].z = __OSs16tof32(&triangles[j].vz[1]);
                    verticesOut[2].x = __OSs16tof32(&triangles[j].vx[2]);
                    verticesOut[2].y = __OSs16tof32(&triangles[j].vy[2]);
                    verticesOut[2].z = __OSs16tof32(&triangles[j].vz[2]);
                    outputTriangle->normal.x = triangles[j].planeN[0];
                    outputTriangle->normal.y = triangles[j].planeN[1];
                    outputTriangle->normal.z = triangles[j].planeN[2];
                    outputTriangle->flags = triangles[j].flags;
                    verticesOut += 3;
                    vertexCount += 3;
                    outputTriangle++;
                    triangleCount += 1;
                }
                j++;
            }
            if (firstVertex < vertexCount) {
                PSMTXMultVecArray((MtxPtr)localMatrix, (Vec*)firstOutputVertex, (Vec*)firstOutputVertex,
                                  vertexCount - firstVertex);
            }
        }
    }
    return triangleCount;
}

/* MWCC allocates this BSS group in reverse declaration order. */
WarpDestination gRcpPendingWarpDest;
FrustumPlane gViewFrustumPlanes[FRUSTUM_PLANE_COUNT];
FrustumPlane gPlayerRelativeFrustumPlanes[FRUSTUM_PLANE_COUNT];
u32 gVisibleObjectSortKeys[0x400];
WarpVec gCameraPosByTransformSpace[0x29];
MapRomListPage* gLoadedRomListPages[ROM_LIST_PAGE_COUNT];
MapRomListIndex gMapRomListIndexes[120];
s8* gMapBlockLayerTables[MAP_BLOCK_LAYER_COUNT];
MapCellEntry* gMapBlockCellEntryTables[5];
s8* gMapBlockCellStateTables[5];
ShaderRomListSlot gShaderRomListSlots[8];
int gShaderMapRomBuffers[0x5];
ModelRenderInstrsState gMapCellRenderState;
GameObject* gLightmapDeferredObjects[20];
f32 distortionFilterVector[3];
ModelLightStruct* gGlowLightList[100];
u8 gCloudLayerTexMatrix[0x30];
MapRenderQueueStorage gLightmapDrawQueue;
