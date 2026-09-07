#include "game/objects/object.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/hud_visibility_api.h"
#include "sys/objects.h"
#include "main/render_flags.h"
#include "main/shader_api.h"
#include "main/shader_map_api.h"
#include "main/sky_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/cloudaction_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/waterfx_interface.h"
#include "main/frustum.h"
#include "main/lightmap_api.h"
#include "main/lightmap_lifecycle_api.h"
#include "main/lightmap_render_queue_api.h"
#include "main/model_render_instrs_api.h"
#include "main/modellight_api.h"
#include "main/newclouds.h"
#include "main/obj_list.h"
#include "main/objprint_render_api.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/pi_dolphin.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXManage.h"
#include "main/sky_state.h"
#include "main/track_dolphin_api.h"
#include "main/mm.h"
#include "main/newshadows.h"
#include "main/newshadows_shadow_api.h"
#include "main/rcp_dolphin.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/dll_0031_minimap.h"
#include "dlls/objects/226.h"
#include "main/dll/savegame_env_api.h"
#include "main/sky.h"
#include "track/intersect_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/dll/cloudaction.h"
#include "main/trig.h"
#include "main/tex_dolphin.h"
#include "main/acosf_api.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx.h"
#include "main/lightmap.h"
#include "main/lightmap_internal.h"

u8 colorFilterColor[4] = {0xFF, 0x70, 0x40, 0};
u8 colorScale = 0xFF;

void sceneDraw(void);
void sceneDrawTransparentPolys(void);

extern f32 gLightmapDegToBamScale;

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
    fov = (int)(gLightmapDegToBamScale * scale) & 0xffff;
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

extern LightSortEntry gLightmapDrawQueue[];

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

u32 gVisibleObjectSortKeys[0x400];

int coordsToMapCell(f32 x, f32 z) {
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)gMapBlockOriginZ);
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
    ix = fastFloorf(x / gMapBlockWorldSize);
    iz = fastFloorf(z / gMapBlockWorldSize);
    s = gMapBlockWorldSize;
    *outX = s * ix;
    *outZ = s * iz;
}

#define MAP_BLOCK_LAYER_COUNT 5

int isInBounds(f32 x, f32 z) {
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)gMapBlockOriginZ);
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
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)gMapBlockOriginZ);
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
    MapRomListPage** pageCursor[1];
    int itemIndex;
    int pageIndex;
    int pageOffset;
    ObjPlacement* item;
    u16 pageDataSize;
    int itemSize;

    for (pageIndex = 0, pageCursor[0] = gLoadedRomListPages; pageIndex < ROM_LIST_PAGE_COUNT;
         pageCursor[0]++, pageIndex++) {
        page = *pageCursor[0];
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
                            gLightmapDrawQueue[gLightmapDrawQueueCount].type = 1;
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
                        gLightmapDrawQueue[gLightmapDrawQueueCount].type = 0;
                        gLightmapDrawQueueCount++;
                        if ((o->anim.modelInstance->renderFlags & 0x20) != 0 &&
                            (o->anim.flags & OBJANIM_FLAG_HIDDEN) == 0) {
                            renderShadowType3(o, 7, 0x50);
                            gLightmapDrawQueue[gLightmapDrawQueueCount].type = 1;
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
    LightSortEntry* q;
    LightmapDrawQueue* dq;

    qbase = (LightmapDrawQueue*)gLightmapDrawQueue;
    q = gLightmapDrawQueue;
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
                LightSortEntry* qe;
                int qi;
                u32 shadowKind;

                renderShadowType3(obj, 0x13, 0);
                shadowKind = 2;
                qi = gLightmapDrawQueueCount;
                qe = &q[qi];
                qe->type = shadowKind;
                gLightmapDrawQueueCount = qi + 1;
            } else if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_CRASH &&
                       (obj->anim.flags & OBJANIM_FLAG_HIDDEN) == 0 &&
                       (obj->anim.modelState->flags & OBJ_MODEL_STATE_SHADOW_VISIBLE)) {
                LightSortEntry* qe;
                int qi;
                u32 shadowKind;

                renderShadowType3(obj, 0x13, 0);
                shadowKind = 3;
                qi = gLightmapDrawQueueCount;
                qe = &q[qi];
                qe->type = shadowKind;
                gLightmapDrawQueueCount = qi + 1;
            }
        }
    }
}
static inline void fillBoxRows(u8* map, int* box) {
    int y, x0;
    int xs, xe;
    u8* p;
    for (y = box[2]; y <= box[3]; y++) {
        xs = box[0];
        p = map + (y + 7) * 0x10 + xs;
        xe = box[1];
        for (x0 = xs; x0 <= xe; x0++) {
            p[7] = 1;
            p++;
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
    worldSize = gMapBlockWorldSize;
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
                    colF = gMapBlockWorldSize * (f32)col;
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

    q = (char*)gLightmapDrawQueue;
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
    mapDebugRender((int*)(q + 0x4164));
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
    *(u32*)(((int)q + 8) + gLightmapDrawQueueCount * 16) = 0x78000000;
    *(u32*)(((int)q + 12) + gLightmapDrawQueueCount * 16) = 8;
    gLightmapDrawQueueCount += 1;
    if (gLightmapDrawQueueCount == 1000) {
        sceneDrawTransparentPolys();
        gLightmapDrawQueueCount = 0;
    }
    *(u32*)(((int)q + 8) + gLightmapDrawQueueCount * 16) = 0x50000000;
    *(u32*)(((int)q + 12) + gLightmapDrawQueueCount * 16) = 9;
    gLightmapDrawQueueCount += 1;
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
void updateEnvironment(int mode) {
    if (mode == 0) {
        MapTextureOverride* textureOverride;
        MapTextureScroll* textureScroll;
        Texture* texture;
        int i;
        int byteOffset;
        f32 offsetX;
        f32 deltaY;
        f32 deltaX;
        f32 deltaTime;

        skyUpdateEnvFx();
        (*gCloudActionInterface)->scrollTexture();
        (*gSky2Interface)->run();
        (*gSkyInterface)->updateTimeOfDay();
        (*gNewCloudsInterface)->run();

        i = 0;
        byteOffset = 0;
        for (; i < 80; i++) {
            textureOverride = (MapTextureOverride*)((u8*)gMapTextureOverrides + byteOffset);
            if (textureOverride->refCount != 0 && (texture = textureOverride->texture) != NULL &&
                texture->animationFrameCount != 0x100 && texture->animationFrameStep != 0) {
                textureUpdateAnimationFrame(texture, &textureOverride->flags, &textureOverride->frame);
            }
            byteOffset += sizeof(MapTextureOverride);
        }

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
