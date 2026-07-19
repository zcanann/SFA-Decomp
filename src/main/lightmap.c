#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/hud_visibility_api.h"
#include "main/object_api.h"
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
#include "main/lightmap_render_control_api.h"
#include "main/lightmap_render_queue_api.h"
#include "main/lightmap_text_color_api.h"
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
#include "string.h"
#include "main/newshadows.h"
#include "main/newshadows_shadow_api.h"
#include "main/rcp_dolphin.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/savegame_env_api.h"
#include "main/sky.h"
#include "track/intersect_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/dll/cloudaction_ext.h"
#include "main/track_dolphin_ext.h"
#include "main/trig_ext.h"
#include "main/tex_dolphin_ext.h"
#include "main/acosf_api.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx/mtx_legacy.h"

u8 colorFilterColor[4] = {0xFF, 0x70, 0x40, 0};
u8 colorScale = 0xFF;
extern f32 widescreenAspect_803DEC1C;
extern f32 lbl_803DB670;

void sceneDraw(void);
void sceneDrawTransparentPolys(void);

typedef struct
{
    f32 lo;
    f32 hi;
} F32Pair;

extern u32 renderFlags;
/* Global renderFlags bits (decoded by the accessor fns below: shouldDrawShadows,
 * shouldDrawClouds, getDrawDistanceFlag, isOvercast, setPendingMapLoad,
 * setStarsHidden). */
#define RENDERFLAG_WIDESCREEN      0x8
#define RENDERFLAG_DRAW_CLOUDS     0x10
#define RENDERFLAG_DRAW_SHADOWS    0x80
#define RENDERFLAG_PENDING_MAP_LOAD 0x1000
#define RENDERFLAG_DRAW_DISTANCE   0x10000
#define RENDERFLAG_OVERCAST        0x40000
#define RENDERFLAG_HIDE_STARS      0x80000

extern f32 lbl_803DEBF8;
extern f32 lbl_803DEBFC;
extern f32 lbl_803DEBCC;
extern f32 lbl_803DEBDC;
extern f32 lbl_803DEC00;
extern f32 gLightmapDegToBamScale;
extern F32Pair lbl_803DEC08;
extern f32 lbl_803DEC0C;
extern FrustumPlane gViewFrustumPlanes[];

extern void* gMapBlockLayerTables[];
extern void** gMapBlocks;
extern u8 lbl_803DCE98; /* count of allocated blocks */
extern f32 lbl_803DEC18;
extern u32 lbl_803DCE34;
extern f32 lbl_803DEC10;
extern u16 lbl_803DCEAC;
extern u8 lbl_803DCE06;
extern s32 heatEffectIntensity;
extern u8 gLightmapScreenImageEnabled;
extern s8 lbl_8030E65C[];
extern s8 lbl_8030E66C[];
extern int lbl_8038228C[];
extern s32 gMapLayerCellStates;
extern s32 gMapCurRomListSlot;
extern f32 lbl_803DCE58;
extern f32 lbl_803DCE54;
typedef struct
{
    u32 a;
    u32 b;
    u32 key;
    u32 d;
} LightSortEntry;
extern void* gMapBlockIds;
extern void* gMapBlockRefCounts;
extern void* lbl_803DCE78;
extern void* lbl_803DCE7C;
extern void* lbl_803DCE80;
extern void* lbl_803DCE84;
extern s16 lbl_803DCE90;
extern s16 lbl_803DCEBA;
extern s16 lbl_803DCEB8;
extern void* lbl_803DCE6C;
extern void* lbl_803DCE68;
extern void* gMinimapInterface;
extern void* lbl_803DCAB0;
extern s32 lbl_803DCE00;

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s8 s8;
    s16 s16;
    s32 s32;
    f32 f32;
} PPCWGPipe;

volatile PPCWGPipe GXWGFifo : (0xCC008000);

void renderShadowType3(u8* obj, u32 b, s32 offset);
static inline void GXPosition3s16(const s16 x, const s16 y, const s16 z)
{
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = z;
}
static inline void GXColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}
static inline void GXTexCoord2s16(const s16 s, const s16 t)
{
    GXWGFifo.s16 = s;
    GXWGFifo.s16 = t;
}
static inline void GXPosition1x8(const u8 x) { GXWGFifo.u8 = x; }

void updateVisibleGeometry(void)
{
    CameraViewSlot* cam;
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

    cam = Camera_GetCurrentViewSlot();
    if ((renderFlags & RENDERFLAG_WIDESCREEN) != 0 || (renderFlags & RENDERFLAG_DRAW_DISTANCE) != 0)
    {
        scale = Camera_GetFovY() / lbl_803DEBF8;
    }
    else
    {
        scale = Camera_GetFovY();
        scale *= lbl_803DEBFC;
    }
    xx = cam->worldX - playerMapOffsetX;
    yy = cam->worldY;
    zz = cam->worldZ - playerMapOffsetZ;
    st.x = lbl_803DEBCC;
    st.y = lbl_803DEBCC;
    st.z = lbl_803DEBCC;
    st.scale = lbl_803DEBDC;
    st.rotX = 0x8000 - cam->worldYaw;
    st.rotY = -cam->worldPitch;
    st.rotZ = cam->worldRoll;
    setMatrixFromObjectPos(m, &st);
    Matrix_TransformPoint(m, lbl_803DEBCC, *(f32*)&lbl_803DEBCC, lbl_803DEC00, &ox, &oy, &oz);
    gViewFrustumPlanes[0].normalX = ox;
    gViewFrustumPlanes[n = 0].normalY = oy;
    gViewFrustumPlanes[n = 0].normalZ = oz;
    dd = -(zz * oz + (xx * ox + yy * oy));
    pw = &gViewFrustumPlanes[0].distance;
    i = 0;
    pw[i * 5] = dd;
    fov = (int)(gLightmapDegToBamScale * scale) & 0xffff;
    tt = fn_80293AC4(fov);
    ratio = fn_80293D0C(fov) / tt;
    ratio2 = ratio * ratio;
    ff = lbl_803DEC08.lo;
    tt = ff * ratio2;
    tt = fn_80292248(sqrtf(ff * tt + ratio2));
    ff = mathSinfHighPrecision(tt);
    ss = mathCosfHighPrecision(tt);
    Matrix_TransformPoint(m, ss, lbl_803DEBCC, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 1].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, -ss, lbl_803DEBCC, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 2].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, lbl_803DEBCC, -ss, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 3].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, lbl_803DEBCC, ss, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 4].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    pw[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    frustumPlanes_updateAabbCornerIndices((FrustumPlane*)gViewFrustumPlanes, 5);
}

MapBlockData* mapGetBlock(int i)
{
    if (i < 0 || i >= lbl_803DCE98) return 0;
    return gMapBlocks[i];
}

extern u32 lbl_8037E0C0[];
extern s32 lbl_803DCE30;

void* mapGetBlockIdx(int layer)
{
    return gMapBlockLayerTables[layer];
}

void* mapGetBlockAtPos(int x, int y, int layer)
{
    s8* table = gMapBlockLayerTables[layer];
    s32 idx;
    if (x < 0 || y < 0 || x >= 0x10 || y >= 0x10) return 0;
    idx = table[x + (y << 4)];
    if (idx < 0 || idx >= lbl_803DCE98) return 0;
    return gMapBlocks[idx];
}

extern u8 gLoadedRomListPages[0x1e0];

void* RomList_GetLoadedPages(void)
{
    return gLoadedRomListPages;
}

u32 gVisibleObjectSortKeys[0x400];
extern int gLightmapDeferredObjectCount;
extern s16 gVisibleObjectSortKeyCount;

typedef struct
{
    u32 a, b, c, d;
} LightmapQEnt;

typedef struct
{
    u8 pad[0x4114];
    u32 deferred[20];
} LightmapDrawQueue;

extern s16* lbl_803822A0[];
extern f32 gMapBlockWorldSize;
extern int gMapBlockOriginX;
extern int gMapBlockOriginZ;

int coordsToMapCell(f32 x, f32 z)
{
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)gMapBlockOriginZ);
    if (ix < 0 || ix >= 16) return -1;
    if (iz < 0 || iz >= 16) return -1;
    return *(s16*)((char*)lbl_803822A0[0] + (ix + iz * 16) * 12);
}

void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32* outX, f32* outZ)
{
    s32 ix, iz;
    f32 s;
    ix = fastFloorf(x / gMapBlockWorldSize);
    iz = fastFloorf(z / gMapBlockWorldSize);
    s = gMapBlockWorldSize;
    *outX = s * ix;
    *outZ = s * iz;
}

#define MAP_BLOCK_LAYER_COUNT 5

int isInBounds(f32 x, f32 z)
{
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)gMapBlockOriginZ);
    int linear;
    void** p;
    if (ix < 0 || ix >= 16) return -1;
    if (iz < 0 || iz >= 16) return -1;
    linear = ix + (iz << 4);
    {
        int i;
        p = gMapBlockLayerTables;
        for (i = 0; i < MAP_BLOCK_LAYER_COUNT; i++)
        {
            if (((s8*)*p)[linear] > -1) return 1;
            p++;
        }
    }
    return 0;
}


int objPosToMapBlockIdx(f32 x, f32 y, f32 z)
{
    s8** tp;
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)gMapBlockOriginX);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)gMapBlockOriginZ);
    int i;
    if (ix < 0 || ix >= 16) return -1;
    if (iz < 0 || iz >= 16) return -1;
    ix = ix + (iz << 4);
    for (tp = (s8**)gMapBlockLayerTables, i = 0; i < MAP_BLOCK_LAYER_COUNT; tp++, i++)
    {
        s8* table = *tp;
        int idx = table[ix];
        if (idx > -1)
        {
            int* block = gMapBlocks[idx];
            if (y > (f32)(*(s16*)((char*)block + 138) - 50) &&
                y < (f32)(*(s16*)((char*)block + 140) + 50))
            {
                return table[ix];
            }
        }
    }
    return -1;
}

extern void* lbl_803DCEA0;

int* mapRomListFindItem(int needle, int* out_idx, int* out_outer, int* out_type, int* out_lastpage)
{
    int** pp;
    int inner_idx;
    int outer;
    int* page;
    int total_offset;
    int* p;
    u16 limit;
    int sz;

    for (outer = 0, pp = (int**)gLoadedRomListPages; outer < 0x78; pp++, outer++)
    {
        page = *pp;
        if (page == NULL) continue;

        lbl_803DCEA0 = page;
        p = (int*)*(int*)((char*)page + 0x20);
        inner_idx = 0;
        total_offset = 0;
        limit = *(u16*)((char*)page + 0x8);

        while (total_offset < limit)
        {
            if (*(u32*)((char*)p + 0x14) == (u32)needle)
            {
                if (out_idx != NULL) *out_idx = inner_idx;
                if (out_outer != NULL) *out_outer = outer;
                if (out_type != NULL)
                {
                    *out_type = (int)*(s8*)((char*)lbl_803DCEA0 + 0x19);
                }
                if (out_lastpage != NULL)
                {
                    *out_lastpage = (outer >= 0x50) ? 1 : 0;
                }
                return p;
            }
            sz = (int)*(u8*)((char*)p + 0x2) << 2;
            total_offset += sz;
            p = (int*)((char*)p + sz);
            inner_idx++;
        }
    }
    return NULL;
}

void sortVisibleObjectKeysDescending(u32* arr, int n);
void getVisibleObjects(s8* opacity)
{
    int part;
    int* objects;
    int* p;
    u8* o;
    int i;
    u32 key;
    int depthInt;
    s8* cur;
    u8* sub;
    u8* att;
    int j;
    u8* interactState;
    int* model;
    ObjModelInstance* modelDef;
    u32 tf;
    u32 mode;
    s16 t;
    int sortDepth;
    int count;
    f32 a, b;
    f32 depth;

    maybeHudFn_8006c91c();
    objects = ObjList_GetObjects((int*)0, 0);
    part = ObjList_PartitionForRender(&count);
    i = 0;
    p = objects;
    cur = opacity;
    for (; i < count; i++, cur++)
    {
        o = (u8*)*p;

        ((GameObject*)o)->objectFlags &= ~OBJECT_OBJFLAG_RENDERED;
        j = 0;
        sub = o;
        for (; j < ((GameObject*)o)->childCount; j++)
        {
            att = *(u8**)(sub + 0xc8);
            if (att != NULL)
            {
                ((GameObject*)att)->objectFlags &= ~OBJECT_OBJFLAG_RENDERED;
            }
            sub += 4;
        }
        if (i >= part)
        {
            *cur = objUpdateOpacity((GameObject*)o);
            if (*cur != 0 || (((ObjAnimComponent*)o)->modelInstance->flags & 0x200000) != 0)
            {
                if ((((ObjAnimComponent*)o)->modelInstance->flags & 0x80000) != 0)
                {
                    *(f32*)&((GameObject*)o)->anim.targetObj =
                        (f32)(((GameObject*)o)->anim.modelInstance->fixedSortDepth * 100);
                    depthInt = (int)*(f32*)&((GameObject*)o)->anim.targetObj;
                }
                else
                {
                    if (((GameObject*)o)->anim.parent != NULL)
                    {
                        Camera_ProjectWorldPoint(((GameObject*)o)->anim.worldPosX, ((GameObject*)o)->anim.worldPosY,
                                                 ((GameObject*)o)->anim.worldPosZ, &a, &b, &depth,
                                                 (f32*)(o + 0xa4));
                    }
                    else
                    {
                        Camera_ProjectWorldPoint(((GameObject*)o)->anim.localPosX - playerMapOffsetX,
                                                 ((GameObject*)o)->anim.localPosY,
                                                 ((GameObject*)o)->anim.localPosZ - playerMapOffsetZ, &a, &b,
                                                 &depth, (f32*)(o + 0xa4));
                    }
                    depthInt = (int)(lbl_803DEC0C * (lbl_803DEBDC + depth));
                }
                if ((((GameObject*)o)->anim.flags & OBJANIM_FLAG_HIDDEN) == 0 &&
                    ((GameObject*)o)->anim.modelState != NULL &&
                    (((GameObject*)o)->anim.modelState->flags & OBJ_MODEL_STATE_SHADOW_VISIBLE) != 0)
                {
                    t = ((ObjAnimComponent*)o)->modelInstance->shadowType;
                    if (t == 2 || t == 1)
                    {
                        shadowCreate((int*)o);
                    }
                    else if (t == 4)
                    {
                        shadowRenderFn_8006b558((int*)o);
                    }
                }
                if (gVisibleObjectSortKeyCount < 1000)
                {
                    key = 0;
                    model = (int*)Obj_GetActiveModel((GameObject*)o);
                    if (*(u8*)(o + 0x37) == 0xff && (((GameObject*)o)->anim.flags & 0x80) == 0 &&
                        ((tf = ((ObjAnimComponent*)o)->modelInstance->flags) & 0x40000) == 0 &&
                        *(void**)(model + 0x16) == NULL)
                    {
                        key |= 0x80000000;
                        sortDepth = 1000 - (depthInt & 0xffff);
                        if ((tf & 0x800000) != 0 && (((GameObject*)o)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE) == 0)
                        {
                            key |= 0x40000000LL;
                            key |= (((GameObject*)o)->anim.seqId & 0x3ff) << 20;
                        }
                        gVisibleObjectSortKeys[gVisibleObjectSortKeyCount] =
                            (i & 0x3ff) | (((sortDepth & 0x3ff) << 10) | key);
                        gVisibleObjectSortKeyCount++;
                        if ((((ObjAnimComponent*)o)->modelInstance->renderFlags & 0x20) != 0 &&
                            (((GameObject*)o)->objectFlags & 0x400) == 0 &&
                            (((GameObject*)o)->anim.flags & OBJANIM_FLAG_HIDDEN) == 0)
                        {
                            renderShadowType3(o, 7, 0x50);
                            lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 1;
                            lbl_803DCE30++;
                        }
                    }
                    else
                    {
                        if ((((ObjAnimComponent*)o)->modelInstance->flags & OBJDEF_FLAG_DEFERRED_RENDER) != 0 ||
                            (((ObjAnimComponent*)o)->modelInstance->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER) != 0)
                        {
                            mode = 0x1f;
                        }
                        else
                        {
                            mode = 7;
                        }
                        renderShadowType3(o, mode, 0);
                        lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 0;
                        lbl_803DCE30++;
                        if ((((ObjAnimComponent*)o)->modelInstance->renderFlags & 0x20) != 0 &&
                            (((GameObject*)o)->anim.flags & OBJANIM_FLAG_HIDDEN) == 0)
                        {
                            renderShadowType3(o, 7, 0x50);
                            lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 1;
                            lbl_803DCE30++;
                        }
                    }
                }
            }
            else
            {
                interactState = (void*)((GameObject*)o)->anim.hitReactState;
                if (interactState != NULL && (interactState[0x62] & 0x30) != 0)
                {
                    interactState[0xaf] = 2;
                }
            }
        }
        p++;
    }
    if (gVisibleObjectSortKeyCount > 1)
    {
        sortVisibleObjectKeysDescending(gVisibleObjectSortKeys, gVisibleObjectSortKeyCount);
    }
    renderShadows(0, 0, 0);
}

void sortVisibleObjectKeysDescending(u32* arr, int n)
{
    int i, j;
    int gap = 1;
    u32 tmp;
    while (gap <= n / 9)
        gap = gap * 3 + 1;
    while (gap > 0)
    {
        for (i = gap + 1; i <= n; i++)
        {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1] < tmp)
            {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}

void renderObjects(s8* opacity)
{
    u32* kp;
    int i;
    u32 flags;
    int idx;
    u8* obj;
    u8* state;
    int* p;
    int slot;
    int* objects;
    LightmapDrawQueue* qbase;
    LightmapQEnt* q;

    qbase = (LightmapDrawQueue*)lbl_8037E0C0;
    q = (LightmapQEnt*)lbl_8037E0C0;
    objects = ObjList_GetObjects((int*)0, 0);
    for (i = 1, kp = (u32*)((u8*)qbase + 0x8818) + 1; i < gVisibleObjectSortKeyCount; kp++, i++)
    {
        idx = *kp & 0x3ff;
        obj = (u8*)objects[idx];
        flags = ((GameObject*)obj)->anim.modelInstance->flags;
        if ((flags & OBJDEF_FLAG_DEFERRED_RENDER) != 0 || ((((GameObject*)obj)->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER) != 0))
        {
            if (opacity[idx] != 0 && gLightmapDeferredObjectCount < 0x14)
            {
                slot = gLightmapDeferredObjectCount;
                gLightmapDeferredObjectCount = slot + 1;
                *(u32*)((u8*)qbase->deferred + slot * 4) = (u32)obj;
            }
        }
        else
        {
            if ((flags & 0x800000) == 0)
            {
                (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, obj);
            }
            objRender(0, 0, 0, 0, (GameObject*)obj, 1);
            p = (int*)((GameObject*)obj)->anim.modelState;
            if (p != NULL && ((GameObject*)obj)->anim.modelState->shadowCastSlot != NULL)
            {
                renderShadowType3(obj, 0x13, 0);
                *(u32*)((u8*)&q->d + lbl_803DCE30 * 16) = 2;
                lbl_803DCE30++;
            }
            else if (((GameObject*)obj)->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_CRASH && (((GameObject*)obj)->anim.flags
                & OBJANIM_FLAG_HIDDEN) == 0 && (((GameObject*)obj)->anim.modelState->flags &
                OBJ_MODEL_STATE_SHADOW_VISIBLE))
            {
                renderShadowType3(obj, 0x13, 0);
                *(u32*)((u8*)&q->d + lbl_803DCE30 * 16) = 3;
                lbl_803DCE30++;
            }
        }
    }
}
static void fillBoxRows(u8* map, int* box)
{
    int y, x0;
    int xs, xe;
    u8* p;
    for (y = box[2]; y <= box[3]; y++)
    {
        xs = box[0];
        p = map + (y + 7) * 0x10 + xs;
        xe = box[1];
        for (x0 = xs; x0 <= xe; x0++)
        {
            p[7] = 1;
            p++;
        }
    }
}

void renderSceneGeometry(u8 renderType, s8* order)
{
    u8 map[256];
    int box0[4];
    int box1[4];
    int box2[4];
    int box3[4];
    void** layerTablePtr;
    int* layerFlagPtr;
    int idx;
    int k[1];
    int row, col;
    int oi, ii;
    int layer;
    u8* blk;
    s8* table;
    f32 worldSize;
    f32 rowF, colF;
    int cell;
    u8* p;

    layer = 4;
    layerTablePtr = &gMapBlockLayerTables[4];
    layerFlagPtr = &lbl_8038228C[4];
    worldSize = gMapBlockWorldSize;
    do
    {
        table = (s8*)*layerTablePtr;
        gMapLayerCellStates = *layerFlagPtr;
        mapFn_80057d24(gMapBlockOriginX + 7, gMapBlockOriginZ + 7, box0, box1, box2, box3, layer, 1,
                       gMapCurRomListSlot);
        p = map;
        for (k[0] = 0; k[0] < 256; k[0]++)
        {
            *p = 0;
            p++;
        }
        fillBoxRows(map, box0);
        fillBoxRows(map, box1);
        fillBoxRows(map, box2);
        fillBoxRows(map, box3);
        for (oi = 0; oi < 16; oi++)
        {
            row = order[oi];
            ii = 0;
            rowF = worldSize * (f32)row;
            for (; ii < 16; ii++)
            {
                col = order[ii];
                cell = row + col * 0x10;
                idx = table[cell];
                if (idx < 0)
                {
                    blk = NULL;
                }
                else
                {
                    blk = gMapBlocks[idx];
                    ((MapBlockData*)blk)->flags4 ^= 1;
                    if (map[cell] == 0)
                    {
                        continue;
                    }
                }
                if (idx > -1 && mapRectFn_8005a728(row, col, blk) != 0)
                {
                    lbl_803DCE58 = rowF;
                    colF = gMapBlockWorldSize * (f32)col;
                    lbl_803DCE54 = colF;
                    PSMTXTrans((f32*)(blk + 0xc), rowF, (f32)(int)((MapBlockData*)blk)->collisionYOffset, colF);
                    renderMapBlock((int*)blk, renderType);
                }
            }
        }
        layerTablePtr--;
        layerFlagPtr--;
        layer--;
    }
    while (layer >= 0);
}
extern u8 bEnableMotionBlur;
extern f32 lbl_803DB62C;

extern u8 bEnableBlurFilter;
extern f32 lbl_803DCE50;
extern f32 lbl_803DCE4C;
extern f32 blurFilterArea;
extern u8 bBlurFilterUseArea;
extern u8 bBiggerBlurFilter;
extern u8 bEnableDistortionFilter;
extern f32 distortionFilterAngle1;
extern f32 distortionFilterAngle2;
extern u8 distortionFilterColor[3];
extern u8 bEnableMonochromeFilter;
extern u8 bEnableSpiritVision;
extern u8 bEnableViewFinderHud;
extern f32 lbl_803DEC14;
extern s32 bEnableColorFilter;

void sceneDraw(void)
{
    char* q;
    int i;
    u8* cursor;
    GameObject* player;
    u8 flag;
    int t;
    GXColor c;
    f32 skyA;
    f32 skyB;
    s8 buf[616];

    q = (char*)lbl_8037E0C0;
    lbl_803DCE34 = (u32)cloudGetLayerTextureSize(&skyA, &skyB);
    if (lbl_803DCE34 != 0)
    {
        *(f32*)(q + 0x3f48) = lbl_803DEC10;
        *(f32*)(q + 0x3f4c) = lbl_803DEBCC;
        *(f32*)(q + 0x3f50) = lbl_803DEBCC;
        *(f32*)(q + 0x3f54) = lbl_803DEC10 * playerMapOffsetX + skyA;
        *(f32*)(q + 0x3f58) = lbl_803DEBCC;
        *(f32*)(q + 0x3f5c) = lbl_803DEBCC;
        *(f32*)(q + 0x3f60) = lbl_803DEC10;
        *(f32*)(q + 0x3f64) = lbl_803DEC10 * playerMapOffsetZ + skyB;
        *(f32*)(q + 0x3f68) = lbl_803DEBCC;
        *(f32*)(q + 0x3f6c) = lbl_803DEBCC;
        *(f32*)(q + 0x3f70) = lbl_803DEBCC;
        *(f32*)(q + 0x3f74) = lbl_803DEBDC;
        PSMTXConcat((f32*)(q + 0x3f48), (f32*)Camera_GetInverseViewMatrix(),
                    (f32*)(q + 0x3f48));
    }
    mapDebugRender((int*)(q + 0x4164));
    fn_80062894();
    fn_80062808();
    gVisibleObjectSortKeyCount = 1;
    lbl_803DCEAC = 0;
    lbl_803DCE06 = 0;
    drawReflectionTexture();
    lbl_803DCE30 = 0;
    getVisibleObjects(buf);
    gxTextureFn_80052efc();
    perspectiveFn_80129db4();
    GXPixModeSync();
    Camera_UpdateProjection(NULL, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    t = 0;
    if ((renderFlags & 0x40) != 0 && (renderFlags & RENDERFLAG_HIDE_STARS) == 0)
    {
        t = 1;
    }
    flag = t;
    if ((renderFlags & RENDERFLAG_OVERCAST) != 0)
    {
        (*gSkyInterface)->renderTimeOfDayBackdrop(0, 0);
        if (flag != 0)
        {
            drawSkyStars();
        }
        (*gSkyInterface)->render(0, 0, 0, 0, flag);
        if ((renderFlags & RENDERFLAG_DRAW_CLOUDS) != 0)
        {
            (*gCloudActionInterface)->renderClouds(0, 0, 0, 0);
        }
    }
    else
    {
        (*gSkyInterface)->render(0, 0, 0, 0, flag);
        (*gCloudActionInterface)->renderClouds(0, 0, 0, 0);
        drawSkyStars();
    }
    if (gLightmapScreenImageEnabled != 0)
    {
        screenImageDraw(gLightmapScreenImageEnabled);
    }
    lightningRenderActive();
    (*gSky2Interface)->applyFogColor(0);
    gLightmapDeferredObjectCount = 0;
    getAmbientColor(0, (u8*)&c, (u8*)&c + 1, (u8*)&c + 2);
    GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(GX_COLOR0, c);
    GXSetNumChans(1);
    renderSceneGeometry(0, lbl_8030E65C);
    renderResetFn_8003fc60();
    renderObjects(buf);
    if (CameraShake_IsActive() != 0 || (int)bEnableMotionBlur != 0)
    {
        renderMotionBlur(lbl_803DB62C);
    }
    if (getHudHiddenFrameCount() == 0)
    {
        updateReflectionTextures();
    }
    if (bEnableBlurFilter != 0)
    {
        doBlurFilter(lbl_803DCE50, lbl_803DCE4C, blurFilterArea, bBlurFilterUseArea,
                     bBiggerBlurFilter);
    }
    if (heatEffectIntensity != 0)
    {
        doHeatEffect(heatEffectIntensity & 0xff);
    }
    i = 0;
    cursor = (u8*)(q + 0x4114);
    for (; i < gLightmapDeferredObjectCount; i++)
    {
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, (void*)*(u32*)cursor);
        objRender(0, 0, 0, 0, (GameObject*)*(u32*)cursor, 1);
        cursor += 4;
    }
    renderParticles();
    renderSceneGeometry(1, lbl_8030E66C);
    renderSceneGeometry(2, lbl_8030E66C);
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    *(u32*)(((int)q + 8) + lbl_803DCE30 * 16) = 0x78000000;
    *(u32*)(((int)q + 12) + lbl_803DCE30 * 16) = 8;
    lbl_803DCE30 = lbl_803DCE30 + 1;
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    *(u32*)(((int)q + 8) + lbl_803DCE30 * 16) = 0x50000000;
    *(u32*)(((int)q + 12) + lbl_803DCE30 * 16) = 9;
    lbl_803DCE30 = lbl_803DCE30 + 1;
    sceneDrawTransparentPolys();
    (*gModgfxInterface)->markSourceFrameUpdated(buf);
    (*gModgfxInterface)->renderEffects(NULL, 0, 0, 0, NULL);
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        i = 0;
        cursor = (u8*)player;
        for (; i < ((GameObject*)player)->childCount; i++)
        {
            u8* m = *(u8**)(cursor + 200);
            if (*(s16*)(m + 0x44) == 45)
            {
                (*(void (***)(void))*(int*)(m + 0x68))[11]();
            }
            cursor += 4;
        }
    }
    quakeSpellTextureFn_8016dbf4();
    (*gNewCloudsInterface)->renderSnowClouds(0);
    if (bEnableDistortionFilter != 0)
    {
        updateReflectionTextures();
        doDistortionFilter((f32*)(q + 0x4108), distortionFilterAngle2,
                           distortionFilterColor, distortionFilterAngle1);
    }
    renderGlows();
    (*gCameraInterface)->minimapShowHelpTextForTarget(0, 0, 0, 0);
    if (bEnableMonochromeFilter != 0)
    {
        doColorFilter(colorFilterColor);
    }
    else if (bEnableSpiritVision != 0)
    {
        doSpiritVisionFilter();
    }
    if (bEnableViewFinderHud != 0)
    {
        drawViewFinderAperture(lbl_803DEC14, lbl_803DEC18, 0x40, 0);
    }
    if (bEnableColorFilter == 1)
    {
        doColorFilter(colorFilterColor);
    }
    setShadowFlag_803db658(0);
}

extern s8 curMapType;
extern int lbl_803DCEA8;

void sceneRender(int wpad0, int wpad1, int wpad2, int wpad3, int wpad4, int wpad5)
{
    renderFlags |= 0x21;
    if (curMapType == MAPTYPE_SUBMAP || curMapType == MAPTYPE_SUBMAP_UNUSED)
    {
        renderFlags &= ~1LL;
    }
    Camera_UpdateProjection(NULL, 0);
    updateVisibleGeometry();
    playerVecFn_8005a9b0();
    Camera_EnableViewYOffset();
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    updateLights();
    lbl_803DCEA8 = (int)Camera_GetCurrentViewSlot();
    sceneDraw();
    screenFn_8000e944(NULL);
    renderFlags &= ~2LL;
}

void doNothing_beforeTitleScreen(void)
{
}
void updateEnvironment(int mode)
{
    if (mode == 0)
    {
        char* entry;
        Texture* tex;
        int z[2];
        int w[2];
        f32 deltaY;
        f32 deltaX;
        f32 x;

        envFxFn_80088884();
        (*gCloudActionInterface)->scrollTexture();
        (*gSky2Interface)->run();
        (*gSkyInterface)->updateTimeOfDay();
        (*gNewCloudsInterface)->run();

        z[0] = 0;
        z[1] = z[0];
        do
        {
            entry = (char*)lbl_803DCE6C + z[1];
            if (*(s16*)(entry + 12) != 0 && (tex = *(void**)entry) != NULL &&
                tex->animationFrameCount != 0x100 && tex->animationFrameStep != 0)
            {
                textureAnimFn_80053f2c(tex, (u32*)(entry + 8), (s32*)(entry + 4));
            }
            z[1] += 0x10;
            z[0]++;
        }
        while (z[0] < 80);

        w[0] = 0;
        w[1] = w[0];
        for (; w[0] < 58; w[0]++)
        {
            entry = (char*)lbl_803DCE68 + w[1];
            if (*(u8*)(entry + 12) != 0)
            {
                deltaY = (f32) * (s16*)(entry + 10) * timeDelta;
                x = *(f32*)entry;
                deltaX = (f32) * (s16*)(entry + 8) * timeDelta;
                *(f32*)entry = x + deltaX;
                *(f32*)(entry + 4) = *(f32*)(entry + 4) + deltaY;
            }
            w[1] += 0x10;
        }

        loadNextMap();
        if (lbl_803DCAB0 != NULL)
        {
            (*(void (***)(void))lbl_803DCAB0)[2]();
        }
        (*(void (***)(void))gMinimapInterface)[1]();

        if (lbl_803DCE00 != 0)
        {
            heatEffectIntensity += lbl_803DCE00;
            if (heatEffectIntensity < 0)
            {
                heatEffectIntensity = 0;
                lbl_803DCE00 = 0;
            }
            else if (heatEffectIntensity > 255)
            {
                heatEffectIntensity = 255;
                lbl_803DCE00 = 0;
            }
        }
    }
}
void initMapBlocks(void)
{
    u8* mb = (u8*)lbl_8037E0C0;
    u32 zero;
    u32* q;
    u16* p;
    void* tmp;
    int i;

    renderFlags = 0;
    gMapBlocks = mmAlloc(0x100, 5, 0);
    gMapBlockIds = mmAlloc(0x80, 5, 0);
    gMapBlockRefCounts = mmAlloc(0x40, 5, 0);
    lbl_803DCE78 = mmAlloc(0xd48, 5, 0);
    *(u32*)(mb + 0x41f4) = (u32)mmAlloc(0x500, 5, 0);
    *(u32*)(mb + 0x41e0) = (u32)mmAlloc(0x3c00, 5, 0);
    *(u32*)(mb + 0x41cc) = (u32)mmAlloc(0x500, 5, 0);

    *(u32*)(mb + 0x41f8) = *(u32*)(mb + 0x41f4) + 0x100;
    *(u32*)(mb + 0x41e4) = *(u32*)(mb + 0x41e0) + 0xc00;
    *(u32*)(mb + 0x41d0) = *(u32*)(mb + 0x41cc) + 0x100;
    *(u32*)(mb + 0x41fc) = *(u32*)(mb + 0x41f8) + 0x100;
    *(u32*)(mb + 0x41e8) = *(u32*)(mb + 0x41e4) + 0xc00;
    *(u32*)(mb + 0x41d4) = *(u32*)(mb + 0x41d0) + 0x100;
    *(u32*)(mb + 0x4200) = *(u32*)(mb + 0x41fc) + 0x100;
    *(u32*)(mb + 0x41ec) = *(u32*)(mb + 0x41e8) + 0xc00;
    *(u32*)(mb + 0x41d8) = *(u32*)(mb + 0x41d4) + 0x100;
    *(u32*)(mb + 0x4204) = *(u32*)(mb + 0x4200) + 0x100;
    *(u32*)(mb + 0x41f0) = *(u32*)(mb + 0x41ec) + 0xc00;
    *(u32*)(mb + 0x41dc) = *(u32*)(mb + 0x41d8) + 0x100;

    loadAssetFileById(&lbl_803DCE7C, MLDF_FILEID_MAPS_TAB);
    loadAssetFileById(&lbl_803DCE80, MLDF_FILEID_HITS_TAB);

    q = (u32*)((u8*)(mb + 0x10000) - 0x7c58);
    zero = 0;
    for (i = 0; i < 3; i++)
    {
        q[0] = zero;
        q[1] = zero;
        q[2] = zero;
        q[3] = zero;
        q[4] = zero;
        q[5] = zero;
        q[6] = zero;
        q[7] = zero;
        q[8] = zero;
        q[9] = zero;
        q[10] = zero;
        q[11] = zero;
        q[12] = zero;
        q[13] = zero;
        q[14] = zero;
        q[15] = zero;
        q[16] = zero;
        q[17] = zero;
        q[18] = zero;
        q[19] = zero;
        q[20] = zero;
        q[21] = zero;
        q[22] = zero;
        q[23] = zero;
        q[24] = zero;
        q[25] = zero;
        q[26] = zero;
        q[27] = zero;
        q[28] = zero;
        q[29] = zero;
        q[30] = zero;
        q[31] = zero;
        q[32] = zero;
        q[33] = zero;
        q[34] = zero;
        q[35] = zero;
        q[36] = zero;
        q[37] = zero;
        q[38] = zero;
        q[39] = zero;
        q += 40;
    }

    loadAssetFileById(&lbl_803DCE84, MLDF_FILEID_TRKBLK_TAB);

    lbl_803DCE90 = 0;
    p = lbl_803DCE84;
    while (*p != 0xffff)
    {
        p++;
        lbl_803DCE90++;
    }
    lbl_803DCE90--;
    lbl_803DCEBA = -1;
    lbl_803DCEB8 = -2;

    tmp = mmAlloc(0x500, 5, 0);
    lbl_803DCE6C = tmp;
    memset(tmp, 0, 0x500);

    tmp = mmAlloc(0x3a0, 5, 0);
    lbl_803DCE68 = tmp;
    memset(tmp, 0, 0x3a0);

    memset(mb + 0x8818, 0, 0xfa0);
    *(u32*)(mb + 0x8818) = -1;
}

void gameFlagFn_8005cd24(int v)
{
    renderFlags = (v != 0) ? (renderFlags | 0x20000) : (renderFlags & ~0x20000);
}

int getDrawDistanceFlag_8005cd48(void) { return renderFlags & RENDERFLAG_DRAW_DISTANCE; }

extern f32 widescreenAspect_803DEC1C;
extern f32 lbl_803DB670;

int setWidescreen(u8 v)
{
    if (v != 0)
    {
        renderFlags |= RENDERFLAG_WIDESCREEN;
        Camera_SetAspectRatio(widescreenAspect_803DEC1C);
    }
    else
    {
        renderFlags &= ~(u64)RENDERFLAG_WIDESCREEN;
        Camera_SetAspectRatio(lbl_803DB670);
    }
    return 0;
}
int isWidescreen(void) { return renderFlags & RENDERFLAG_WIDESCREEN; }
u32 shouldDrawShadows(void) { return renderFlags & RENDERFLAG_DRAW_SHADOWS; }
int shouldDrawClouds(void) { return renderFlags & RENDERFLAG_DRAW_CLOUDS; }

void titleScreenFn_8005cdd4(int v)
{
    if (v != 0) renderFlags &= ~0x2000;
    else renderFlags |= 0x2000;
}

void setDrawLights(int v)
{
    void* env = saveGameGetEnvState();
    if (v != 0)
    {
        renderFlags |= 0x40;
        *(u8*)((char*)env + 0x40) |= 0x8;
    }
    else
    {
        renderFlags &= ~0x40LL;
        *(u8*)((char*)env + 0x40) &= ~0x8;
    }
}

void gameFlagFn_8005ce6c(int v)
{
    renderFlags = (v != 0) ? (renderFlags | 0x20) : (renderFlags & ~0x20);
}

u8 isOvercast(void)
{
    u32 v = renderFlags & RENDERFLAG_OVERCAST;
    u32 t = ((u32) - (s32)v | v) >> 31;
    return t;
}

void setIsOvercast(int v)
{
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_OVERCAST) : (renderFlags & ~RENDERFLAG_OVERCAST);
}

void setStarsHidden(int v)
{
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_HIDE_STARS) : (renderFlags & ~RENDERFLAG_HIDE_STARS);
}

void setDrawCloudsAndLights(int v)
{
    void* env = saveGameGetEnvState();
    if (v != 0)
    {
        renderFlags |= 0x50;
        *(u8*)((char*)env + 0x40) |= 0x9;
    }
    else
    {
        renderFlags &= ~0x50;
        *(u8*)((char*)env + 0x40) &= ~0x9;
    }
}

void setPendingMapLoad(int v)
{
    renderFlags = (v != 0) ? (renderFlags | RENDERFLAG_PENDING_MAP_LOAD) : (renderFlags & ~RENDERFLAG_PENDING_MAP_LOAD);
}
typedef struct LightmapVertex
{
    s16 x;
    s16 y;
    s16 z;
    s16 pad;
    s16 s;
    s16 t;
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} LightmapVertex;

void drawFn_8005cf8c(const void* vertexBase, u8* triList, int triCount)
{
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
    for (tri = 0; tri < triCount; tri++)
    {
        u8* list = triList;
        for (vtx = 0; vtx < 3; vtx++)
        {
            GXPosition1x8(0);
            vertex = &vertices[list[vtx + 1]];
            GXPosition3s16(vertex->x, vertex->y, vertex->z);
            vertex = &vertices[list[vtx + 1]];
            GXColor4u8(vertex->r, vertex->g, vertex->b, vertex->a);
            vertex = &vertices[list[vtx + 1]];
            GXTexCoord2s16(vertex->s, vertex->t);
        }
        triList = triList + 0x10;
    }
}


void fn_8005D0BC(int unused, u8 a, u8 b, u8 c, int wpad0)
{
    fn_800704FC(a, b, c);
}


void _textSetColor(void* context, int red, int green, int blue, int alpha)
{
    _gxSetTevColor1(red, green, blue, alpha);
}

void setTextColor(void* context, int a, int b, int c, int d)
{
    _gxSetTevColor2(a, b, c, d);
}

void doNothing_8005D148(int arg0, int arg1)
{
}


void objDrawFn_8005da48(GameObject* obj);
void modelRenderFn_8005d4ec(int* p1, int* obj, float* p3);
void modelRenderFn_8005d69c(int* p1, int* obj, float* p3);
void modelRenderFn_8005d894(int* p1, int* obj, float* p3);
void lightmap_sortTransparentDrawQueue(void);

void getVisibleObjects(s8 * opacity);


void renderSceneGeometry(u8 renderType, s8* order);

void doNothing_8005D14C(int arg0, int arg1)
{
}
void renderShadowType3(u8* obj, u32 b, s32 offset)
{
    f32 stk[3];
    s32 t, v;
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        stk[0] = ((GameObject*)obj)->anim.worldPosX;
        stk[1] = ((GameObject*)obj)->anim.worldPosY;
        stk[2] = ((GameObject*)obj)->anim.worldPosZ;
    }
    else
    {
        stk[0] = ((GameObject*)obj)->anim.worldPosX - playerMapOffsetX;
        stk[1] = ((GameObject*)obj)->anim.worldPosY;
        stk[2] = ((GameObject*)obj)->anim.worldPosZ - playerMapOffsetZ;
    }
    PSMTXMultVec((f32*)Camera_GetViewMatrix(), stk, stk);
    t = (s32) - stk[2] + offset;
    v = t < 0 ? 0 : (t > 0x7ffffff ? 0x7ffffff : t);
    lbl_8037E0C0[lbl_803DCE30 * 4] = (u32)obj;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = v | ((b & 0xff) << 27);
}


typedef union
{
    double d;

    struct
    {
        u32 hi;
        u32 lo;
    } u;
} F64Cvt;




extern f32 lbl_803DEC20;

asm void fn_8005D3B4(u8* obj, u8* model, s32 b)
{
    nofralloc
    stwu r1, -48(r1)
    mflr r0
    stw r0, 52(r1)
    stw r31, 44(r1)
    stw r30, 40(r1)
    stw r29, 36(r1)
    mr r29, r3
    mr r30, r4
    mr r31, r5
    lwz r0, lbl_803DCE30
    cmpwi r0, 1000
    bne _psq
    bl sceneDrawTransparentPolys
    li r0, 0
    stw r0, lbl_803DCE30
_psq:
    psq_l f0, 12(r29), 1, 5
    psq_l f1, 6(r29), 1, 5
    psq_l f2, 14(r29), 1, 5
    lfs f3, lbl_803DEC20
    lfs f6, 40(r30)
    fmadds f9, f2, f3, f6
    psq_l f4, 8(r29), 1, 5
    psq_l f2, 16(r29), 1, 5
    lfs f7, 56(r30)
    fmadds f10, f2, f3, f7
    psq_l f5, 10(r29), 1, 5
    lfs f2, lbl_803DEBFC
    lfs f8, 24(r30)
    fmadds f1, f1, f3, f8
    fmadds f0, f0, f3, f8
    fadds f0, f1, f0
    fmuls f0, f2, f0
    stfs f0, 8(r1)
    fmadds f0, f4, f3, f6
    fadds f0, f0, f9
    fmuls f0, f2, f0
    stfs f0, 12(r1)
    fmadds f0, f5, f3, f7
    fadds f0, f0, f10
    fmuls f0, f2, f0
    stfs f0, 16(r1)
    bl Camera_GetViewMatrix
    addi r4, r1, 8
    mr r5, r4
    bl PSMTXMultVec
    lfs f0, 16(r1)
    fneg f0, f0
    fctiwz f0, f0
    stfd f0, 24(r1)
    lwz r0, 28(r1)
    cmpwi r0, 0
    bge _pos
    li r4, 0
    b _store
_pos:
    lis r3, 2048
    addi r4, r3, -1
    cmpw r0, r4
    ble _clamp
    b _store
_clamp:
    mr r4, r0
_store:
    lwz r0, lbl_803DCE30
    slwi r0, r0, 4
    lis r3, lbl_8037E0C0@ha
    addi r3, r3, lbl_8037E0C0@l
    stwx r29, r3, r0
    add r3, r3, r0
    stw r30, 4(r3)
    clrlwi r0, r31, 24
    slwi r0, r0, 27
    or r0, r4, r0
    stw r0, 8(r3)
    lwz r31, 44(r1)
    lwz r30, 40(r1)
    lwz r29, 36(r1)
    lwz r0, 52(r1)
    mtlr r0
    addi r1, r1, 48
    blr
}


void sortVisibleObjectKeysDescending(u32* arr, int n);


void sceneDrawTransparentPolys(void)
{
    int (*e)[4];
    int i;
    int* block;
    GameObject* player;
    GXColor c4;
    GXColor c5;
    GXColor c6;
    f32 m[16];

    lightmap_sortTransparentDrawQueue();
    i = 0;
    e = (int(*)[4])&lbl_8037E0C0;
    for (; i < lbl_803DCE30; i++)
    {
        switch (e[i][3])
        {
        case 0:
            expgfx_renderSourcePools(e[i][0], 0);
            objDrawFn_8005da48((GameObject*)e[i][0]);
            expgfx_renderSourcePools(e[i][0], 1);
            break;
        case 1:
            block = (int*)e[i][0];
            Obj_GetActiveModel((GameObject*)block);
            player = Obj_GetPlayerObject();
            if ((GameObject*)block == player)
            {
                if (playerIsDisguised((GameObject*)block) == 0)
                {
                    fn_802B4ED8((GameObject*)block, 1, 1);
                }
            }
            else
            {
                objRenderFuzz(block);
            }
            break;
        case 2:
            fn_8000F9B4();
            objShadowFn_80062498((GameObject*)e[i][0], 0, 0, framesThisStep);
            Camera_ApplyFullViewport();
            break;
        case 3:
            fn_8000F9B4();
            objDrawFn_80061654((int)e[i][0], (int)Obj_GetActiveModel((GameObject*)e[i][0]));
            Camera_ApplyFullViewport();
            break;
        case 4:
            block = (int*)e[i][1];
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            objGetColor(0, (u8*)&c4, (u8*)&c4 + 1, (u8*)&c4 + 2);
            GXSetChanAmbColor(GX_COLOR0, c4);
            GXSetNumChans(1);
            PSMTXConcat((f32*)Camera_GetViewMatrix(), (f32*)(block + 3), m);
            setupToRenderMapBlock(block, m);
            modelRenderFn_8005d894((int*)e[i][0], (int*)e[i][1], m);
            break;
        case 5:
            block = (int*)e[i][1];
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            objGetColor(0, (u8*)&c5, (u8*)&c5 + 1, (u8*)&c5 + 2);
            GXSetChanAmbColor(GX_COLOR0, c5);
            GXSetNumChans(1);
            PSMTXConcat((f32*)Camera_GetViewMatrix(), (f32*)(block + 3), m);
            setupToRenderMapBlock(block, m);
            modelRenderFn_8005d69c((int*)e[i][0], (int*)e[i][1], m);
            break;
        case 6:
            block = (int*)e[i][1];
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            objGetColor(0, (u8*)&c6, (u8*)&c6 + 1, (u8*)&c6 + 2);
            GXSetChanAmbColor(GX_COLOR0, c6);
            GXSetNumChans(1);
            PSMTXConcat((f32*)Camera_GetViewMatrix(), (f32*)(block + 3), m);
            setupToRenderMapBlock(block, m);
            modelRenderFn_8005d4ec((int*)e[i][0], (int*)e[i][1], m);
            break;
        case 7:
            drawGlow((u32)e[i][0], e[i][1]);
            break;
        case 8:
            drawFn_8006f500();
            break;
        case 9:
            (*gWaterfxInterface)->render(0, 0);
        }
    }
}


void modelRenderFn_8005d4ec(int* p1, int* obj, float* p3)
{
    int state[5];
    int countShifted;
    int cursor;
    u32 v;
    int* base;
    struct MapShader* newR;
    int nibble;
    int i;
    u8* s0;

    countShifted = (int)*(u16*)((char*)obj + 0x84) << 3;
    modelRenderInstrsState_init((ModelRenderInstrsState*)state, *(void**)((char*)obj + 0x78), countShifted,
                                countShifted);
    modelRenderInstrsState_setBit((ModelRenderInstrsState*)state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    mapBlockRender_drawDimmedAabbLights((u32)p1, (u32)obj, (int)p3);
    newR = mapBlockRender_setLightmapShader((struct MapBlockData*)obj, state);
    state[4] += 4;
    mapBlockRender_setVtxDcrs(1, obj, newR, state);
    cursor = state[4] + 4;
    state[4] = cursor;
    countShifted = cursor >> 3;
    s0 = (u8*)state[0];
    v = s0[countShifted];
    base = (int*)(state[0] + countShifted);
    v = v | ((u32) * (u8*)((char*)base + 1) << 8);
    v = v | ((u32) * (u8*)((char*)base + 2) << 16);
    state[4] += 4;
    nibble = (v >> (cursor & 7)) & 0xf;
    for (i = 0; i < nibble; i++)
    {
        *(int*)&state[4] = state[4] + 8;
    }
    state[4] += 4;
    mapBlockRender_drawLightmapIndirectPasses((struct MapBlockData*)obj, newR, state, (float (*)[4])p3);
}
void modelRenderFn_8005d69c(int* p1, int* obj, float* p3)
{
    int state[5];
    f32 m[12];
    int countShifted;
    struct MapShader* newR;
    int cursor;
    u32 v;
    int* base;
    int nibble;
    int i;
    u8* s0;

    PSMTXConcat((f32*)lbl_80396850, p3, m);
    GXLoadTexMtxImm((const f32 (*)[4])m, GX_TEXMTX0, GX_MTX3x4);
    PSMTXConcat((f32*)lbl_80396820, p3, m);
    GXLoadTexMtxImm((const f32 (*)[4])m, GX_TEXMTX1, GX_MTX3x4);
    gxTextureSetupFn_8007cf7c();
    countShifted = (int)*(u16*)((char*)obj + 0x88) << 3;
    modelRenderInstrsState_init((ModelRenderInstrsState*)state,
                                *(void**)&((GameObject *)obj)->anim.previousLocalPosX, countShifted, countShifted);
    modelRenderInstrsState_setBit((ModelRenderInstrsState*)state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    newR = mapBlockRender_setShader(1, (struct MapBlockData*)obj, state);
    state[4] += 4;
    mapBlockRender_setVtxDcrs(1, obj, newR, state);
    cursor = state[4] + 4;
    state[4] = cursor;
    countShifted = cursor >> 3;
    s0 = (u8*)state[0];
    v = s0[countShifted];
    base = (int*)(state[0] + countShifted);
    v = v | ((u32) * (u8*)((char*)base + 1) << 8);
    v = v | ((u32) * (u8*)((char*)base + 2) << 16);
    state[4] += 4;
    nibble = (v >> (cursor & 7)) & 0xf;
    for (i = 0; i < nibble; i++)
    {
        *(int*)&state[4] = state[4] + 8;
    }
    state[4] += 4;
    mapBlockRender_callList(1, 1, (struct MapBlockData*)obj, newR, state, p3);
}
void modelRenderFn_8005d894(int* p1, int* obj, float* p3)
{
    int state[5];
    int countShifted;
    struct MapShader* newR;
    int cursor;
    u32 v;
    int* base;
    int nibble;
    int i;
    u8* s0;

    fn_8000F8F8();
    countShifted = (int)*(u16*)((char*)obj + 0x86) << 3;
    modelRenderInstrsState_init((ModelRenderInstrsState*)state, *(void**)&((GameObject *)obj)->anim.banks,
                                countShifted, countShifted);
    modelRenderInstrsState_setBit((ModelRenderInstrsState*)state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    newR = mapBlockRender_setShader(1, (struct MapBlockData*)obj, state);
    state[4] += 4;
    mapBlockRender_setVtxDcrs(1, obj, newR, state);
    cursor = state[4] + 4;
    state[4] = cursor;
    countShifted = cursor >> 3;
    s0 = (u8*)state[0];
    v = s0[countShifted];
    base = (int*)(state[0] + countShifted);
    v = v | ((u32) * (u8*)((char*)base + 1) << 8);
    v = v | ((u32) * (u8*)((char*)base + 2) << 16);
    state[4] += 4;
    nibble = (v >> (cursor & 7)) & 0xf;
    for (i = 0; i < nibble; i++)
    {
        *(int*)&state[4] = state[4] + 8;
    }
    state[4] += 4;
    mapBlockRender_callList(1, 1, (struct MapBlockData*)obj, newR, state, p3);
    Camera_ApplyFullViewport();
}


void objDrawFn_8005da48(GameObject* obj)
{
    int* model = (int*)Obj_GetActiveModel(obj);
    if (*(void**)((char*)model + 0x58) != NULL)
    {
        objRenderFn_8003d980((u8*)obj, model);
    }
    else
    {
        void* shadow;
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, obj);
        renderResetFn_8003fc60();
        objRender(0, 0, 0, 0, obj, 1);
        fn_8000F9B4();
        shadow = obj->anim.modelState;
        if (shadow != NULL && ((ObjModelState*)shadow)->shadowCastSlot != NULL)
        {
            objShadowFn_80062498(obj, 0, 0, framesThisStep);
        }
        else if (((ObjAnimComponent*)obj)->modelInstance->shadowType == OBJ_SHADOW_TYPE_CRASH)
        {
            objDrawFn_80061654((int)obj, (int)model);
        }
        Camera_ApplyFullViewport();
    }
}


void lightmap_sortTransparentDrawQueue(void)
{
    int i, j;
    int gap = 1;
    LightSortEntry tmp;
    while (gap <= (lbl_803DCE30 - 1) / 9)
        gap = gap * 3 + 1;
    while (gap > 0)
    {
        for (i = gap + 1; i <= lbl_803DCE30; i++)
        {
            tmp = ((LightSortEntry*)lbl_8037E0C0)[i - 1];
            j = i;
            while (j > gap && ((LightSortEntry*)lbl_8037E0C0)[j - gap - 1].key < tmp.key)
            {
                ((LightSortEntry*)lbl_8037E0C0)[j - 1] = ((LightSortEntry*)lbl_8037E0C0)[j - gap - 1];
                j -= gap;
            }
            ((LightSortEntry*)lbl_8037E0C0)[j - 1] = tmp;
        }
        gap /= 3;
    }
}

void lightmap_queueExternalRenderEntry(u32 a, u32 b, f32* p)
{
    s32 t, v;
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    t = (s32) - p[2];
    v = t < 0 ? 0 : (t > 0x7ffffff ? 0x7ffffff : t);
    lbl_8037E0C0[lbl_803DCE30 * 4] = a;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 1] = b;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = v | 0x38000000;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 7;
    lbl_803DCE30++;
}
