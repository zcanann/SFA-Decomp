#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/checkpoint_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEvent.h"
#include "main/newclouds.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/shader.h"
#include "main/gameplay_runtime.h"
#include "main/camera.h"
#include "main/mm.h"
#include "main/voxmaps.h"
#include "main/dll/baddie/dll_003B_menu.h"
#include "main/dll/savegame.h"
#include "main/track_dolphin.h"
#include "main/objprint_dolphin.h"
#include "dolphin/os/OSCache.h"
extern float ABS();
extern u32 FUN_8000693c();
extern u32 FUN_80006958();
extern u32 FUN_8001771c();
extern int FUN_80017a98();
extern void* ObjGroup_GetObjects();
extern u32 mapLoadDataFile(int mapId, int fileId);
extern u32 piRomLoadSection();
extern u64 FUN_80286834();
extern u32 FUN_80286880();
extern int DAT_80382eac;
extern u32 DAT_8038859c;
extern u32 DAT_803885a0;
extern u32 DAT_803885a4;
extern u32 DAT_803885a8;
extern u32* DAT_803dd6ec;
extern u32* DAT_803dd71c;
extern u32 DAT_803dda61;
extern u32 DAT_803dda6c;
extern u32 DAT_803ddae8;
extern int* DAT_803ddaec;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF834;
extern f32 lbl_803DF838;
extern f32 lbl_803DF84C;
extern f32 lbl_803DF854;
extern f32 lbl_803DF858;
extern f32 lbl_803DF85C;
extern f32 lbl_803DF860;
extern f32 lbl_803DF864;
extern f32 lbl_803DF868;
extern char sShaderDebugStrings[];
#define MAP_BLOCK_LAYER_COUNT 5
#define FRUSTUM_PLANE_COUNT 5
extern int gMapBlockLayerTables[MAP_BLOCK_LAYER_COUNT];
typedef struct WarpVec
{
    f32 x;
    f32 y;
    f32 z;
    f32 pad;
} WarpVec;
extern u8 lbl_80386648[];
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern const f32 gMapBlockWorldSize;
extern float fastFloorf(float x);
extern void OSReport(const char* msg, ...);

int objShouldLoad(int obj, int viewSlot, int mapEventGroup)
{
    char* strs;
    int verbose;
    int useObj;
    f32 y;
    f32 z;
    f32 x;
    int t;
    int ok;
    int bx;
    int bz;
    s8 found;
    s8 i;
    int* tbl;
    int* player;
    int off;
    f32* p;
    f32 d;
    f32 dz;
    f32 dy;
    f32 range;

    strs = sShaderDebugStrings;
    if (*(u32*)&((GameObject*)obj)->anim.localPosZ == 0x49054)
    {
        verbose = 1;
    }
    else
    {
        verbose = 0;
    }
    t = (*gMapEventInterface)->getMapAct(mapEventGroup);
    if (t == -1)
    {
        ok = 0;
        goto test;
    }
    if (t != 0)
    {
        if (t < 9)
        {
            if ((*(u8*)(obj + 3) >> (t - 1)) & 1)
            {
                ok = 0;
                goto test;
            }
        }
        else
        {
            if ((*(u8*)(obj + 5) >> (16 - t)) & 1)
            {
                ok = 0;
                goto test;
            }
        }
    }
    ok = 1;
test:
    if (ok == 0)
    {
        return 0;
    }
    if (*(u8*)(obj + 4) & 1)
    {
        if (verbose)
        {
            OSReport(strs + 0x1cc);
        }
        return 1;
    }
    if (*(u8*)(obj + 4) & 2)
    {
        if (verbose)
        {
            OSReport(strs + 0x1e8);
        }
        return 0;
    }
    if ((s8)viewSlot == 0)
    {
        bx = fastFloorf((((GameObject*)obj)->anim.rootMotionScale - playerMapOffsetX) / gMapBlockWorldSize);
        bz = fastFloorf((((GameObject*)obj)->anim.localPosY - playerMapOffsetZ) / gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16)
        {
            if (verbose)
            {
                OSReport(strs + 0x200, obj + 8, obj + 0xc, obj + 0x10);
            }
            return 0;
        }
        found = 0;
        bx += bz << 4;
        for (i = 0; i < MAP_BLOCK_LAYER_COUNT; i++)
        {
            if (*(s8*)(bx + gMapBlockLayerTables[i]) >= 0)
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
    if (*(u8*)(obj + 4) & 0x20)
    {
        if (verbose)
        {
            OSReport(strs + 0x240);
        }
        return 1;
    }
    useObj = 0;
    if ((*(u8*)(obj + 4) & 4) && (s8)viewSlot == 0)
    {
        player = Obj_GetPlayerObject();
        if (player != NULL)
        {
            x = ((GameObject*)player)->anim.worldPosX;
            y = ((GameObject*)player)->anim.worldPosY;
            z = ((GameObject*)player)->anim.worldPosZ;
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
        off = (s8)viewSlot << 4;
        x = ((WarpVec*)lbl_80386648)[(s8)viewSlot].x;
        p = (f32*)(lbl_80386648 + off);
        y = p[1];
        z = p[2];
    }
    range = (f32)(*(u8*)(obj + 6) << 3);
    d = x - ((GameObject*)obj)->anim.rootMotionScale;
    dy = y - ((GameObject*)obj)->anim.localPosX;
    dz = z - ((GameObject*)obj)->anim.localPosY;
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

int fn_80056800(int index)
{
    return (int)(DAT_803ddaec + index * 4);
}

void FUN_80056418(int idx, int xStep, int yStep, int texWidthFixed, int texHeightFixed)
{
    int entry;

    entry = DAT_803ddae8 + idx * 0x10;
    *(short*)(entry + 8) = (short)((xStep << 0x10) / (texWidthFixed >> 6));
    *(short*)(entry + 10) = (short)((yStep << 0x10) / (texHeightFixed >> 6));
    return;
}

int FUN_80056600(void)
{
    return DAT_803dda61;
}

void FUN_80056cfc(void)
{
    u8* stepPtr;
    short tag;
    bool found;
    u32 v;
    u32* q;
    u32* tbl;
    int in_r6;
    u32 mask;
    int pos;
    u32 count;
    short* cur;
    int page;
    u64 ret;

    ret = FUN_80286834();
    page = (int)((u64)ret >> 0x20);
    tbl = (u32*)ret;
    found = false;
    mask = 0;
    cur = *(short**)(page + 0x20);
    count = (u32) * (u16*)(page + 8);
    if (count != 0)
    {
        pos = 0;
        if (in_r6 == 0)
        {
            tbl[0x21] = 0xffffffff;
            *tbl = 0xffffffff;
            tbl[1] = 0xffffffff;
            tbl[2] = 0xffffffff;
            tbl[3] = 0xffffffff;
            tbl[4] = 0xffffffff;
            tbl[5] = 0xffffffff;
            tbl[6] = 0xffffffff;
            tbl[7] = 0xffffffff;
            tbl[8] = 0xffffffff;
            tbl[9] = 0xffffffff;
            tbl[10] = 0xffffffff;
            tbl[0xb] = 0xffffffff;
            tbl[0xc] = 0xffffffff;
            tbl[0xd] = 0xffffffff;
            tbl[0xe] = 0xffffffff;
            tbl[0xf] = 0xffffffff;
            tbl[0x10] = 0xffffffff;
            tbl[0x11] = 0xffffffff;
            tbl[0x12] = 0xffffffff;
            tbl[0x13] = 0xffffffff;
            tbl[0x14] = 0xffffffff;
            tbl[0x15] = 0xffffffff;
            tbl[0x16] = 0xffffffff;
            tbl[0x17] = 0xffffffff;
            tbl[0x18] = 0xffffffff;
            tbl[0x19] = 0xffffffff;
            tbl[0x1a] = 0xffffffff;
            tbl[0x1b] = 0xffffffff;
            tbl[0x1c] = 0xffffffff;
            tbl[0x1d] = 0xffffffff;
            tbl[0x1e] = 0xffffffff;
            tbl[0x1f] = 0xffffffff;
        }
        for (; pos < count; pos = pos + (u32) * stepPtr * 4)
        {
            if (in_r6 == 0)
            {
                tag = *cur;
                if ((tag == 0x6e) || (tag == 5))
                {
                    if (tag == 0x6e)
                    {
                        (**(VtableFn**)(*DAT_803dd71c + 8))(cur);
                    }
                    else
                    {
                        (**(VtableFn**)(*DAT_803dd6ec + 8))(cur);
                    }
                    if (!found)
                    {
                        tbl[0x21] = (int)cur - *(int*)(page + 0x20);
                        found = true;
                    }
                }
                else if (((*(u8*)(cur + 2) & 0x10) != 0) &&
                    ((mask & 1 << (u32) * (u8*)(cur + 3)) == 0))
                {
                    tbl[*(u8*)(cur + 3)] = (int)cur - *(int*)(page + 0x20);
                    mask = mask | 1 << (u32) * (u8*)(cur + 3);
                }
            }
            else
            {
                if (*cur == 0x6e)
                {
                    (**(VtableFn**)(*DAT_803dd71c + 0xc))(cur);
                }
                if (*cur == 5)
                {
                    (**(VtableFn**)(*DAT_803dd6ec + 0xc))(cur);
                }
            }
            stepPtr = (u8*)(cur + 1);
            cur = cur + (u32) * stepPtr * 2;
        }
        if (in_r6 == 0)
        {
            v = tbl[0x21];
            mask = count;
            if ((v != 0xffffffff) && ((int)v < count))
            {
                mask = v;
            }
            page = 4;
            q = tbl;
            do
            {
                v = *q;
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[1];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[2];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[3];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[4];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[5];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[6];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                v = q[7];
                if ((v != 0xffffffff) && ((int)v < mask))
                {
                    mask = v;
                }
                q = q + 8;
                page = page + -1;
            }
            while (page != 0);
            tbl[0x22] = mask;
            if (tbl[0x21] == 0xffffffff)
            {
                tbl[0x20] = count;
            }
            else
            {
                tbl[0x20] = tbl[0x21];
            }
        }
    }
    FUN_80286880();
    return;
}

void FUN_800571f8(u8* outFlags)
{
    int foundIdx;
    int remain;
    int* entry;
    int mapId;

    mapId = 0;
    do
    {
        foundIdx = 0;
        remain = DAT_803dda6c;
        entry = &DAT_80382eac;
        if (0 < remain)
        {
            do
            {
                if ((*entry != 0) && (mapId == *(short*)(entry + 1))) goto found;
                entry = entry + 2;
                foundIdx = foundIdx + 1;
                remain = remain + -1;
            }
            while (remain != 0);
        }
        foundIdx = -1;
    found:
        if (foundIdx == -1)
        {
            *outFlags = 0;
        }
        else
        {
            *outFlags = 1;
        }
        mapId = mapId + 1;
        outFlags = outFlags + 1;
        if (0x77 < mapId)
        {
            return;
        }
    }
    while (true);
}

u32 FUN_800575b4(double radius, float* pos)
{
    u32 planeIdx;
    u8 i;

    i = 0;
    while (true)
    {
        if (4 < i)
        {
            return 1;
        }
        planeIdx = i;
        if ((float)(radius +
                (double)((float)(&DAT_803885a8)[planeIdx * 5] +
                    (float)(&DAT_803885a4)[planeIdx * 5] * (pos[2] - lbl_803DDA5C) +
                    pos[1] * (float)(&DAT_803885a0)[planeIdx * 5] +
                    (float)(&DAT_8038859c)[planeIdx * 5] * (*pos - lbl_803DDA58))) <
            lbl_803DF84C)
            break;
        i = i + 1;
    }
    return 0;
}

u32 FUN_80057690(int obj)
{
    float projSize;
    int viewObj;
    u32 result;
    u8 planeIdx;
    int placementData;
    u32 alpha;
    double nearDist;
    double dist;
    double range;
    float screenW;
    float screenH;
    float projRadius;
    float screenY;
    u8 projOutA[4];
    u8 projOutB[4];
    u64 alphaScaled;

    if (((GameObject*)obj)->anim.alpha == 0)
    {
        *(u8*)(obj + 0x37) = 0;
        return 0;
    }
    placementData = *(int*)&((GameObject*)obj)->anim.placementData;
    if ((placementData == 0) || ((*(u8*)(placementData + 5) & 1) == 0))
    {
        range = (double)*(float*)(obj + 0x40);
        if (range < (double)lbl_803DF838)
        {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        viewObj = FUN_80017a98();
        if (((placementData == 0) || ((*(u8*)(placementData + 5) & 2) == 0)) || (viewObj == 0))
        {
            dist = (double)FUN_80006958((double)((GameObject*)obj)->anim.worldPosX,
                                         (double)((GameObject*)obj)->anim.worldPosY,
                                         (double)((GameObject*)obj)->anim.worldPosZ);
        }
        else
        {
            dist = (double)FUN_8001771c((float*)(obj + 0x18), (float*)(viewObj + 0x18));
        }
        if (range < dist)
        {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        alpha = 0xff;
        nearDist = (double)(float)(range - (double)lbl_803DF854);
        if (nearDist < dist)
        {
            alpha = (u32)(lbl_803DF858 *
                (lbl_803DF85C - (float)(dist - nearDist) / (float)(range - nearDist)));
            alphaScaled = (double)(s64)(int)
            alpha;
        }
        FUN_8000693c((double)(((GameObject*)obj)->anim.worldPosX - lbl_803DDA58),
                     (double)((GameObject*)obj)->anim.worldPosY,
                     (double)(((GameObject*)obj)->anim.worldPosZ - lbl_803DDA5C),
                     (double)(((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale),
                     projOutB,
                     projOutA, &screenY, &projRadius, &screenH, &screenW);
        projSize = ABS(projRadius) * lbl_803DF834;
        if (projSize < lbl_803DF860)
        {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        if (projSize < lbl_803DF868)
        {
            alphaScaled = (double)(int)alpha;
            alpha = (u32)(((float)(alphaScaled) * (projSize - lbl_803DF860)) /
                lbl_803DF864);
        }
        *(char*)(obj + 0x37) = (char)(alpha * (((GameObject*)obj)->anim.alpha + 1) >> 8);
    }
    else
    {
        *(char*)(obj + 0x37) = (char)((((GameObject*)obj)->anim.alpha + 1) * 0xff >> 8);
    }
    if (*(char*)(obj + 0x37) == '\0')
    {
        result = 0;
    }
    else
    {
        for (planeIdx = 0; planeIdx < 5; planeIdx = planeIdx + 1)
        {
            alpha = planeIdx;
            if (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale +
                (float)(&DAT_803885a8)[alpha * 5] +
                (float)(&DAT_803885a4)[alpha * 5] * (((GameObject*)obj)->anim.worldPosZ - lbl_803DDA5C) +
                ((GameObject*)obj)->anim.worldPosY * (float)(&DAT_803885a0)[alpha * 5] +
                (float)(&DAT_8038859c)[alpha * 5] * (((GameObject*)obj)->anim.worldPosX - lbl_803DDA58) <
                lbl_803DF84C)
            {
                return 0;
            }
        }
        result = 1;
    }
    return result;
}

int return0_80056694(void) { return 0x0; }
int return0_8005669C(void) { return 0x0; }

extern s8 curMapLayer;
extern s8 curMapType;
extern s16 lbl_803DCEB4;
extern s16 lbl_803DCEB6;
extern u32 renderFlags;
s32 getCurMapLayer(void) { return curMapLayer; }
s32 getCurMapType(void) { return curMapType; }

void mapReloadWithFadeout(void)
{
    curMapType = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
}

extern int lbl_803DCE6C;

void* mapTextureOverrideGetEntry(int idx)
{
    return (void*)(lbl_803DCE6C + (idx << 4));
}

extern int lbl_803822A0[5];

void* fn_80059334(int a, int b)
{
    int* base = (int*)lbl_803822A0[0];
    return (char*)base + (a + (b << 4)) * 12;
}

extern int lbl_803DCE68;
extern f32 lbl_803DEBC8;

void mapTextureScrollGetOffset(int idx, float* outX, float* outY)
{
    f32 divisor;
    char* base;
    idx <<= 4;
    *outX = *(f32*)(lbl_803DCE68 + idx) / (divisor = lbl_803DEBC8);
    base = (char*)(lbl_803DCE68 + 4);
    *outY = *(f32*)(base + idx) / divisor;
}

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

/* 132b per-block flag scan. */
typedef struct
{
    u32 field_0;
    s16 field_4;
    u16 field_6;
} BlockEntry;

extern BlockEntry gShaderRomListSlots[8];
extern s8 gShaderRomListSlotCount;

void mapBlockFn_80059c2c(u8* outFlags)
{
    int i;
    BlockEntry* p;
    int outer;
    for (outer = 0; outer < 0x78; outer++)
    {
        s8 limit = gShaderRomListSlotCount;
        for (i = 0, p = gShaderRomListSlots; i < limit; p++, i++)
        {
            if (p->field_0 != 0 && outer == p->field_4)
            {
                goto checked;
            }
        }
        i = -1;
    checked:
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

extern f32 lbl_803DEBCC;
extern f32 retraceCount_803DEBE0;
extern f32 flushFlag_803DEBE4;
extern f32 retraceQueue_803DEBE8;
extern f32 lbl_803DEBEC;
extern f32 PreCB;
extern char gViewFrustumPlanes[];

int ViewFrustum_IsSphereVisible(float* center, float radius)
{
    FrustumPlane* plane;
    u8 i = 0;
    f32 offZ = playerMapOffsetZ;
    f32 offX = playerMapOffsetX;
    for (; i < FRUSTUM_PLANE_COUNT; i++)
    {
        float dot;
        plane = (FrustumPlane*)(gViewFrustumPlanes + i * sizeof(FrustumPlane));
        dot = plane->distance
            + (plane->normalZ * (center[2] - offZ)
                + (center[1] * plane->normalY + plane->normalX * (center[0] - offX)));
        if (radius + dot < *(f32*)&lbl_803DEBCC) return 0;
    }
    return 1;
}

extern char lbl_803822C8[];
#define ROM_LIST_PAGE_COUNT 120
extern void* gLoadedRomListPages[];
extern void defStartFn_8005972c(char* p1, u32* p2, int idx, int flag);

void fn_80059A50(int pageIndex)
{
    int idx = pageIndex;
    void* p = gLoadedRomListPages[idx];
    if (p != 0)
    {
        defStartFn_8005972c(p, (u32*)(lbl_803822C8 + idx * 0x8C), idx, 1);
        mm_free(gLoadedRomListPages[idx]);
        gLoadedRomListPages[idx] = 0;
    }
}

extern f32 gShaderLoadCenterZ;
extern f32 gShaderLoadCenterY;
extern f32 gShaderLoadCenterX;

void loadMapForCameraPos(float x, float y, float z)
{
    if ((renderFlags & 2) != 0 && (renderFlags & 0x800) == 0) return;
    gShaderLoadCenterX = x;
    gShaderLoadCenterY = y;
    gShaderLoadCenterZ = z;
    renderFlags |= 2;
    if ((renderFlags & 0x800) != 0)
    {
        doPendingMapLoads();
    }
}

extern int lbl_803DB648;
extern void* lbl_803DCEA0;

void* mapBlockFn_800592e4(void)
{
    char* p = (char*)lbl_803822A0[0];
    int v = *(s16*)(p + 0x594);
    if (v < 0)
    {
        v = lbl_803DB648;
    }
    if (v < 0)
    {
        return 0;
    }
    {
        void* res = gLoadedRomListPages[v];
        if (res == 0)
        {
            return res;
        }
        lbl_803DB648 = v;
        lbl_803DCEA0 = res;
        return res;
    }
}

extern int gShaderGameTextLoadedMapId;
extern int gShaderCurMapEventId;
extern s8 gShaderMapTextDirTable[];
extern void gameTextLoadDir(int dirId);

void gameTextLoadForMap_800571f0(u8 force)
{
    int curVal = gShaderCurMapEventId;
    if (curVal == -1) return;
    if (curVal == gShaderGameTextLoadedMapId && force == 0) return;
    gShaderGameTextLoadedMapId = curVal;
    if (curVal >= 0x76) return;
    {
        s8 entry = gShaderMapTextDirTable[curVal];
        if (entry == -1) return;
        gameTextLoadDir(entry);
    }
}

void mapTextureScrollSetStep(int idx, int xStep, int yStep, int texWidthFixed, int texHeightFixed)
{
    int base = lbl_803DCE68 + idx * 16;
    *(s16*)(base + 8) = (s16)((xStep << 16) / (texWidthFixed >> 6));
    *(s16*)(base + 10) = (s16)((yStep << 16) / (texHeightFixed >> 6));
}

extern s8 lbl_803DB624;
extern u8* lbl_803DCE78;
extern int mapCoordsToId(int x, int z, int layer);
extern u32 getDataFileSize(int idx);

void mapSetup(int mapType, f32 a, s32* outMapId, s32* outEvent, f32 b, f32 c)
{
    u8* tabEntry;
    int mapY;
    int mapId;
    int layer;
    int mapCount;
    s8* arr;

    layer = 0;
    arr = (s8*)(int)&lbl_803DB624;
    if (arr[0] != mapType)
    {
        layer = 1;
        if (arr[1] != mapType)
        {
            layer = 2;
            if (arr[2] != mapType)
            {
                layer = 3;
                if (arr[3] != mapType)
                {
                    layer = 4;
                    if (arr[4] != mapType)
                    {
                        layer = 5;
                    }
                }
            }
        }
    }
    curMapLayer = 0;
    mapY = fastFloorf(c / gMapBlockWorldSize);
    mapId = mapCoordsToId((s32)fastFloorf(a / gMapBlockWorldSize), mapY, layer);
    mapCount = (s32)((u32)getDataFileSize(0x1f) >> 5);
    if (mapId < 0 || mapId >= mapCount)
    {
        curMapType = 0;
    }
    else
    {
        tabEntry = lbl_803DCE78;
        getTabEntry(tabEntry, 0x1f, mapId << 5, 0x20);
        curMapType = *(s8*)(tabEntry + 0x1c);
    }
    lbl_803DCEB4 = 0;
    if (curMapType == 1)
    {
        lbl_803DCEB6 = mapId;
        lbl_803DCEB4 = *(s16*)(tabEntry + 0x1e);
    }
    *outMapId = mapId;
    if (mapId != -1)
    {
        *outEvent = (s32) * (s8*)((*gMapEventInterface)->getCurCharPos() + 0xe);
    }
}

extern s16* lbl_803DCE94;
extern u8 lbl_803DCE98;
extern u8* lbl_803DCE8C;
extern void mapBlockFn_80059354(int p1, int p2, s16* entry, int layer);
extern int mapCheckCurBlocks(int v);

extern void MapBlock_init(void* blk);
extern int textureLoad(int id, int param);
extern void MapBlock_initHits(void* blk, int blockId);
extern void MapBlock_initShaders(void* blk);
extern int return0_80060B90(void* blk);


int mapLoadBlock(int cellX, int cellZ, int worldX, int worldZ, int layer)
{
    int blockId;
    int byteOff;
    char* entry;
    int slotIdx;
    s16* arr;
    int i;
    void* blk;
    s8* statusArr;

    entry = (char*)lbl_803822A0[layer];
    statusArr = (s8*)gMapBlockLayerTables[layer];
    slotIdx = cellX + (cellZ << 4);
    entry += slotIdx * 12;

    mapBlockFn_80059354(worldX, worldZ, (s16*)entry, layer);

    blockId = *(s16*)(entry + 6);
    if (mapCheckCurBlocks(*(s8*)(entry + 9)) == -1)
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

    arr = lbl_803DCE94;
    for (i = 0; i < lbl_803DCE98; i++)
    {
        if (blockId == *arr)
        {
            lbl_803DCE8C[i]++;
            statusArr[slotIdx] = i;
            return 1;
        }
        arr++;
    }

    blk = MapBlock_loadFromFile(blockId);
    if (blk != NULL)
    {
        MapBlock_init(blk);
        i = 0;
        byteOff = i;
        while (i < *(u8*)((char*)blk + 0xa0))
        {
            int v = *(int*)(*(int*)((char*)blk + 0x54) + byteOff);
            v = -(int)((u32)v | 0x8000);
            *(int*)(*(int*)((char*)blk + 0x54) + byteOff) = textureLoad(v, 0);
            byteOff += 4;
            i++;
        }
        MapBlock_initHits(blk, blockId);
        MapBlock_initShaders(blk);
        trackLoadBlockEnd(blk, blockId, slotIdx, layer);
        *(int*)blk = return0_80060B90(blk);
        DCStoreRange(blk, *(int*)((char*)blk + 0x8));
    }
    return 1;
}

typedef struct
{
    f32 v[15];
} _PlaneDirPack;

typedef struct
{
    f32 v[5];
} _ScalePack;

typedef struct
{
    f32 x, y, z;
} _Vec3;

extern _PlaneDirPack sPlayerFrustumPlaneDirs;
extern _ScalePack sPlayerFrustumPlaneScales;
extern FrustumPlane gPlayerRelativeFrustumPlanes[];
extern f32 PostCB_803DEBF4;
extern f32* Camera_GetInverseViewRotationMatrix(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern void PSMTXMultVec(f32 * mtx, _Vec3 * in, f32 * out);
extern void PSVECScale(f32* in, _Vec3* out, f32 s);
extern void PSVECAdd(_Vec3* a, _Vec3* b, _Vec3* out);
extern f32 PSVECDotProduct(_Vec3 * a, f32 * b);

void playerVecFn_8005a9b0(void)
{
    _Vec3 tmp;
    _Vec3 camPos;
    _ScalePack scales;
    _PlaneDirPack planes;
    int* player;
    int* viewSlot;
    f32* outPtr;
    int i;
    f32* invRotMtx;
    f32 clipDist;

    planes = sPlayerFrustumPlaneDirs;
    scales = sPlayerFrustumPlaneScales;
    player = Obj_GetPlayerObject();
    viewSlot = Camera_GetCurrentViewSlot();
    camPos.x = *(f32*)((char*)viewSlot + 0x44) - playerMapOffsetX;
    camPos.y = *(f32*)((char*)viewSlot + 0x48);
    camPos.z = *(f32*)&((GameObject*)viewSlot)->anim.placementData - playerMapOffsetZ;
    invRotMtx = Camera_GetInverseViewRotationMatrix();
    if (player != NULL)
    {
        clipDist = -Camera_DistanceToCurrentViewPosition(
            ((GameObject*)player)->anim.worldPosX,
            ((GameObject*)player)->anim.worldPosY,
            ((GameObject*)player)->anim.worldPosZ);
    }
    else
    {
        clipDist = PostCB_803DEBF4;
    }
    scales.v[0] = clipDist;

    outPtr = (f32*)gPlayerRelativeFrustumPlanes;
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++)
    {
        PSMTXMultVec(invRotMtx, (_Vec3*)&planes.v[i * 3], &outPtr[i * 5]);
        PSVECScale(&outPtr[i * 5], &tmp, scales.v[i]);
        PSVECAdd(&camPos, &tmp, &tmp);
        outPtr[i * 5 + 3] = -PSVECDotProduct(&tmp, &outPtr[i * 5]);
    }
    frustumPlanes_updateAabbCornerIndices(gPlayerRelativeFrustumPlanes, FRUSTUM_PLANE_COUNT);
}

extern int* lbl_803DCE9C;

extern char sTrackLoadBlockOverrunError[];

void trackLoadBlockEnd(void* blk, int blockId, int slotIdx, int layer)
{
    int i;
    s16* arr;
    int count;
    s8* statusArr;

    i = 0;
    arr = lbl_803DCE94;
    count = lbl_803DCE98;
    for (; i < count; i++)
    {
        if (*arr == -1) break;
        arr++;
    }
    if (i == count)
    {
        lbl_803DCE98++;
        if (lbl_803DCE98 == 0x40)
        {
            OSReport(sTrackLoadBlockOverrunError);
        }
    }
    statusArr = (s8*)gMapBlockLayerTables[layer];
    statusArr[slotIdx] = i;
    lbl_803DCE9C[i] = (int)blk;
    lbl_803DCE94[i] = blockId;
    lbl_803DCE8C[i] = 1;
    setMapBlockFlag();
}

#pragma dont_inline on
void mapTextureOverrideRelease(int key, int type)
{
    int i;
    int off;
    u32 entryKey;

    for (i = 0; i < 80; i++)
    {
        off = i * 0x10;
        entryKey = *(u32*)(lbl_803DCE6C + off);
        if (entryKey == key &&
            *(u8*)(lbl_803DCE6C + off + 0xe) == type &&
            *(s16*)(lbl_803DCE6C + off + 0xc) > 0)
        {
            *(s16*)(lbl_803DCE6C + off + 0xc) -= 1;
            if (*(s16*)(lbl_803DCE6C + off + 0xc) == 0)
            {
                *(int*)(lbl_803DCE6C + off + 4) = 0;
                *(u8*)(lbl_803DCE6C + off + 0xe) = 0;
                *(int*)(lbl_803DCE6C + off) = 0;
                *(int*)(lbl_803DCE6C + off + 8) = 0;
            }
        }
    }
}
#pragma dont_inline reset

void mapTextureOverrideSetValue(int type, u32 key, int value)
{
    int i;
    int off;

    for (i = 0; i < 80; i++)
    {
        off = i * 0x10;
        if (*(s16*)(lbl_803DCE6C + off + 0xc) > 0 &&
            *(void**)(lbl_803DCE6C + off) == (void*)key &&
            type == *(u8*)(lbl_803DCE6C + off + 0xe))
        {
            *(int*)(lbl_803DCE6C + off + 4) = value;
        }
    }
}

extern int mapGetRomListAndOffsets(int p1, int b);

void mapLoadForObject(int p1, char* p2)
{
    int saved = gShaderCurMapEventId;
    int slot;
    int romList = mapGetRomListAndOffsets(p1, 1);
    int i;
    slot = 0x50;

    for (i = 0; i < 40; i++)
    {
        if (gLoadedRomListPages[slot] == NULL)
        {
            gLoadedRomListPages[slot] = (void*)romList;
            break;
        }
        slot++;
    }
    *(u8*)(p2 + 0x34) = slot;
    (*gMapEventInterface)->setMapActLut(p1, slot);
    defStartFn_8005972c((char*)romList, (u32*)&lbl_803822C8[slot * 0x8c], slot, 0);
    (*gMapEventInterface)->updateObjGroups(slot);
    gShaderCurMapEventId = saved;
}

int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed)
{
    char* base;
    char* e;
    char* e2;
    int idx;
    int slot;
    f32 init;

    idx = 0;
    base = (char*)lbl_803DCE68;
    e = base;
    for (; idx < 0x3a; idx++)
    {
        if (*(s16*)(e + 8) == xStep && *(s16*)(e + 0xa) == yStep)
        {
            *(u8*)(e + 0xc) += 1;
            return idx;
        }
        e += 0x10;
    }
    slot = -1;
    for (idx = 0, e2 = base; idx < 0x3a; idx++, e2 += 0x10)
    {
        if (*(u8*)(e2 + 0xc) == 0)
        {
            slot = idx;
            break;
        }
    }
    if (slot == -1)
        return -1;
    e = base + slot * 0x10;
    *(s16*)(e + 8) = (s16)((xStep << 16) / (texWidthFixed >> 6));
    *(s16*)(e + 0xa) = (s16)((yStep << 16) / (texHeightFixed >> 6));
    init = lbl_803DEBCC;
    *(f32*)e = init;
    *(f32*)(e + 4) = init;
    *(u8*)(e + 0xc) += 1;
    return slot;
}

extern int isRomListLoading(void);
extern void padUpdate(void);
extern void checkReset(void);
extern void waitNextFrame(void);
extern void loadDataFiles(void);
extern void dvdCheckError(void);
extern void mmFreeTick(int arg);
extern void gameTextRun(void);
extern int GXFlush_(u8 visible, int unused);
extern int saveGame_restoreObjectPosToRomList(void* object);
extern char lbl_8037E0C0[];
extern u8 gDvdErrorPauseActive;
extern int lbl_803DB620;

typedef struct ShaderRomListSlot
{
    void* romlist;
    s16 slot;
    s16 pad;
} ShaderRomListSlot;

int mapProcessRomList(int slot)
{
    char* base;
    int j;
    char* obj;
    int i;
    char* cur;
    u8 flag;
    int count;
    ShaderRomListSlot* p;
    ShaderRomListSlot* slots;
    ShaderRomListSlot* entry;
    s16* rects;
    int step;
    int rl;
    f32 dx, dz;

    base = lbl_8037E0C0;
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
    rl = mapGetRomListAndOffsets(slot, 0);
    slots = (ShaderRomListSlot*)(base + 0x418C);
    entry = &slots[i];
    entry->romlist = (void*)rl;
    *(int*)(slot * 4 + 0x83A8 + (char*)base) = rl;
    *(s16*)(base + i * 8 + 0x4190) = slot;
    lbl_803DCEA0 = entry->romlist;
    rects = (s16*)(*(int*)(base + 0x417C) + slot * 10);
    *(u8*)((char*)lbl_803DCEA0 + 0x19) = *(u8*)(*(int*)(base + 0x4184) + slot);
    *(f32*)((char*)lbl_803DCEA0 + 0x24) =
        gMapBlockWorldSize * (f32)(rects[0] + *(s16*)((char*)lbl_803DCEA0 + 4));
    *(f32*)((char*)lbl_803DCEA0 + 0x28) =
        gMapBlockWorldSize * (f32)(rects[2] + *(s16*)((char*)lbl_803DCEA0 + 6));
    cur = lbl_803DCEA0;
    dz = *(f32*)(cur + 0x28);
    dx = *(f32*)(cur + 0x24);
    if (cur != 0)
    {
        obj = *(char**)(cur + 0x20);
        for (j = 0; j < *(u16*)(cur + 8);)
        {
            if (saveGame_restoreObjectPosToRomList(obj) == 0)
            {
                ((GameObject*)obj)->anim.rootMotionScale += dx;
                ((GameObject*)obj)->anim.localPosY += dz;
            }
            step = *(u8*)(obj + 2) * 4;
            j += step;
            obj += step;
        }
    }
    lbl_803DB620 = slot;
    return i;
}

extern void mapsBinGetRomlistSize(int offset, int* a, int* b, int* c);
extern int lbl_803DCE7C;

int mapGetRomListAndOffsets(int p1, int flag)
{
    int tabOff = p1 * 7 << 2;
    int offset0 = *(int*)(lbl_803DCE7C + tabOff);
    int tailLen = *(int*)((lbl_803DCE7C + 0x1c) + tabOff) - offset0;
    int v0, v1, v2;
    int i;

    mapsBinGetRomlistSize(offset0, &v0, &v1, &v2);
    lbl_803DCEA0 = mmAlloc(tailLen + (v0 + 7 >> 3) + 0x401 + v2, 5, 0);
    fileLoadToBufferOffset(0x1d, lbl_803DCEA0, offset0, tailLen);

    *(int*)((char*)lbl_803DCEA0 + 0xc) = (int)lbl_803DCEA0 + *(int*)((lbl_803DCE7C + 4) + tabOff) - offset0;
    *(int*)((char*)lbl_803DCEA0 + 0x14) = (int)lbl_803DCEA0 + *(int*)((lbl_803DCE7C + 8) + tabOff) - offset0;
    *(int*)((char*)lbl_803DCEA0 + 0x30) = (int)lbl_803DCEA0 + *(int*)((lbl_803DCE7C + 0xc) + tabOff) - offset0;
    *(int*)((char*)lbl_803DCEA0 + 0x2c) = (int)lbl_803DCEA0 + *(int*)((lbl_803DCE7C + 0x10) + tabOff) - offset0;
    *(int*)((char*)lbl_803DCEA0 + 0x34) = (int)lbl_803DCEA0 + *(int*)((lbl_803DCE7C + 0x14) + tabOff) - offset0;
    *(int*)((char*)lbl_803DCEA0 + 0x20) = (int)lbl_803DCEA0 + *(int*)((lbl_803DCE7C + 0x18) + tabOff) - offset0;

    piRomLoadSection(*(int*)((lbl_803DCE7C + 0x18) + tabOff), p1, *(int*)((char*)lbl_803DCEA0 + 0x20));
    *(int*)((char*)lbl_803DCEA0 + 0x10) = (*(int*)((lbl_803DCE7C + 0x1c) + tabOff) + v2) + (int)lbl_803DCEA0 - offset0;

    for (i = 0; i < (v0 + 7 >> 3) + 1; i++)
    {
        *(u8*)(*(int*)((char*)lbl_803DCEA0 + 0x10) + i) = 0;
    }
    {
        f32 fillVal = lbl_803DEBCC;
        *(f32*)((char*)lbl_803DCEA0 + 0x24) = fillVal;
        *(f32*)((char*)lbl_803DCEA0 + 0x28) = fillVal;
    }
    *(u8*)((char*)lbl_803DCEA0 + 0x18) = 0;
    *(u8*)((char*)lbl_803DCEA0 + 0x19) = 0;
    if (flag == 0)
    {
        defStartFn_8005972c(lbl_803DCEA0, (u32*)&lbl_803822C8[p1 * 0x8c], p1, 0);
        (*gMapEventInterface)->updateObjGroups(p1);
    }
    return (int)lbl_803DCEA0;
}

#pragma dont_inline on
void mapInitSetRects(s16* rect, u8* bitmap, int p3, int p4, int idx)
{
    u8* self = lbl_803DCE78;
    int tabOff = idx * 7 << 2;
    int offset0 = *(int*)(lbl_803DCE7C + tabOff);
    int x, y;

    getTabEntry(self, 0x1d, offset0,
                *(int*)((lbl_803DCE7C + 8) + tabOff) - offset0);
    *(int*)(self + 0xc) = (int)self + *(int*)((lbl_803DCE7C + 4) + tabOff) - *(int*)(lbl_803DCE7C + tabOff);
    rect[0] = p3 - *(s16*)(self + 4);
    rect[2] = p4 - *(s16*)(self + 6);
    rect[1] = rect[0] + *(s16*)(self + 0) - 1;
    rect[3] = rect[2] + *(s16*)(self + 2) - 1;
    *(s8*)((char*)rect + 8) = *(s16*)(self + 4);
    *(s8*)((char*)rect + 9) = *(s16*)(self + 6);
    for (y = 0; (s16)y < *(s16*)(self + 2); y++)
    {
        for (x = 0; (s16)x < *(s16*)(self + 0); x++)
        {
            int p = (s16)x + (s16)y * *(s16*)(self + 0);
            if ((int)(*(u32*)(*(int*)(self + 0xc) + p * 4) >> 23 & 0xff) != 0xff)
            {
                bitmap[p >> 3] |= 1 << (p & 7);
            }
        }
    }
}
#pragma dont_inline reset

extern void Obj_UpdateWorldTransform(void);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);

void playerUpdateFn_8005649c(void)
{
    int count;
    int** objs;
    char* cam;
    int** e;
    int i, slot;
    f32 lx, ly, lz;

    objs = ObjGroup_GetObjects(6, &count);
    cam = (char*)Camera_GetCurrentViewSlot();
    Obj_UpdateWorldTransform();
    for (i = 0; i < 31; i++)
        *(int*)(lbl_80386648 + i * 0x10 + 0xc) = 0;
    *(f32*)(lbl_80386648 + 0) = *(f32*)(cam + 0x44);
    *(f32*)(lbl_80386648 + 4) = *(f32*)(cam + 0x48);
    *(f32*)(lbl_80386648 + 8) = *(f32*)&((GameObject*)cam)->anim.placementData;
    *(int*)(lbl_80386648 + 0xc) = 1;
    for (i = 0, e = objs; i < count; i++, e++)
    {
        int* obj = *e;
        slot = *(s8*)((char*)obj + 0x35) + 1;
        if (*(void**)(cam + 0x40) == obj)
        {
            *(f32*)(lbl_80386648 + slot * 0x10 + 0) = ((GameObject*)cam)->anim.localPosX;
            *(f32*)(lbl_80386648 + slot * 0x10 + 4) = ((GameObject*)cam)->anim.localPosY;
            *(f32*)(lbl_80386648 + slot * 0x10 + 8) = ((GameObject*)cam)->anim.localPosZ;
        }
        else
        {
            Obj_TransformWorldPointToLocal(*(f32*)(cam + 0x44), *(f32*)(cam + 0x48), *(f32*)&((GameObject*)cam)->anim.placementData, &lx, &ly,
                                           &lz);
            *(f32*)(lbl_80386648 + slot * 0x10 + 0) = lx;
            *(f32*)(lbl_80386648 + slot * 0x10 + 4) = ly;
            *(f32*)(lbl_80386648 + slot * 0x10 + 8) = lz;
        }
        *(int*)(lbl_80386648 + slot * 0x10 + 0xc) = 1;
    }
}

extern char sTrackGlobalTexanimOverflowError[];

typedef struct TexOverrideEntry
{
    u32 key;
    int data0;
    int data1;
    s16 refs;
    u8 type;
    u8 pad;
} TexOverrideEntry;

int mapTextureOverrideAcquire(int key, int value, int type)
{
    TexOverrideEntry* e;
    int idx;
    int found;
    TexOverrideEntry* e2;
    int idx2;

    found = -1;
    idx = 0;
    e = (TexOverrideEntry*)lbl_803DCE6C;
    for (; idx < 80; idx++)
    {
        if (e->refs != 0 && e->key == key && type == e->type)
        {
            found = idx;
            break;
        }
        e++;
    }
    if (found != -1)
    {
        *(s16*)((char*)(lbl_803DCE6C + 12) + found * 16) += 1;
        return found;
    }
    found = -1;
    idx2 = 0;
    e2 = (TexOverrideEntry*)lbl_803DCE6C;
    for (; idx2 < 80; idx2++)
    {
        if (e2->refs == 0)
        {
            found = idx2;
            break;
        }
        e2++;
    }
    if (found != -1)
    {
        *(s16*)((char*)(lbl_803DCE6C + 12) + found * 16) = 1;
        *(int*)((char*)(lbl_803DCE6C + 4) + found * 16) = 0;
        *(int*)((char*)(lbl_803DCE6C + 8) + found * 16) = value;
        ((TexOverrideEntry*)lbl_803DCE6C)[found].key = key;
        *(u8*)((char*)(lbl_803DCE6C + 14) + found * 16) = type;
        return found;
    }
    OSReport(sTrackGlobalTexanimOverflowError);
    return 0;
}

extern void audioStopByMask(int mask);
extern void doNothing_8001F678(int a, int b);
extern void textureFree(int id);
extern void fn_80133934(void);

void unloadMap(void)
{
    int blk;
    int i;
    int layer;
    s8* cur;
    int mapType;
    int j;
    int rb;
    char* p;
    int n;
    int k;

    audioStopByMask(4);
    Sfx_ClearLoopedObjectSounds();
    doNothing_8001F678(1, 0);
    for (layer = 0; layer < MAP_BLOCK_LAYER_COUNT; layer++)
    {
        cur = (s8*)gMapBlockLayerTables[layer];
        for (i = 0; i < 256; i++)
        {
            mapType = cur[i];
            if (mapType >= 0)
            {
                lbl_803DCE8C[mapType]--;
                if (lbl_803DCE8C[mapType] == 0)
                {
                    blk = lbl_803DCE9C[mapType];
                    lbl_803DCE94[mapType] = -1;
                    lbl_803DCE9C[mapType] = j = 0;
                    for (; j < *(u8*)(blk + 0xa2); j++)
                    {
                        rb = *(int*)(blk + 0x64) + j * 68;
                        p = (char*)rb;
                        for (k = 0; k < *(u8*)(rb + 0x41); k++)
                        {
                            u32 cell = *(u8*)(p + 0x2a);
                            if (cell != 0xff)
                            {
                                if (*(u8*)(lbl_803DCE68 + cell * 16 + 12) != 0)
                                    *(u8*)(lbl_803DCE68 + cell * 16 + 12) -= 1;
                            }
                            if (*(u8*)(p + 0x29) != 0)
                                mapTextureOverrideRelease(*(int*)(p + 0x24), *(u8*)(p + 0x29));
                            p += 8;
                        }
                    }
                    for (j = 0; j < *(u8*)(blk + 0xa0); j++)
                        textureFree(*(int*)(*(int*)(blk + 0x54) + j * 4));
                    if (*(void**)(blk + 0x74) != 0)
                        mm_free(*(void**)(blk + 0x74));
                    if (*(void**)(blk + 0x70) != 0)
                        mm_free(*(void**)(blk + 0x70));
                    setMapBlockFlag();
                    mm_free((void*)blk);
                }
            }
        }
    }
    lbl_803DCE98 = 0;
    Obj_ResetObjectSystem();
    for (n = 0; n < ROM_LIST_PAGE_COUNT; n++)
    {
        if (gLoadedRomListPages[n] != 0)
        {
            mm_free(gLoadedRomListPages[n]);
            gLoadedRomListPages[n] = 0;
        }
    }
    (*gCheckpointInterface)->reset();
    (*gRomCurveInterface)->initialise();
    gShaderRomListSlotCount = 0;
    playerMapOffsetX = lbl_803DEBCC;
    playerMapOffsetZ = lbl_803DEBCC;
    voxmaps_resetLoadedMaps();
    textureFreeFn_8012fcec();
    fn_80133934();
    (*gNewCloudsInterface)->killSnowCloud(-1, 0);
    (*gCloudActionInterface)->freeCloudObjects();
}

extern int gShaderMapRomBuffers[];
extern void loadAssetFileById(void* out, int id);
extern void* memset(void* p, int v, int n);

void initMaps(void)
{
    void* data;
    int total;
    int i;
    int i2;
    int ofs;
    int idx;
    int k;
    char* e;

    data = 0;
    total = getDataFileSize(0x15);
    loadAssetFileById(&data, 0x15);
    gShaderMapRomBuffers[0] = -1;
    gShaderMapRomBuffers[1] = (int)mmAlloc(1280, 5, 0);
    gShaderMapRomBuffers[2] = (int)mmAlloc(512, 5, 0);
    gShaderMapRomBuffers[3] = (int)mmAlloc(128, 5, 0);
    gShaderMapRomBuffers[4] = (int)mmAlloc(8192, 5, 0);
    memset((void*)gShaderMapRomBuffers[4], 0, 8192);
    idx = ofs = 0;
    for (i = 0; i < 16; i++)
    {
        e = (char*)gShaderMapRomBuffers[1] + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + idx) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[idx << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(idx << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 10 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 1)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 20 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 2)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 30 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 3)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 40 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 4)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 50 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 5)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 60 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 6)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        e = (char*)gShaderMapRomBuffers[1] + 70 + ofs;
        *(s8*)((char*)gShaderMapRomBuffers[3] + (k = idx + 7)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)gShaderMapRomBuffers[2])[k << 1] = -1;
        ((s16*)gShaderMapRomBuffers[2])[(k << 1) + 1] = -1;
        ofs += 80;
        idx += 8;
    }
    i2 = 0;
    total = total / 12;
    while (i2 < total && *(s16*)((char*)data + i2 * 12 + 6) > -1)
    {
        *(s8*)((char*)gShaderMapRomBuffers[3] + *(s16*)((char*)data + i2 * 12 + 6)) =
            (s8) * (s16*)((char*)data + i2 * 12 + 4);
        mapInitSetRects((s16*)((char*)gShaderMapRomBuffers[1] + *(s16*)((char*)data + i2 * 12 + 6) * 10),
                        (u8*)((char*)gShaderMapRomBuffers[4] + *(s16*)((char*)data + i2 * 12 + 6) * 64),
                        *(s16*)((char*)data + i2 * 12), *(s16*)((char*)data + i2 * 12 + 2),
                        *(s16*)((char*)data + i2 * 12 + 6));
        ((s16*)gShaderMapRomBuffers[2])[*(s16*)((char*)data + i2 * 12 + 6) << 1] =
            *(s16*)((char*)data + i2 * 12 + 8);
        ((s16*)gShaderMapRomBuffers[2])[(*(s16*)((char*)data + i2 * 12 + 6) << 1) + 1] =
            *(s16*)((char*)data + i2 * 12 + 0xa);
        i2++;
    }
    curMapType = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
    mm_free(data);
}

void mapFn_80057d24(int a, int b, int* o0, int* o1, int* o2, int* o3, int f1, int f2, int idx)
{
    int base;
    s16* e2;
    int aa, bb;
    int ptr0;
    int tbl, tbl2;
    int index;
    int idx2;
    u32 v, v2;
    int cellVal;

    if (idx == -1)
    {
        o0[0] = -1;
        o0[1] = 1;
        o0[2] = -1;
        o0[3] = 1;
        o1[0] = 0;
        o1[1] = 0;
        o1[2] = 0;
        o1[3] = -1;
        o2[0] = 0;
        o2[1] = 0;
        o2[2] = 0;
        o2[3] = -1;
        o3[0] = 0;
        o3[1] = 0;
        o3[2] = 0;
        o3[3] = -1;
        if (f1 != 0)
            o0[3] = -2;
        return;
    }
    base = gShaderMapRomBuffers[1];
    e2 = (s16*)(base + gShaderRomListSlots[idx].field_4 * 10);
    aa = a - e2[0];
    bb = b - e2[2];
    ptr0 = gShaderRomListSlots[idx].field_0;
    if (idx == -1)
    {
        o0[0] = -1;
        o0[1] = 1;
        o0[2] = -1;
        o0[3] = 1;
        o1[0] = 0;
        o1[1] = 0;
        o1[2] = 0;
        o1[3] = -1;
        o2[0] = 0;
        o2[1] = 0;
        o2[2] = 0;
        o2[3] = -1;
        o3[0] = 0;
        o3[1] = 0;
        o3[2] = 0;
        o3[3] = -1;
        if (f1 != 0)
            o0[3] = -2;
        return;
    }
    if (f2 != 0)
    {
        tbl = *(int*)(ptr0 + 0x30);
        tbl2 = *(int*)(ptr0 + 0x34);
    }
    else
    {
        tbl = *(int*)(ptr0 + 0x14);
        tbl2 = *(int*)(ptr0 + 0x2c);
    }
    index = aa + bb * *(s16*)ptr0;
    idx2 = index * 2;
    if (f1 == 0)
    {
        v = *(int*)(tbl + idx2 * 4);
        o0[0] = ((v >> 12) & 0xf) - 7;
        o0[2] = ((v >> 8) & 0xf) - 7;
        o0[1] = ((v >> 4) & 0xf) - 7;
        o0[3] = (v & 0xf) - 7;
        o1[0] = (v >> 28) - 7;
        o1[2] = ((v >> 24) & 0xf) - 7;
        o1[1] = ((v >> 20) & 0xf) - 7;
        o1[3] = ((v >> 16) & 0xf) - 7;
        v2 = *(int*)((tbl + 4) + idx2 * 4);
        o2[0] = ((v2 >> 12) & 0xf) - 7;
        o2[2] = ((v2 >> 8) & 0xf) - 7;
        o2[1] = ((v2 >> 4) & 0xf) - 7;
        o2[3] = (v2 & 0xf) - 7;
        o3[0] = (v2 >> 28) - 7;
        o3[2] = ((v2 >> 24) & 0xf) - 7;
        o3[1] = ((v2 >> 20) & 0xf) - 7;
        o3[3] = ((v2 >> 16) & 0xf) - 7;
    }
    else
    {
        o0[0] = 0;
        o0[1] = -1;
        o0[2] = 0;
        o0[3] = -1;
        o1[0] = 0;
        o1[1] = -1;
        o1[2] = 0;
        o1[3] = -1;
        o2[0] = 0;
        o2[1] = -1;
        o2[2] = 0;
        o2[3] = -1;
        o3[0] = 0;
        o3[1] = -1;
        o3[2] = 0;
        o3[3] = -1;
        cellVal = *(int*)(*(int*)(ptr0 + 0xc) + (idx2 >> 1) * 4) & 0x7f;
        if (cellVal != 127)
        {
            v2 = ((int*)tbl2)[f1 - 1 + cellVal * 4];
            o0[0] = ((v2 >> 12) & 0xf) - 7;
            o0[2] = ((v2 >> 8) & 0xf) - 7;
            o0[1] = ((v2 >> 4) & 0xf) - 7;
            o0[3] = (v2 & 0xf) - 7;
            o1[0] = (v2 >> 28) - 7;
            o1[2] = ((v2 >> 24) & 0xf) - 7;
            o1[1] = ((v2 >> 20) & 0xf) - 7;
            o1[3] = ((v2 >> 16) & 0xf) - 7;
        }
    }
}

#pragma dont_inline on
int mapCoordsToId(int x, int z, int layerIdx)
{
    int x0, z0;
    s8* layers;
    int x1;
    s16* rects;
    u8* bits;
    int id;
    int layer;
    int idx;

    layer = curMapLayer + (&lbl_803DB624)[layerIdx];
    rects = (s16*)gShaderMapRomBuffers[1];
    bits = (u8*)gShaderMapRomBuffers[4];
    id = 0;
    layers = (s8*)gShaderMapRomBuffers[3];
    for (; id < 128; id++)
    {
        if (layer == layers[0])
        {
            x0 = rects[0];
            if (x >= x0)
            {
                x1 = rects[1];
                if (x <= x1)
                {
                    z0 = rects[2];
                    if (z >= z0 && z <= rects[3])
                    {
                        idx = (x - x0) + (z - z0) * ((x1 - x0) + 1);
                        if ((1 << (idx & 7)) & bits[idx >> 3])
                            return id;
                    }
                }
            }
        }
        rects += 5;
        bits += 0x40;
        layers += 1;
    }
    return -1;
}
#pragma dont_inline reset

extern f32 sAabbCornerDirections[];

void frustumPlanes_updateAabbCornerIndices(FrustumPlane* planes, int count)
{
    int k;
    int j;
    int bi;
    f32 best;
    f32 v;

    for (k = 0; k < count; k++)
    {
        best = lbl_803DEBCC;
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

int mapRectFn_8005a728(int bx, int bz, char* obj)
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
    if (obj)
    {
        y0 = (f32) * (s16*)(obj + 0x8a);
        y1 = (f32) * (s16*)(obj + 0x8c);
    }
    else
    {
        y0 = lbl_803DEBEC;
        y1 = PreCB;
    }
    plane = (FrustumPlane*)gViewFrustumPlanes;
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
            if (v > lbl_803DEBCC)
                hit = 1;
            j++;
        }
        if (j == 8 && hit == 0)
            return 0;
    }
    return 1;
}

void defStartFn_8005972c(char* p, u32* tbl, int idx, int flag)
{
    char* cur;
    int count;
    int pos;
    u8 found;
    u32 mask;
    int* q;
    int j;
    int m;
    int v;
    s16 t;
    int step;
    int n2;

    found = 0;
    mask = 0;
    cur = *(char**)(p + 0x20);
    count = *(u16*)(p + 8);
    if (count != 0)
    {
        pos = 0;
        if (flag == 0)
        {
            tbl[0x21] = -1;
            tbl[0] = -1;
            tbl[1] = -1;
            tbl[2] = -1;
            tbl[3] = -1;
            tbl[4] = -1;
            tbl[5] = -1;
            tbl[6] = -1;
            tbl[7] = -1;
            tbl[8] = -1;
            tbl[9] = -1;
            tbl[10] = -1;
            tbl[11] = -1;
            tbl[12] = -1;
            tbl[13] = -1;
            tbl[14] = -1;
            tbl[15] = -1;
            tbl[16] = -1;
            tbl[17] = -1;
            tbl[18] = -1;
            tbl[19] = -1;
            tbl[20] = -1;
            tbl[21] = -1;
            tbl[22] = -1;
            tbl[23] = -1;
            tbl[24] = -1;
            tbl[25] = -1;
            tbl[26] = -1;
            tbl[27] = -1;
            tbl[28] = -1;
            tbl[29] = -1;
            tbl[30] = -1;
            tbl[31] = -1;
        }
        for (; pos < count;)
        {
            if (flag != 0)
            {
                if (*(s16*)cur == 110)
                    (*gRomCurveInterface)->addCurveDef((RomCurveDef*)cur);
                if (*(s16*)cur == 5)
                    (*gCheckpointInterface)->removeRouteEntry((CheckpointRouteEntry*)cur);
            }
            else
            {
                t = *(s16*)cur;
                if (t == 110 || t == 5)
                {
                    if (t == 110)
                        (*gRomCurveInterface)->remove((RomCurveDef*)cur);
                    else
                        (*gCheckpointInterface)->addRouteEntry((CheckpointRouteEntry*)cur);
                    if (found == 0)
                    {
                        tbl[0x21] = (int)cur - *(int*)(p + 0x20);
                        found = 1;
                    }
                }
                else if (*(u8*)(cur + 4) & 0x10)
                {
                    if ((mask & (1 << *(u8*)(cur + 6))) == 0)
                    {
                        tbl[*(u8*)(cur + 6)] = (int)cur - *(int*)(p + 0x20);
                        mask |= 1 << *(u8*)(cur + 6);
                    }
                }
            }
            step = *(u8*)(cur + 2) * 4;
            pos += step;
            cur += step;
        }
        if (flag == 0)
        {
            m = count;
            v = tbl[0x21];
            if (v != -1 && v < count)
                m = v;
            j = 0;
            for (n2 = 0; n2 < 4; n2++, j += 7)
            {
                q = (int*)tbl + j + n2;
                v = q[0];
                if (v != -1 && v < m)
                    m = v;
                v = q[1];
                if (v != -1 && v < m)
                    m = v;
                v = q[2];
                if (v != -1 && v < m)
                    m = v;
                v = q[3];
                if (v != -1 && v < m)
                    m = v;
                v = q[4];
                if (v != -1 && v < m)
                    m = v;
                v = q[5];
                if (v != -1 && v < m)
                    m = v;
                v = q[6];
                if (v != -1 && v < m)
                    m = v;
                v = q[7];
                if (v != -1 && v < m)
                    m = v;
            }
            tbl[0x22] = m;
            v = tbl[0x21];
            if (v != -1)
                tbl[0x20] = v;
            else
                tbl[0x20] = count;
        }
    }
}

extern f32 lbl_803DEBB8;
extern f32 lbl_803DEBD4;
extern f32 lbl_803DEBD8;
extern f32 lbl_803DEBDC;
extern f32 Vec_distance(f32* a, f32* b);
extern void Camera_ProjectWorldSphere( f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX, f32* outRadiusY, f32* outRadiusZ);

int objUpdateOpacity(char* obj)
{
    u8 op;
    char* ptr;
    int alpha;
    f32 range;
    f32 d;
    f32 near;
    int* player;
    u8 i;
    f32 o1, o2, o3;
    f32 sz;
    f32 o5, o6;
    f32 prod;
    f32 offZ, offX;

    op = ((GameObject*)obj)->anim.alpha;
    if (op == 0)
    {
        *(u8*)(obj + 0x37) = 0;
        return 0;
    }
    ptr = (void*)((GameObject*)obj)->anim.placementData;
    if (ptr != 0 && (*(u8*)(ptr + 5) & 1))
    {
        *(u8*)(obj + 0x37) = (u8)(((op + 1) * 255) >> 8);
    }
    else
    {
        range = *(f32*)(obj + 0x40);
        if (range < lbl_803DEBB8)
        {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        player = Obj_GetPlayerObject();
        if (ptr != 0 && (*(u8*)(ptr + 5) & 2) && player != 0)
        {
            d = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
        }
        else
        {
            d = Camera_DistanceToCurrentViewPosition(((GameObject*)obj)->anim.worldPosX,
                                                     ((GameObject*)obj)->anim.worldPosY,
                                                     ((GameObject*)obj)->anim.worldPosZ);
        }
        if (d > range)
        {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        alpha = 255;
        near = range - lbl_803DEBD4;
        if (d > near)
        {
            range = range - near;
            d = d - near;
            alpha = (int)(lbl_803DEBD8 * (lbl_803DEBDC - d / range));
        }
        Camera_ProjectWorldSphere(((GameObject*)obj)->anim.worldPosX - playerMapOffsetX,
                                  ((GameObject*)obj)->anim.worldPosY,
                                  ((GameObject*)obj)->anim.worldPosZ - playerMapOffsetZ,
                                  ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale,
                                  &o1, &o2, &o3, &sz, &o5, &o6);
        sz = __fabsf(sz);
        sz = sz * gMapBlockWorldSize;
        if (sz < retraceCount_803DEBE0)
        {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        if (sz < retraceQueue_803DEBE8)
        {
            alpha = (int)(((f32)alpha * (sz - retraceCount_803DEBE0)) / flushFlag_803DEBE4);
        }
        *(u8*)(obj + 0x37) = (u8)((alpha * (((GameObject*)obj)->anim.alpha + 1)) >> 8);
    }
    if (*(u8*)(obj + 0x37) == 0)
    {
        return 0;
    }
    else
    {
        prod = ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale;
        offZ = playerMapOffsetZ;
        offX = playerMapOffsetX;
        for (i = 0; i < FRUSTUM_PLANE_COUNT; i++)
        {
            FrustumPlane* plane = (FrustumPlane*)(gViewFrustumPlanes + i * sizeof(FrustumPlane));
            if (prod
                + (plane->distance
                    + (plane->normalZ * (((GameObject*)obj)->anim.worldPosZ - offZ)
                        + (((GameObject*)obj)->anim.worldPosY * plane->normalY
                            + plane->normalX * (((GameObject*)obj)->anim.worldPosX - offX)))) <
                *(f32*)&lbl_803DEBCC)
                return 0;
        }
    }
    return 1;
}

extern void* ObjList_GetObjects(int* outA, int* outB);
extern int objShouldUnload(char* obj);
extern void Obj_FreeObject(char* obj);
extern int getLoadedFileFlags(int file);
extern int SaveGame_findTransientMapBit(int mapId, int bit);
extern void mapInstantiateObjects(char* page, int mapId, int bit, char* obj);
extern void mapClearBit(int mapId, int bit);
extern void Obj_SetupObject(u32 setup, int a, int b, int c, char* d);

#pragma opt_propagation off
void mapLoadUnloadObjects(int flag)
{
    int b;
    int k;
    int i;
    int n;
    s16 list[8];
    s16* q;
    char* base;
    s16 count;
    char* obj;
    char* fp;
    int unload;
    u32 bits;
    int* tp;
    int bit;
    u32 cur;
    u32 end;
    u32 o;
    u8* bp;
    u8 m;
    int vis;
    int idx;

    base = lbl_8037E0C0;
    count = 0;
    tp = (int*)(base + 0x41E0);
    for (i = 0; i < 5; i++)
    {
        k = 0;
        q = (s16*)(*tp + 0x594);
        for (; k < 3; k++)
        {
            s16 id = *q;
            if (id >= 0 && id < 80 && *(void**)(base + (0x83A8 + id * 4)) != 0)
            {
                s16 dup = 0;
                s16* w = list;
                int j2;
                for (j2 = 0; j2 < count; j2++)
                {
                    if (*w == id)
                    {
                        dup = 1;
                        break;
                    }
                    w++;
                }
                if (dup == 0)
                    list[count++] = id;
            }
            q++;
        }
        tp++;
    }
    {
        int* objs = ObjList_GetObjects(&i, &n);
        while (i < n)
        {
            obj = (char*)objs[i];
            fp = (void*)((GameObject*)obj)->anim.placementData;
            i++;
            unload = 0;
            if (((GameObject*)obj)->anim.mapEventSlot > -1)
            {
                u8 fl = *(u8*)(fp + 4);
                if (!(fl & 2))
                {
                    if (fl & 0x10)
                    {
                        if (((GameObject*)obj)->anim.classId > -1 && objShouldUnload(obj))
                        {
                            unload = 1;
                        }
                        else if (((GameObject*)obj)->anim.mapEventSlot < 80 &&
                            *(void**)(base + (0x83A8 + ((GameObject*)obj)->anim.mapEventSlot * 4)) == 0)
                        {
                            unload = 1;
                        }
                    }
                    else
                    {
                        if (((GameObject*)obj)->anim.classId > -1 && objShouldUnload(obj))
                        {
                            unload = 1;
                        }
                        else if (((GameObject*)obj)->anim.mapEventSlot < 80 &&
                            ((GameObject*)obj)->anim.mapEventSlot != gShaderCurMapEventId)
                        {
                            unload = 1;
                        }
                    }
                }
            }
            if (unload)
            {
                char* page = *(char**)(base + (0x83A8 + ((GameObject*)obj)->anim.mapEventSlot * 4));
                if (page != 0)
                {
                    s16 tbit = *(s16*)(obj + 0xB2);
                    if (tbit >= 0 && tbit >= 0)
                    {
                        u8* bb = *(u8**)(page + 0x10);
                        *(s8*)&bb[tbit >> 3] = bb[tbit >> 3] & ~(1 << (tbit & 7));
                    }
                }
                if (((GameObject*)obj)->anim.seqId == 0x72)
                {
                    s8 mid = ((GameObject*)obj)->anim.mapEventSlot;
                    s16 j3 = 0;
                    s16* w2 = list;
                    for (j3 = 0; j3 < count; j3++)
                    {
                        if (mid == *w2)
                            break;
                        w2++;
                    }
                }
                Obj_FreeObject(obj);
                i--;
                n--;
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
                    b = 0;
                    while (bits != 0)
                    {
                        if ((bits & 1) && (s8)SaveGame_findTransientMapBit(i, b) == -1)
                        {
                            mapInstantiateObjects(((char**)(base + 0x83A8))[i], i, b, 0);
                            mapClearBit(i, b);
                        }
                        bits >>= 1;
                        b++;
                    }
                }
            }
        }
        for (i = 0; i < count; i++)
        {
            int id2 = list[i];
            if (gShaderCurMapEventId == id2)
            {
                char* page = *(char**)(base + (0x83A8 + id2 * 4));
                if (page != 0)
                {
                    m = 1;
                    bit = 0;
                    cur = *(u32*)(page + 0x20);
                    bp = *(u8**)(page + 0x10);
                    end = cur + *(int*)(base + (0x4290 + id2 * 0x8C));
                    while (cur < end)
                    {
                        o = cur;
                        if ((*bp & m) == 0 && objShouldLoad(cur, 0, list[i]) != 0)
                        {
                            if (bit >= 0)
                            {
                                char* pg = *(char**)(base + (0x83A8 + list[i] * 4));
                                int ix2 = bit >> 3;
                                int msk = 1 << (bit & 7);
                                *(s8*)(*(int*)(pg + 0x10) + ix2) =
                                    *(u8*)(*(int*)(pg + 0x10) + ix2) & ~msk;
                                *(s8*)(*(int*)(pg + 0x10) + ix2) =
                                    *(u8*)(*(int*)(pg + 0x10) + ix2) | msk;
                            }
                            Obj_SetupObject(o, 1, list[i], bit, 0);
                        }
                        bit++;
                        m = (u8)(m << 1);
                        if (m == 0)
                        {
                            bp++;
                            while (*bp == -1)
                            {
                                bit += 8;
                                cur += *(u8*)(o + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                o = cur;
                                bp++;
                            }
                            m = 1;
                        }
                        cur += *(u8*)(o + 2) * 4;
                    }
                }
            }
        }
        {
            int* objs2 = ObjGroup_GetObjects(6, &n);
            for (i = 0; i < n; i++)
            {
                char* obj2 = (char*)objs2[i];
                u32 mid2 = *(u8*)(obj2 + 0x34);
                char** slot = &((char**)(base + 0x83A8))[mid2];
                char* page2 = *slot;
                if (page2 != 0)
                {
                    s8 lp = *(s8*)(obj2 + 0x35) + 1;
                    bit = 0;
                    cur = *(u32*)(page2 + 0x20);
                    end = cur + *(int*)(base + (0x4290 + mid2 * 0x8C));
                    bits = (*gMapEventInterface)->getObjGroups(mid2);
                    if (bits != 0)
                    {
                        b = 0;
                        while (bits != 0)
                        {
                            if ((bits & 1) && (s8)SaveGame_findTransientMapBit(mid2, b) == -1)
                            {
                                mapInstantiateObjects(page2, mid2, b, obj2);
                            }
                            bits >>= 1;
                            mapClearBit(mid2, b);
                            b++;
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
                            char* pg2 = *slot;
                            idx = bit >> 3;
                            if (idx < 0xc4)
                            {
                                vis = 1;
                                if (((1 << (bit & 7)) &
                                    *(s8*)(*(int*)(pg2 + 0x10) + idx)) == 0)
                                    vis = 0;
                            }
                            else
                            {
                                vis = 0;
                            }
                        }
                        if (vis == 0 && objShouldLoad(cur, lp, mid2) != 0)
                        {
                            if (bit >= 0)
                            {
                                char* pg3 = *slot;
                                int ix3 = bit >> 3;
                                int msk3 = 1 << (bit & 7);
                                *(s8*)(*(int*)(pg3 + 0x10) + ix3) =
                                    *(u8*)(*(int*)(pg3 + 0x10) + ix3) & ~msk3;
                                *(s8*)(*(int*)(pg3 + 0x10) + ix3) =
                                    *(u8*)(*(int*)(pg3 + 0x10) + ix3) | msk3;
                            }
                            Obj_SetupObject(cur, 1, mid2, bit, obj2);
                        }
                        bit++;
                        cur += *(u8*)(cur + 2) * 4;
                    }
                }
            }
        }
    }
}
#pragma opt_propagation reset

extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern ModgfxInterface** gModgfxInterface;
extern int lbl_803DCDD0;
extern int lbl_803DCDD4;
extern int lbl_803DCDC8;
extern int lbl_803DCDCC;
extern f32 lbl_803DCED0;
extern f32 lbl_803DCECC;
extern int lbl_803DCEC0;
extern u8 lbl_803DCE04;
extern u8 bEnableBlurFilter;
extern u8 bEnableMotionBlur;
extern f32 lbl_803DB62C;
extern int lbl_803DCE00;
extern u8 lbl_803DCEBD;
extern f32 gShaderDefaultTimeOfDay;
extern void mapInitFn_8006fccc(void);
extern void setSaveGameLoadingFlag(void);
extern void clearSaveGameLoadingFlag(void);
extern void mapSetupPlayer(void);
extern void* saveGameGetEnvState(void);
extern void getEnvfxAct(void* obj, void* source, int actId, int flags);
extern void skyFn_80088c94(int flags, u8 mode);
extern void skyFn_80088e54(f32 a, int on);

void beginLoadingMap(void)
{
    char* base;
    int i;
    int j;
    s8* a;
    s8* b;
    int k2, k3;
    int mapKind;
    f32* p;
    f32 px, py, pz;
    int* cam;
    char* player;
    u8* env;
    int bo;
    char buf[0x110];

    base = lbl_8037E0C0;
    if (lbl_803DCEB8 == -1)
    {
        lbl_803DCEB8 = -2;
        lbl_803DCDE0 = 8;
    }
    (*gObjectTriggerInterface)->onMapSetup();
    mapInitFn_80069990();
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
        *(s16*)((char*)lbl_803DCE94 + j * 2) = -1;
        *(int*)((char*)lbl_803DCE9C + j * 4) = 0;
    }
    lbl_803DCE98 = 0;
    gShaderRomListSlotCount = 0;
    mapKind = (*gMapEventInterface)->getCurChar();
    p = (f32*)(*gMapEventInterface)->getCurCharPos();
    lbl_803DCDD0 = fastFloorf(p[0] / gMapBlockWorldSize);
    lbl_803DCDD4 = fastFloorf(p[2] / gMapBlockWorldSize);
    *(f32*)(base + 0x8588) = p[0];
    *(f32*)(base + 0x858C) = p[1];
    *(f32*)(base + 0x8590) = p[2];
    *(int*)(base + 0x8594) = 1;
    lbl_803DCDC8 = lbl_803DCDD0 * 640;
    lbl_803DCDCC = *(volatile int*)&lbl_803DCDD4 * 640;
    playerMapOffsetX = lbl_803DCDC8;
    playerMapOffsetZ = lbl_803DCDCC;
    lbl_803DCED0 = playerMapOffsetX;
    lbl_803DCECC = playerMapOffsetZ;
    gShaderCurMapEventId = -1;
    gShaderGameTextLoadedMapId = gShaderGameTextLoadedMapId - 1;
    lbl_803DCEC0 = -1;
    curMapLayer = *(s8*)((char*)p + 0xd);
    renderFlags &= 0x82008;
    renderFlags |= 0x481F0LL;
    renderFlags |= 0x804;
    lbl_803DCE04 = 0;
    bEnableBlurFilter = 0;
    bEnableMotionBlur = 0;
    lbl_803DB62C = lbl_803DEBCC;
    lbl_803DCE00 = -1;
    setSaveGameLoadingFlag();
    pz = p[2];
    py = p[1];
    px = p[0];
    if (!(renderFlags & 2) || (renderFlags & 0x800))
    {
        gShaderLoadCenterX = px;
        gShaderLoadCenterY = py;
        gShaderLoadCenterZ = pz;
        renderFlags |= 2;
        if (renderFlags & 0x800)
            doPendingMapLoads();
    }
    renderFlags &= ~4LL;
    trackIntersect();
    cam = Camera_GetCurrentViewSlot();
    ((GameObject*)cam)->anim.localPosX = p[0];
    ((GameObject*)cam)->anim.localPosY = p[1];
    ((GameObject*)cam)->anim.localPosZ = p[2];
    mapSetupPlayer();
    lbl_803DCEBD = 0;
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
    mapInitFn_8006fccc();
    player = (char*)Obj_GetPlayerObject();
    if (lbl_803DCEB8 == -2 && player != 0 && (mapKind == 0 || mapKind == 1))
    {
        s16 cam2 = SaveGame_getCamActionNo();
        if (cam2 != -1)
        {
            (*gCameraInterface)->loadTriggeredCamAction(0, cam2, 1);
        }
        env = saveGameGetEnvState();
        {
            s16 v = *(s16*)(env + 4);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = *(s16*)(env + 6);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = *(s16*)(env + 0xa);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = *(s16*)(env + 0xc);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
        }
        skyFn_80088c94(1, (*(u8*)(env + 0x40) & 2) ? 1 : 0);
        skyFn_80088c94(2, (*(u8*)(env + 0x40) & 4) ? 1 : 0);
        skyFn_80088e54(lbl_803DEBCC, (*(u8*)(env + 0x40) & 0x10) ? 1 : 0);
        if (*(u8*)(env + 0x40) & 1)
            bo = 1;
        else
            bo = 0;
        {
            u8* e2 = saveGameGetEnvState();
            if (bo)
            {
                renderFlags |= 0x50;
                *(u8*)(e2 + 0x40) = *(u8*)(e2 + 0x40) | 9;
            }
            else
            {
                renderFlags &= ~0x50;
                *(u8*)(e2 + 0x40) = *(u8*)(e2 + 0x40) & ~9;
            }
        }
        if (*(u8*)(env + 0x40) & 8)
            bo = 1;
        else
            bo = 0;
        {
            u8* e3 = saveGameGetEnvState();
            if (bo)
            {
                renderFlags |= 0x40;
                *(u8*)(e3 + 0x40) = *(u8*)(e3 + 0x40) | 8;
            }
            else
            {
                renderFlags &= ~0x40LL;
                *(u8*)(e3 + 0x40) = *(u8*)(e3 + 0x40) & ~8;
            }
        }
        if (*(u8*)(env + 0x40) & 0x20)
            lbl_803DCE00 = 1;
        else
            lbl_803DCE00 = -1;
        *(int*)(buf + 0x30) = 0;
        *(f32*)(buf + 0xc) = lbl_803DEBCC;
        *(f32*)(buf + 0x10) = lbl_803DEBCC;
        *(f32*)(buf + 0x14) = lbl_803DEBCC;
        *(f32*)(buf + 0x18) = lbl_803DEBCC;
        *(f32*)(buf + 0x1c) = lbl_803DEBCC;
        *(f32*)(buf + 0x20) = lbl_803DEBCC;
        {
            s16 a1 = *(s16*)(env + 0xe);
            if (a1 != -1)
            {
                *(f32*)(buf + 0xc) = (f32) * (int*)(env + 0x14);
                *(f32*)(buf + 0x10) = (f32) * (int*)(env + 0x18);
                *(f32*)(buf + 0x14) = (f32) * (int*)(env + 0x1c);
                getEnvfxAct(buf, player, a1 & 0xFFFF, 0);
            }
            a1 = *(s16*)(env + 0x10);
            if (a1 != -1)
            {
                *(f32*)(buf + 0xc) = (f32) * (int*)(env + 0x20);
                *(f32*)(buf + 0x10) = (f32) * (int*)(env + 0x24);
                *(f32*)(buf + 0x14) = (f32) * (int*)(env + 0x28);
                getEnvfxAct(buf, player, a1 & 0xFFFF, 0);
            }
            a1 = *(s16*)(env + 0x12);
            if (a1 != -1)
            {
                *(f32*)(buf + 0xc) = (f32) * (int*)(env + 0x2c);
                *(f32*)(buf + 0x10) = (f32) * (int*)(env + 0x30);
                *(f32*)(buf + 0x14) = (f32) * (int*)(env + 0x34);
                getEnvfxAct(buf, player, a1 & 0xFFFF, 0);
            }
        }
        (*gSkyInterface)->setTimeOfDay(*(f32*)env);
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

extern void setForceLoadImmediately(void);
extern void clearForceLoadImmediately(void);
extern void loadModelAndAnimTabs(void);

extern char sTrackPiLockedFormat[];
extern int lbl_803DCE88;
extern int lbl_803DCE1C;
extern int* lbl_803DCDE4;
extern int lbl_803DCEB0;
extern s16 lbl_803DCE70;
extern u8 lbl_803DCDED;

void doPendingMapLoads(void)
{
    s16* p5;
    u8 waited;
    int slot;
    s16* p7;
    int gx, gz;
    int row;
    int layer;
    int cell;
    int i;
    char* base;
    s16* p13;
    int col;
    int doLoad;
    int cnt;
    int* o1;
    f32 dz;
    int* eBase;
    int* aBase;
    int* cBase;
    s16 recs[1200];
    int oa[4], ob[4], oc[4], od[4];

    base = lbl_8037E0C0;
    waited = 0;
    if (!(renderFlags & 0x1000))
    {
        lbl_803DCED0 = playerMapOffsetX;
        lbl_803DCECC = playerMapOffsetZ;
        if (gShaderCurMapEventId != -1 && gShaderCurMapEventId != gShaderGameTextLoadedMapId &&
            (gShaderGameTextLoadedMapId = gShaderCurMapEventId, gShaderCurMapEventId < 118) &&
            gShaderMapTextDirTable[gShaderCurMapEventId] != -1)
        {
            gameTextLoadDir(gShaderMapTextDirTable[gShaderCurMapEventId]);
        }
        if (!(renderFlags & 2) && (getLoadedFileFlags(0) != 0 || lbl_803DCE1C == 0))
        {
            lbl_803DCE1C = getLoadedFileFlags(0);
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
                        lbl_803DCE04 = 1;
                    }
                }
                else
                {
                    if (lbl_803DCE04 != 0)
                    {
                        lbl_803DCE04 = 0;
                        doLoad = 1;
                    }
                }
            }
            if (gx != 7 || gz != 7 || doLoad != 0 || (renderFlags & 0x4000))
            {
                setShadowFlag_803db658(1);
                doNothing_8001F678(1, 0);
                cnt = 0;
                layer = 0;
                eBase = (int*)(base + 0x41E0);
                aBase = (int*)(base + 0x41F4);
                cBase = (int*)(base + 0x41CC);
                {
                    int* bp2 = eBase;
                    int* ap2 = aBase;
                    int* cp2 = cBase;
                    int k8;
                    s8 c;
                    p13 = recs;
                    for (layer = 0; layer < 5; layer++)
                    {
                        s16* ent = (s16*)*bp2;
                        char* g = (char*)*ap2;
                        lbl_803DCE88 = *cp2;
                        cell = 0;
                        row = 0;
                        p7 = p13;
                        for (row = 0; row < 16; row++)
                        {
                            col = 0;
                            p5 = p7;
                            for (k8 = 0; k8 < 8; k8++)
                            {
                                c = g[0];
                                if (c > -1)
                                {
                                    p5[0] = lbl_803DCDD0 + col;
                                    p5[1] = lbl_803DCDD4 + row;
                                    p5[3] = layer;
                                    p5[2] = c;
                                    p5 += 4;
                                    p7 += 4;
                                    p13 += 4;
                                    cnt++;
                                }
                                g[0] = -2;
                                *(s8*)(lbl_803DCE88 + cell) = -1;
                                ent[3] = -3;
                                ent[0] = -1;
                                ent[1] = -1;
                                ent[2] = -1;
                                cell = cell + 1;
                                col = col + 1;
                                c = g[1];
                                if (c > -1)
                                {
                                    p5[0] = lbl_803DCDD0 + col;
                                    p5[1] = lbl_803DCDD4 + row;
                                    p5[3] = layer;
                                    p5[2] = c;
                                    p5 += 4;
                                    p7 += 4;
                                    p13 += 4;
                                    cnt++;
                                }
                                g[1] = -2;
                                *(s8*)(lbl_803DCE88 + cell) = -1;
                                ent[9] = -3;
                                ent[6] = -1;
                                ent[7] = -1;
                                ent[8] = -1;
                                ent += 12;
                                cell = cell + 1;
                                g += 2;
                                col = col + 1;
                            }
                        }
                        bp2++;
                        ap2++;
                        cp2++;
                    }
                }
                lbl_803DCDD0 = (gx + lbl_803DCDD0) - 7;
                lbl_803DCDD4 = (gz + lbl_803DCDD4) - 7;
                playerMapOffsetX = gMapBlockWorldSize * lbl_803DCDD0;
                playerMapOffsetZ = gMapBlockWorldSize * lbl_803DCDD4;
                lbl_803DCDC8 = playerMapOffsetX;
                lbl_803DCDCC = playerMapOffsetZ;
                {
                    s8* sp = (s8*)(base + 0x418C);
                    int slotN = gShaderRomListSlotCount;
                    i = 0;
                    for (; i < slotN; i++)
                    {
                        sp[i * 8 + 6] = 0;
                    }
                }
                gShaderCurMapEventId = mapCoordsToId(lbl_803DCDD0 + 7, lbl_803DCDD4 + 7, 0);
                lbl_803DCEC0 = -1;
                if (gShaderCurMapEventId == -1)
                {
                    int d = mapGetDirIdx(41);
                    setForceLoadImmediately();
                    mapLoadDataFile(d, 32);
                    mapLoadDataFile(d, 35);
                    mapLoadDataFile(d, 48);
                    mapLoadDataFile(d, 43);
                    mapLoadDataFile(d, 33);
                    mapLoadDataFile(d, 42);
                    mapLoadDataFile(d, 47);
                    mapLoadDataFile(d, 36);
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
                        {
                            int m = gShaderCurMapEventId;
                            int i2 = 0;
                            char* p2 = base + 0x418C;
                            int cn = gShaderRomListSlotCount;
                            int k;
                            for (k = 0; k < cn; k++)
                            {
                                if (*(void**)p2 != NULL && m == *(s16*)(p2 + 4))
                                    goto found;
                                p2 += 8;
                                i2++;
                            }
                            i2 = -1;
                        found:
                            slot = i2;
                        }
                        if (slot == -1)
                            slot = mapProcessRomList(gShaderCurMapEventId);
                        {
                            int m2 = gShaderCurMapEventId;
                            u32 sz = getDataFileSize(0x1f);
                            if (m2 < 0 || m2 >= (int)(sz >> 5))
                            {
                                curMapType = 0;
                            }
                            else
                            {
                                u8* e = lbl_803DCE78;
                                getTabEntry(e, 0x1f, m2 << 5, 0x20);
                                *(u8*)&curMapType = e[0x1c];
                            }
                        }
                        *(s8*)(base + slot * 8 + 0x4192) = 1;
                        lbl_803DCEC0 = slot;
                        mapGetDirIdx(gShaderCurMapEventId);
                        mapCheckCurBlocks(0);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), 38);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), 37);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), 26);
                        mapLoadDataFile(mapGetDirIdx(gShaderCurMapEventId), 27);
                        lbl_803DCDE4 = (int*)getCurrentDataFile(38);
                        lbl_803DCEB0 = 0;
                        {
                            int* p3;
                            for (p3 = lbl_803DCDE4; lbl_803DCDE4 != 0 && *p3 != -1; p3++)
                            {
                                lbl_803DCEB0 = lbl_803DCEB0 + 1;
                            }
                        }
                        lbl_803DCEB0 = lbl_803DCEB0 - 1;
                        {
                            int* tp2 = eBase;
                            for (i = 0; i < 5; i++)
                            {
                                char* g2 = (char*)*tp2;
                                int t2 = 0;
                                int k2;
                                for (k2 = 0; k2 < 2; k2++)
                                {
                                    g2 += 0x540;
                                    t2 += 7;
                                }
                                tp2++;
                            }
                        }
                        {
                            int d2 = mapGetDirIdx(gShaderCurMapEventId);
                            mapLoadDataFile(d2, 32);
                            mapLoadDataFile(d2, 35);
                            mapLoadDataFile(d2, 48);
                            mapLoadDataFile(d2, 43);
                            mapLoadDataFile(d2, 13);
                            mapLoadDataFile(d2, 33);
                            mapLoadDataFile(d2, 42);
                            mapLoadDataFile(d2, 47);
                            mapLoadDataFile(d2, 36);
                            mapLoadDataFile(d2, 14);
                        }
                        loadModelAndAnimTabs();
                        {
                            int* ap3 = aBase;
                            int* cp3 = cBase;
                            for (layer = 0; layer < 5; layer++)
                            {
                                char* g3;
                                int zz, xx;
                                s8 cnt2;
                                mapFn_80057d24(lbl_803DCDD0 + 7, lbl_803DCDD4 + 7, oa, ob, oc, od,
                                               layer, 0, slot);
                                g3 = (char*)*ap3;
                                lbl_803DCE88 = *cp3;
                                for (zz = oa[2]; zz <= oa[3]; zz++)
                                {
                                    char* gp = g3 + oa[0] + (zz + 7) * 16;
                                    for (xx = oa[0]; xx <= oa[1]; xx++)
                                    {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                for (zz = ob[2]; zz <= ob[3]; zz++)
                                {
                                    char* gp = g3 + ob[0] + (zz + 7) * 16;
                                    for (xx = ob[0]; xx <= ob[1]; xx++)
                                    {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                for (zz = oc[2]; zz <= oc[3]; zz++)
                                {
                                    char* gp = g3 + oc[0] + (zz + 7) * 16;
                                    for (xx = oc[0]; xx <= oc[1]; xx++)
                                    {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                for (zz = od[2]; zz <= od[3]; zz++)
                                {
                                    char* gp = g3 + od[0] + (zz + 7) * 16;
                                    for (xx = od[0]; xx <= od[1]; xx++)
                                    {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                {
                                    s8 cn2 = 0;
                                    int cell2 = 0;
                                    char* gp2 = g3;
                                    int rr, cc;
                                    for (rr = 0; rr < 16; rr++)
                                    {
                                        for (cc = 0; cc < 16; cc++)
                                        {
                                            int bx = lbl_803DCDD0 + cc;
                                            int bz = lbl_803DCDD4 + rr;
                                            if (*(s8*)gp2 == -3)
                                            {
                                                if (mapLoadBlock(cc, rr, bx, bz, layer) == 0)
                                                {
                                                    *gp2 = -2;
                                                }
                                                else
                                                {
                                                    *(s8*)(lbl_803DCE88 + cell2) = cn2++;
                                                }
                                            }
                                            cell2++;
                                            gp2++;
                                        }
                                    }
                                }
                                ap3++;
                                cp3++;
                            }
                        }
                        clearForceLoadImmediately();
                    }
                }
                {
                    s8 first = 1;
                    int i3 = gShaderRomListSlotCount - 1;
                    char* p4 = base + 0x418C + i3 * 8;
                    for (; i3 >= 0; i3--)
                    {
                        if (*(s8*)(p4 + 6) == 0)
                        {
                            if (*(void**)p4 != NULL)
                            {
                                s16 sl = *(s16*)(p4 + 4);
                                defStartFn_8005972c(*(char**)p4, (u32*)(base + sl * 0x8C + 0x4208),
                                                    sl, 1);
                                mm_free(*(void**)p4);
                                ((int*)(base + 0x83A8))[sl] = 0;
                            }
                            *(int*)p4 = 0;
                            *(s16*)(p4 + 4) = -1;
                        }
                        if (first)
                        {
                            if (*(void**)p4 == NULL)
                                gShaderRomListSlotCount--;
                            else
                                first = 0;
                        }
                        p4 -= 8;
                    }
                }
                {
                    s16* rc = recs;
                    for (i = 0; i < cnt; i++)
                    {
                        s16 mid = rc[2];
                        if (mid >= 0)
                        {
                            *(u8*)(lbl_803DCE8C + mid) -= 1;
                            if (*(u8*)(lbl_803DCE8C + mid) == 0)
                            {
                                char* blk = (char*)*(int*)((char*)lbl_803DCE9C + mid * 4);
                                int off;
                                int j, k;
                                *(s16*)((char*)lbl_803DCE94 + mid * 2) = -1;
                                *(int*)((char*)lbl_803DCE9C + mid * 4) = 0;
                                off = 0;
                                for (j = 0; j < *(u8*)(blk + 0xa2); j++)
                                {
                                    char* ent2 = (char*)(*(int*)(blk + 100) + off);
                                    char* cur2 = ent2;
                                    for (k = 0; k < *(u8*)(ent2 + 0x41); k++)
                                    {
                                        if (*(u8*)(cur2 + 0x2a) != 0xFF)
                                        {
                                            int ix = *(u8*)(cur2 + 0x2a) * 16 + 12;
                                            u8 c2 = *(u8*)(lbl_803DCE68 + ix);
                                            if (c2 != 0)
                                                *(u8*)(lbl_803DCE68 + ix) = c2 - 1;
                                        }
                                        if (*(u8*)(cur2 + 0x29) != 0)
                                            mapTextureOverrideRelease(*(int*)(cur2 + 0x24),
                                                                      *(u8*)(cur2 + 0x29));
                                        cur2 += 8;
                                    }
                                    off += 0x44;
                                }
                                {
                                    int o2 = 0;
                                    for (j = 0; j < *(u8*)(blk + 0xa0); j++)
                                    {
                                        textureFree(*(int*)(*(int*)(blk + 0x54) + o2));
                                        o2 += 4;
                                    }
                                }
                                if (*(void**)(blk + 0x74) != NULL)
                                    mm_free(*(void**)(blk + 0x74));
                                if (*(void**)(blk + 0x70) != NULL)
                                    mm_free(*(void**)(blk + 0x70));
                                setMapBlockFlag();
                                mm_free(blk);
                            }
                        }
                        rc += 4;
                    }
                }
                lbl_803DCE70 = 0;
                lbl_803DCDED = 0;
            }
            mapLoadUnloadObjects(doLoad);
            lbl_803DCE1C = getLoadedFileFlags(0);
            renderFlags &= ~0x4000LL;
        }
    }
}

extern s16 lbl_803DCE90;
extern int lbl_803DCE84;

static inline int mapFindRomListSlot(char* p2, int id)
{
    int i2 = 0;
    char* q2 = p2;
    int cn = gShaderRomListSlotCount;
    int k;
    for (k = 0; k < cn; k++)
    {
        if (*(void**)q2 != NULL && id == *(s16*)(q2 + 4))
            return i2;
        q2 += 8;
        i2++;
    }
    return -1;
}

void mapBlockFn_80059354(int x, int z, s16* out, int layer)
{
    int id;
    int slot;
    int cv3, cv4;
    char* entry;
    s16* pairs;
    s16* rects;
    u32 v;
    int k;

    id = mapCoordsToId(x, z, layer);
    if (id != -1)
    {
        char* p2 = (char*)gShaderRomListSlots;
        char* p6;
        slot = mapFindRomListSlot(p2, id);
        if (slot == -1)
            slot = mapProcessRomList(id);
        p6 = p2 + 6;
        *(s8*)(p6 + slot * 8) = 1;
        entry = (char*)*(u32*)(p2 + slot * 8);
        pairs = (s16*)gShaderMapRomBuffers[2];
        cv3 = (s8)pairs[id << 1];
        cv4 = (s8)pairs[(id << 1) + 1];
        out[0] = id;
        out[1] = cv3;
        out[2] = cv4;
        if (cv3 != -1)
        {
            slot = mapFindRomListSlot(p2, cv3);
            if (slot == -1)
                slot = mapProcessRomList(cv3);
            *(s8*)(p6 + slot * 8) = 1;
        }
        if (cv4 != -1)
        {
            slot = mapFindRomListSlot(p2, cv4);
            if (slot == -1)
                slot = mapProcessRomList(cv4);
            *(s8*)(p6 + slot * 8) = 1;
        }
        rects = (s16*)(gShaderMapRomBuffers[1] + id * 10);
        x = x - rects[0];
        z = z - rects[2];
        v = *(u32*)(*(int*)(entry + 0xc) + (x + z * *(s16*)entry) * 4);
        *(s8*)((char*)out + 8) = (v >> 0x11) & 0x3f;
        *(s8*)((char*)out + 9) = (v >> 0x17) & 0xff;
        if (*(s8*)((char*)out + 9) == 0xFF)
            *(s8*)((char*)out + 9) = -1;
        if (*(s8*)((char*)out + 9) == -1)
        {
            out[3] = -1;
        }
        else
        {
            if (*(s8*)((char*)out + 9) >= lbl_803DCE90)
                *(s8*)((char*)out + 9) = lbl_803DCE90 - 1;
            out[3] = *(s8*)((char*)out + 8) + *(u16*)(lbl_803DCE84 + *(s8*)((char*)out + 9) * 2);
            if (out[3] >= *(u16*)(lbl_803DCE84 + lbl_803DCE90 * 2))
                out[3] = *(u16*)(lbl_803DCE84 + lbl_803DCE90 * 2) - 1;
        }
    }
    else
    {
        out[0] = -1;
        out[1] = -1;
        out[2] = -1;
        out[3] = -2;
        *(s8*)((char*)out + 9) = -1;
        *(s8*)((char*)out + 8) = 0;
    }
}

extern int gMapBlockLayerTables[];
extern void* lbl_803DCEA8;
extern int lbl_803DCE74;
extern char sTrackCellCoordFormat[];
extern void fn_80137948(char* fmt, ...);
extern void modelRenderInstrsState_init(int* state, int buf, int s1, int s2);

#pragma optimization_level 2
void mapDebugRender(int* state)
{
    int bx, bz;
    char* blk;
    s8* tbl;
    int sx, sz;
    int wx, wz;
    int ci;
    int y0;
    int y0a;
    f32 cy;
    int y1;
    int yy, dy, h;
    int step;
    int row, cx, cz;
    int cell;
    int v;
    int n;

    if (lbl_803DCDED != 0)
    {
        bx = fastFloorf((*(f32*)((char*)lbl_803DCEA8 + 0xc) - playerMapOffsetX) /
            gMapBlockWorldSize);
        bz = fastFloorf((*(f32*)((char*)lbl_803DCEA8 + 0x14) - playerMapOffsetZ) /
            gMapBlockWorldSize);
        tbl = (s8*)gMapBlockLayerTables[0];
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16)
        {
            blk = 0;
        }
        else
        {
            ci = tbl[bx + bz * 16];
            if (ci < 0 || ci >= lbl_803DCE98)
            {
                blk = 0;
            }
            else
            {
                blk = *(char**)((char*)lbl_803DCE9C + ci * 4);
            }
        }
        sx = (int)(gMapBlockWorldSize * fastFloorf(*(f32*)((char*)lbl_803DCEA8 + 0xc) /
            gMapBlockWorldSize));
        sz = (int)(gMapBlockWorldSize * fastFloorf(*(f32*)((char*)lbl_803DCEA8 + 0x14) /
            gMapBlockWorldSize));
        wx = (int)(*(f32*)((char*)lbl_803DCEA8 + 0xc) - sx);
        wz = (int)(*(f32*)((char*)lbl_803DCEA8 + 0x14) - sz);
        if (blk != 0)
        {
            y0 = *(s16*)(blk + 0x8a);
            y0a = y0;
            if (y0 & 1)
                y0a = y0 - 1;
            cy = *(f32*)((char*)lbl_803DCEA8 + 0x10);
            y1 = *(s16*)(blk + 0x8c);
            if (cy > y1)
                cy = (f32)(y1 - 1);
            yy = cy;
            dy = yy - y0a;
            h = y1 - y0;
            if (h / 80 < 8)
                step = h / 8;
            else
                step = 80;
            row = dy / step;
            cz = wz / 80;
            cx = wx / 80;
            cell = row * 0x40;
            cell += cz * 8;
            cell += cx;
            fn_80137948(sTrackCellCoordFormat);
            v = lbl_803DCE70;
            n = v >> 3;
            if (v & 7)
                n = n + 1;
            modelRenderInstrsState_init(state, lbl_803DCE74 + n * cell, v, v);
        }
    }
}
#pragma optimization_level reset
