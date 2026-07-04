#include "main/game_object.h"
#include "main/camera_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frustum.h"
#include "main/lightmap.h"
#include "main/newclouds.h"
#include "main/objlib.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXManage.h"
#include "main/sky_state.h"
#include "main/mm.h"
#include "string.h"
#include "main/newshadows.h"
#include "main/sfa_extern_decls.h"
#include "main/rcp_dolphin.h"
#include "main/dll/dll_0000_gameui.h"
extern u32 FUN_80006934();
extern u32 FUN_8000694c();
extern u32 FUN_80006974();
extern u32 FUN_80006984();
extern u32 FUN_80006988();
extern u32 FUN_80006994();
extern void* FUN_800069a8();
extern u32 FUN_800069bc();
extern u32 FUN_800069d4();
extern u32 FUN_800069f4();
extern u32 FUN_8001761c();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern u32 FUN_8003b878();
extern u32 FUN_8003d97c();
extern u32 FUN_8003f9f8();
extern u32 FUN_800404cc();
extern u32 FUN_800566ec();
extern int FUN_80057ce8();
extern u32 FUN_80057fd0();
extern u32 mapBlockRender_setVtxDcrs();
extern u32 FUN_8005fab0();
extern u32 FUN_8005fb68();
extern u32 FUN_80060a64();
extern u32 FUN_80061194();
extern u32 FUN_8006f09c();
extern u32 FUN_80071fb4();
extern u32 FUN_80080f88();
extern void* FUN_800e87a8();
extern u32 FUN_80247618();
extern u32 FUN_80247a48();
extern u32 FUN_80247bf8();
extern u32 FUN_802570dc();
extern u32 FUN_80257b5c();
extern u32 FUN_80259000();
extern u32 FUN_8025a2ec();
extern u32 FUN_8025a5bc();
extern u32 FUN_8025a608();
extern u32 FUN_80286818();
extern u32 FUN_80286830();
extern u32 FUN_80286864();
extern u32 FUN_8028687c();
extern u32 FUN_802924c4();
extern u8 FUN_80294c20();
extern u32 FUN_802950c4();
extern u32 builtin_strncpy();
extern u32 DAT_8037ed10;
extern int DAT_8037ed20;
extern u32 DAT_8037ed28;
extern u32 DAT_80382efc;
extern u32 DAT_80382f00;
extern int DAT_80382f14;
extern int DAT_80382f24;
extern int DAT_803870c8;
extern ModgfxInterface** gModgfxInterface;
extern u32* DAT_803dd718;
extern u32 DAT_803dda50;
extern u32 DAT_803dda54;
extern u32 DAT_803dda68;
extern u32 DAT_803ddab0;
extern u32 DAT_803ddb08;
extern u32 DAT_803ddb18;
extern u32 DAT_803ddb1c;
extern u32 DAT_803ddb24;
extern u32 DAT_803ddb28;
extern u32 DAT_803ddb40;
extern u32 DAT_cc008000;
extern f64 DOUBLE_803df840;
extern f32 lbl_803DC2D0;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDAD4;
extern f32 lbl_803DDAD8;
extern f32 lbl_803DF834;
extern f32 lbl_803DF89C;

typedef struct
{
    s16 rx, ry, rz, pad;
    f32 d4;
    f32 x, y, z;
} PosRot;

typedef struct
{
    f32 lo;
    f32 hi;
} F32Pair;

extern int Camera_GetCurrentViewSlot(void);
extern u32 renderFlags;
/* Global renderFlags bits (decoded by the accessor fns below: shouldDrawShadows,
 * shouldDrawClouds, getDrawDistanceFlag, isOvercast, setPendingMapLoad). */
#define RENDERFLAG_WIDESCREEN      0x8
#define RENDERFLAG_DRAW_CLOUDS     0x10
#define RENDERFLAG_DRAW_SHADOWS    0x80
#define RENDERFLAG_PENDING_MAP_LOAD 0x1000
#define RENDERFLAG_DRAW_DISTANCE   0x10000
#define RENDERFLAG_OVERCAST        0x40000

extern f32 Camera_GetFovY(void);
extern f32 encoderType_803DEBF8;
extern f32 displayOffsetH_803DEBFC;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DEBCC;
extern f32 lbl_803DEBDC;
extern f32 changeMode_803DEC00;
extern f32 gLightmapDegToBamScale;
extern F32Pair changed_803DEC08;
extern f32 lbl_803DEC0C;
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern FrustumPlane gViewFrustumPlanes[];
extern f32 fn_80293AC4(int v);
extern f32 fn_80293D0C(int v);
extern f32 sqrtf(f32 v);
extern f32 fn_80292248(f32 v);
extern float floor(float x);
extern float fn_802943F4(float x);

#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void updateVisibleGeometry(void)
{
    u8* cam;
    int n;
    f32 tt, ff, ss;
    f32 scale;
    f32 xx, yy, zz;
    f32 ratio, ratio2;
    u16 fov;
    f32 ox, oy, oz;
    PosRot st;
    f32 m[17];

    cam = (u8*)Camera_GetCurrentViewSlot();
    if ((renderFlags & RENDERFLAG_WIDESCREEN) != 0 || (renderFlags & RENDERFLAG_DRAW_DISTANCE) != 0)
    {
        scale = Camera_GetFovY() / encoderType_803DEBF8;
    }
    else
    {
        scale = Camera_GetFovY();
        scale *= displayOffsetH_803DEBFC;
    }
    xx = *(f32*)(cam + 0x44) - playerMapOffsetX;
    yy = *(f32*)(cam + 0x48);
    zz = *(f32*)(cam + 0x4c) - playerMapOffsetZ;
    st.x = lbl_803DEBCC;
    st.y = lbl_803DEBCC;
    st.z = lbl_803DEBCC;
    st.d4 = lbl_803DEBDC;
    st.rx = 0x8000 - *(s16*)(cam + 0x50);
    st.ry = -*(s16*)(cam + 0x52);
    st.rz = *(s16*)(cam + 0x54);
    setMatrixFromObjectPos(m, &st);
    Matrix_TransformPoint(m, lbl_803DEBCC, *(f32*)&lbl_803DEBCC, changeMode_803DEC00, &ox, &oy, &oz);
    gViewFrustumPlanes[0].normalX = ox;
    gViewFrustumPlanes[n = 0].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    gViewFrustumPlanes[n].distance = -(zz * oz + (xx * ox + yy * oy));
    fov = (int)(gLightmapDegToBamScale * scale) & 0xffff;
    tt = fn_80293AC4(fov);
    ratio = fn_80293D0C(fov) / tt;
    ratio2 = ratio * ratio;
    tt = changed_803DEC08.lo * ratio2;
    tt = fn_80292248(sqrtf(tt * changed_803DEC08.lo + ratio2));
    ff = floor(tt);
    ss = fn_802943F4(tt);
    Matrix_TransformPoint(m, ss, lbl_803DEBCC, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 1].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    gViewFrustumPlanes[n].distance = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, -ss, lbl_803DEBCC, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 2].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    gViewFrustumPlanes[n].distance = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, lbl_803DEBCC, -ss, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 3].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    gViewFrustumPlanes[n].distance = -(zz * oz + (xx * ox + yy * oy));
    Matrix_TransformPoint(m, lbl_803DEBCC, ss, -ff, &ox, &oy, &oz);
    gViewFrustumPlanes[n = 4].normalX = ox;
    gViewFrustumPlanes[n].normalY = oy;
    gViewFrustumPlanes[n].normalZ = oz;
    gViewFrustumPlanes[n].distance = -(zz * oz + (xx * ox + yy * oy));
    frustumPlanes_updateAabbCornerIndices((FrustumPlane*)gViewFrustumPlanes, 5);
}
#pragma opt_propagation reset

u32 FUN_8005af70(int idx)
{
    if ((-1 < idx) && (idx < (int)(u32)DAT_803ddb18))
    {
        return *(u32*)(DAT_803ddb1c + idx * 4);
    }
    return 0;
}

extern s16* lbl_803822A0[];
extern f32 gMapBlockWorldSize;
extern float fastFloorf(float x);
extern int lbl_803DCDD0;
extern int lbl_803DCDD4;

int coordsToMapCell(f32 x, f32 z)
{
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)lbl_803DCDD0);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)lbl_803DCDD4);
    if (ix < 0 || ix >= 16) return -1;
    if (iz < 0 || iz >= 16) return -1;
    return *(s16*)((char*)lbl_803822A0[0] + (ix + iz * 16) * 12);
}

int* fn_8005B11C(void)
{
    return &DAT_803870c8;
}

int FUN_8005b024(void)
{
    int cellZ;
    int cellX;
    double coord;

    coord = (double)FUN_802924c4();
    cellX = (int)(coord - (double)(f32)(s32)(DAT_803dda50));
    coord = (double)FUN_802924c4();
    cellZ = (int)(coord - (double)(f32)(s32)(DAT_803dda54));
    if ((cellX < 0) || (0xf < cellX))
    {
        cellX = -1;
    }
    else if ((cellZ < 0) || (0xf < cellZ))
    {
        cellX = -1;
    }
    else
    {
        cellX = (int)*(short*)(DAT_80382f00 + (cellX + cellZ * 0x10) * 0xc);
    }
    return cellX;
}

int FUN_8005b398(u64 arg1, double y)
{
    int block;
    int* layerTable;
    int cellX;
    int cellZ;
    double coord;
    u64 cvtTmp;

    coord = (double)FUN_802924c4();
    cellX = (int)(coord - (double)(f32)(s32)(DAT_803dda50));
    coord = (double)FUN_802924c4();
    cellZ = (int)(coord - (double)(f32)(s32)(DAT_803dda54));
    if ((((-1 < cellX) && (cellX < 0x10)) && (-1 < cellZ)) && (cellZ < 0x10))
    {
        cellX = cellX + cellZ * 0x10;
        layerTable = &DAT_80382f14;
        cellZ = 5;
        do
        {
            block = (int)*(char*)(cellX + *layerTable);
            if (-1 < block)
            {
                block = *(int*)(DAT_803ddb1c + block * 4);
                if (((double)(f32)(s32)((int)*(short*)(block + 0x8a) - 0x32U) < y) &&
                    (cvtTmp = (double)(int)*(short*)(block + 0x8c) + 0x32U,
                        y < (double)(float)(cvtTmp)))
                {
                    return (int)*(char*)(*layerTable + cellX);
                }
            }
            layerTable = layerTable + 1;
            cellZ = cellZ + -1;
        }
        while (cellZ != 0);
    }
    return -1;
}

void lightmap_sortQueuedRenderKeys(int queueBase, int keyCount)
{
    int scratch;
    int remain;
    u32 cmpKey;
    int insertPtr;
    int srcPtr;
    int i;
    int j;
    u32 key;
    int gap;

    scratch = keyCount / 9 + (keyCount >> 0x1f);
    for (gap = 1; gap <= scratch - (scratch >> 0x1f); gap = gap * 3 + 1)
    {
    }
    for (; 0 < gap; gap = gap / 3)
    {
        i = gap + 1;
        scratch = i * 4;
        srcPtr = queueBase + scratch;
        remain = (keyCount + 1) - i;
        if (i <= keyCount)
        {
            do
            {
                key = *(u32*)(srcPtr + -4);
                insertPtr = queueBase + scratch;
                j = i;
                while ((gap < j &&
                    (cmpKey = *(u32*)(queueBase + (j - gap) * 4 + -4), cmpKey < key)))
                {
                    *(u32*)(insertPtr + -4) = cmpKey;
                    insertPtr = insertPtr + gap * -4;
                    j = j - gap;
                }
                *(u32*)(queueBase + j * 4 + -4) = key;
                srcPtr = srcPtr + 4;
                i = i + 1;
                scratch = scratch + 4;
                remain = remain + -1;
            }
            while (remain != 0);
        }
    }
    return;
}

/*
 * Per-LOD-layer visibility sweep over the 16x16 map-block grid.
 * For each of the 5 detail layers (layer 4..0) it clears a 16-row visibility
 * mask (visGrid), stamps the four concentric camera "rings" (ring0..ring3,
 * each an inclusive x0/x1/y0/y1 box returned by FUN_800566ec) into the mask,
 * then walks every cell: a resident block (cellState >= 0) toggles its
 * double-buffer parity bit and, when marked visible, streams its render; an
 * empty cell (cellState < 0) may still be drawn via FUN_80057ce8. worldX /
 * lbl_803DDAD4 hold the cell's world-space X/Z (u32->f64 magic-number cvt).
 * NOTE: extraout_r4 is the decompiler's placeholder for the visGrid row base
 * that the retail code keeps live in r4 across the fill loop; leaving it
 * unassigned reproduces the exact register colouring.
 */
void FUN_8005bdbc(void)
{
    char* extraout_r4;
    char* gridPtr;
    int cellState;
    int cellIdx;
    char* colPtr;
    int cellTable;
    int blockPtr;
    int layer;
    int scratchA;
    u32 runBlocks;
    u32 scratchC;
    u32* layerDat;
    int* layerTbl;
    int scratchB;
    double in_f29;
    double worldX;
    double in_f30;
    double scaleA;
    double in_f31;
    double scaleB;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    int ring3_x0;
    int ring3_x1;
    int ring3_y0;
    int ring3_y1;
    int ring2_x0;
    int ring2_x1;
    int ring2_y0;
    int ring2_y1;
    int ring1_x0;
    int ring1_x1;
    int ring1_y0;
    int ring1_y1;
    int ring0_x0;
    int ring0_x1;
    int ring0_y0;
    int ring0_y1;
    char visGrid[256];
    u32 cvtLoHiA;
    u32 cvtLoLoA;
    u32 cvtHiHi;
    u32 cvtHiLo;
    float spillF29;
    float spillF29_1;
    float spillF30;
    float spillF30_1;
    float spillF31;
    float spillF31_1;

    spillF31 = (float)in_f31;
    spillF31_1 = (float)in_ps31_1;
    spillF30 = (float)in_f30;
    spillF30_1 = (float)in_ps30_1;
    spillF29 = (float)in_f29;
    spillF29_1 = (float)in_ps29_1;
    FUN_80286818();
    layer = 4;
    layerTbl = &DAT_80382f24;
    layerDat = &DAT_80382efc;
    scaleA = (double)lbl_803DF834;
    scaleB = DOUBLE_803df840;
    do
    {
        cellTable = *layerTbl;
        DAT_803ddb08 = *layerDat;
        FUN_800566ec(DAT_803dda50 + 7, DAT_803dda54 + 7, &ring0_x0, &ring1_x0, &ring2_x0, &ring3_x0, layer
                     , 1, DAT_803ddb40);
        gridPtr = visGrid;
        scratchB = 8;
        do
        {
            *gridPtr = '\0';
            gridPtr[1] = '\0';
            gridPtr[2] = '\0';
            gridPtr[3] = '\0';
            gridPtr[4] = '\0';
            gridPtr[5] = '\0';
            gridPtr[6] = '\0';
            gridPtr[7] = '\0';
            gridPtr[8] = '\0';
            gridPtr[9] = '\0';
            gridPtr[10] = '\0';
            gridPtr[0xb] = '\0';
            gridPtr[0xc] = '\0';
            gridPtr[0xd] = '\0';
            gridPtr[0xe] = '\0';
            gridPtr[0xf] = '\0';
            gridPtr[0x10] = '\0';
            gridPtr[0x11] = '\0';
            gridPtr[0x12] = '\0';
            gridPtr[0x13] = '\0';
            gridPtr[0x14] = '\0';
            gridPtr[0x15] = '\0';
            gridPtr[0x16] = '\0';
            gridPtr[0x17] = '\0';
            gridPtr[0x18] = '\0';
            gridPtr[0x19] = '\0';
            gridPtr[0x1a] = '\0';
            gridPtr[0x1b] = '\0';
            gridPtr[0x1c] = '\0';
            gridPtr[0x1d] = '\0';
            gridPtr[0x1e] = '\0';
            gridPtr[0x1f] = '\0';
            gridPtr = gridPtr + 0x20;
            scratchB = scratchB + -1;
            scratchA = ring0_y0;
        }
        while (scratchB != 0);
        for (; scratchB = ring1_y0, scratchA <= ring0_y1; scratchA = scratchA + 1)
        {
            gridPtr = visGrid + (scratchA + 7) * 0x10 + ring0_x0;
            scratchC = (ring0_x1 + 1) - ring0_x0;
            if (ring0_x0 <= ring0_x1)
            {
                runBlocks = scratchC >> 3;
                if (runBlocks != 0)
                {
                    do
                    {
                        builtin_strncpy(gridPtr + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        gridPtr = gridPtr + 8;
                        runBlocks = runBlocks - 1;
                    }
                    while (runBlocks != 0);
                    scratchC = scratchC & 7;
                    if (scratchC == 0) goto LAB_8005bfc4;
                }
                do
                {
                    gridPtr[7] = '\x01';
                    gridPtr = gridPtr + 1;
                    scratchC = scratchC - 1;
                }
                while (scratchC != 0);
            }
        LAB_8005bfc4:
            ;
        }
        for (; scratchA = ring2_y0, scratchB <= ring1_y1; scratchB = scratchB + 1)
        {
            gridPtr = visGrid + (scratchB + 7) * 0x10 + ring1_x0;
            scratchC = (ring1_x1 + 1) - ring1_x0;
            if (ring1_x0 <= ring1_x1)
            {
                runBlocks = scratchC >> 3;
                if (runBlocks != 0)
                {
                    do
                    {
                        builtin_strncpy(gridPtr + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        gridPtr = gridPtr + 8;
                        runBlocks = runBlocks - 1;
                    }
                    while (runBlocks != 0);
                    scratchC = scratchC & 7;
                    if (scratchC == 0) goto LAB_8005c058;
                }
                do
                {
                    gridPtr[7] = '\x01';
                    gridPtr = gridPtr + 1;
                    scratchC = scratchC - 1;
                }
                while (scratchC != 0);
            }
        LAB_8005c058:
            ;
        }
        for (; scratchB = ring3_y0, scratchA <= ring2_y1; scratchA = scratchA + 1)
        {
            gridPtr = visGrid + (scratchA + 7) * 0x10 + ring2_x0;
            scratchC = (ring2_x1 + 1) - ring2_x0;
            if (ring2_x0 <= ring2_x1)
            {
                runBlocks = scratchC >> 3;
                if (runBlocks != 0)
                {
                    do
                    {
                        builtin_strncpy(gridPtr + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        gridPtr = gridPtr + 8;
                        runBlocks = runBlocks - 1;
                    }
                    while (runBlocks != 0);
                    scratchC = scratchC & 7;
                    if (scratchC == 0) goto LAB_8005c0ec;
                }
                do
                {
                    gridPtr[7] = '\x01';
                    gridPtr = gridPtr + 1;
                    scratchC = scratchC - 1;
                }
                while (scratchC != 0);
            }
        LAB_8005c0ec:
            ;
        }
        for (; scratchB <= ring3_y1; scratchB = scratchB + 1)
        {
            gridPtr = visGrid + (scratchB + 7) * 0x10 + ring3_x0;
            scratchC = (ring3_x1 + 1) - ring3_x0;
            if (ring3_x0 <= ring3_x1)
            {
                runBlocks = scratchC >> 3;
                if (runBlocks != 0)
                {
                    do
                    {
                        builtin_strncpy(gridPtr + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        gridPtr = gridPtr + 8;
                        runBlocks = runBlocks - 1;
                    }
                    while (runBlocks != 0);
                    scratchC = scratchC & 7;
                    if (scratchC == 0) goto LAB_8005c180;
                }
                do
                {
                    gridPtr[7] = '\x01';
                    gridPtr = gridPtr + 1;
                    scratchC = scratchC - 1;
                }
                while (scratchC != 0);
            }
        LAB_8005c180:
            ;
        }
        scratchB = 0;
        gridPtr = extraout_r4;
        do
        {
            scratchC = (u32) * gridPtr;
            scratchA = 0;
            cvtLoLoA = scratchC ^ 0x80000000;
            cvtLoHiA = 0x43300000;
            worldX = (double)(float)(scaleA * (double)(float)((double)(int)scratchC));
            colPtr = extraout_r4;
            do
            {
                runBlocks = (u32) * colPtr;
                cellIdx = scratchC + runBlocks * 0x10;
                cellState = (int)*(char*)(cellTable + cellIdx);
                if (cellState < 0)
                {
                    blockPtr = 0;
                LAB_8005c210:
                    if ((-1 < cellState) && (cellState = FUN_80057ce8(scratchC, runBlocks, blockPtr), cellState != 0))
                    {
                        lbl_803DDAD8 = (float)worldX;
                        cvtLoLoA = runBlocks ^ 0x80000000;
                        cvtLoHiA = 0x43300000;
                        lbl_803DDAD4 =
                            lbl_803DF834 * (f32)(s32)
                        cvtLoLoA;
                        cvtHiLo = (int)*(short*)(blockPtr + 0x8e) ^ 0x80000000;
                        cvtHiHi = 0x43300000;
                        FUN_80247a48(worldX, (f64)(f32)(s32)cvtHiLo, (double)lbl_803DDAD4,
                                     (u32*)(blockPtr + 0xc));
                        FUN_8005fb68();
                    }
                }
                else
                {
                    blockPtr = *(int*)(DAT_803ddb1c + cellState * 4);
                    *(u16*)(blockPtr + 4) = *(u16*)(blockPtr + 4) ^ 1;
                    if (visGrid[cellIdx] != '\0') goto LAB_8005c210;
                }
                scratchA = scratchA + 1;
                colPtr = colPtr + 1;
            }
            while (scratchA < 0x10);
            scratchB = scratchB + 1;
            gridPtr = gridPtr + 1;
        }
        while (scratchB < 0x10);
        layerTbl = layerTbl + -1;
        layerDat = layerDat + -1;
        layer = layer + -1;
        if (layer < 0)
        {
            FUN_80286864();
            return;
        }
    }
    while (true);
}

void fn_8005C8CC(void)
{
    DAT_803dda68 = DAT_803dda68 | 0x21;
    if ((DAT_803ddb24 == '\x01') || (DAT_803ddb24 == '\x03'))
    {
        DAT_803dda68 = DAT_803dda68 & ~1;
    }
    FUN_8000694c();
    updateVisibleGeometry();
    FUN_80057fd0();
    FUN_800069bc();
    FUN_80006984();
    FUN_800069d4();
    FUN_8001761c();
    DAT_803ddb28 = (int)FUN_800069a8();
    FUN_8005c24c();
    FUN_80006934();
    DAT_803dda68 = DAT_803dda68 & 0xfffffffd;
    return;
}

/*
 * DAT_803dda68 is the lightmap/scene render-state bitfield. The setters below
 * decode as: 0x00020000 reflection-pass enable (FUN_8005cff0), 0x8 shadow-map
 * enable (FUN_8005d018, also swaps the shadow bias lbl_803DC2D0/lbl_803DF89C),
 * 0x40 lights enable (FUN_8005d0ac, mirrored into env-state bit 3), 0x50
 * clouds+lights (FUN_8005d17c), 0x1000 pending-map-load (FUN_8005d1e8).
 */
void FUN_8005cff0(int enable)
{
    if (enable == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xfffdffff;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x20000;
    }
    return;
}

u32 FUN_8005d018(char enable)
{
    if (enable == '\0')
    {
        DAT_803dda68 = DAT_803dda68 & 0xfffffff7;
        FUN_800069f4((double)lbl_803DC2D0);
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 8;
        FUN_800069f4((double)lbl_803DF89C);
    }
    return 0;
}

u32 FUN_8005d06c(void)
{
    return DAT_803dda68 & 8;
}

void FUN_8005d0ac(int enable)
{
    u32* settings;

    settings = FUN_800e87a8();
    if (enable == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xffffffbf;
        *(u8*)(settings + 0x10) = *(u8*)(settings + 0x10) & 0xf7;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x40;
        *(u8*)(settings + 0x10) = *(u8*)(settings + 0x10) | 8;
    }
    return;
}

void FUN_8005d17c(int enable)
{
    u32* settings;

    settings = FUN_800e87a8();
    if (enable == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xffffffaf;
        *(u8*)(settings + 0x10) = *(u8*)(settings + 0x10) & 0xf6;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x50;
        *(u8*)(settings + 0x10) = *(u8*)(settings + 0x10) | 9;
    }
    return;
}

void FUN_8005d1e8(int enable)
{
    if (enable == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xffffefff;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x1000;
    }
    return;
}

void fn_8005D108(int vtxTable, int indices, int triCount)
{
    volatile u8* fifo8;
    volatile u16* fifo16;
    u16* vtx;
    int idx;
    int vtxAddr;
    int i;
    int corner;
    int cornerCount;

    fifo8 = (volatile u8*)&DAT_cc008000;
    fifo16 = (volatile u16*)&DAT_cc008000;
    FUN_80257b5c();
    FUN_802570dc(0, 1);
    FUN_802570dc(9, 1);
    FUN_802570dc(0xb, 1);
    FUN_802570dc(0xd, 1);
    FUN_80259000(0x90, 0, triCount * 3 & 0xffff);
    for (i = 0; i < triCount; i = i + 1)
    {
        corner = 0;
        cornerCount = 3;
        do
        {
            *fifo8 = 0;
            idx = corner + 1;
            vtx = (u16*)(vtxTable + (u32) * (u8*)(indices + idx) * 0x10);
            *fifo16 = *vtx;
            *fifo16 = vtx[1];
            *fifo16 = vtx[2];
            vtxAddr = vtxTable + (u32) * (u8*)(indices + idx) * 0x10;
            *fifo8 = *(u8*)(vtxAddr + 0xc);
            *fifo8 = *(u8*)(vtxAddr + 0xd);
            *fifo8 = *(u8*)(vtxAddr + 0xe);
            *fifo8 = *(u8*)(vtxAddr + 0xf);
            idx = vtxTable + (u32) * (u8*)(indices + idx) * 0x10;
            *fifo16 = *(u16*)(idx + 8);
            *fifo16 = *(u16*)(idx + 10);
            corner = corner + 1;
            cornerCount = cornerCount + -1;
        }
        while (cornerCount != 0);
        indices = indices + 0x10;
    }
    return;
}

void FUN_8005d370(u32 arg1, u8 fwdArg2, u8 fwdArg3, u8 fwdArg4,
                  u8 fwdArg5)
{
    FUN_80071fb4(fwdArg2, fwdArg3, fwdArg4, fwdArg5);
    return;
}

void lightmap_queueObjectRenderEntry(int object, int sortGroup, int depthBias)
{
    int idx;
    u32 sortKey;
    float* viewMtx;
    float viewX;
    float viewY;
    float viewZ;

    if (DAT_803ddab0 == 1000)
    {
        lightmap_flushQueuedRenderPackets();
        DAT_803ddab0 = 0;
    }
    if (*(int*)(object + 0x30) == 0)
    {
        viewX = *(float*)(object + 0x18) - lbl_803DDA58;
        viewY = *(float*)(object + 0x1c);
        viewZ = *(float*)(object + 0x20) - lbl_803DDA5C;
    }
    else
    {
        viewX = *(float*)(object + 0x18);
        viewY = *(float*)(object + 0x1c);
        viewZ = *(float*)(object + 0x20);
    }
    viewMtx = (float*)FUN_80006974();
    FUN_80247bf8(viewMtx, &viewX, &viewX);
    idx = DAT_803ddab0;
    sortKey = (int)-viewZ + depthBias;
    if ((int)sortKey < 0)
    {
        sortKey = 0;
    }
    else if (0x7ffffff < sortKey)
    {
        sortKey = 0x7ffffff;
    }
    (&DAT_8037ed20)[DAT_803ddab0 * 4] = object;
    (&DAT_8037ed28)[idx * 4] = sortKey | sortGroup << 0x1b;
    return;
}

void lightmap_sortQueuedRenderPackets(void)
{
    int byteOff;
    u32 word1;
    u32 word3;
    u32 tmpWord;
    int prevIdx;
    int i;
    int gap;
    u32 word0;
    u32 sortKey;
    int insertPos;
    u32* src;
    u32* packets;
    int j;

    packets = &DAT_8037ed10;
    byteOff = (DAT_803ddab0 + -1) / 9 + (DAT_803ddab0 + -1 >> 0x1f);
    for (gap = 1; gap <= byteOff - (byteOff >> 0x1f); gap = gap * 3 + 1)
    {
    }
    for (; 0 < gap; gap = gap / 3)
    {
        i = gap + 1;
        byteOff = i * 0x10;
        src = packets + i * 4;
        for (; i <= DAT_803ddab0; i = i + 1)
        {
            word0 = src[-4];
            word1 = src[-3];
            sortKey = src[-2];
            word3 = src[-1];
            insertPos = (int)(packets + i * 4);
            j = i;
            while ((gap < j &&
                (prevIdx = j - gap, packets[prevIdx * 4 + 2] < sortKey)))
            {
                tmpWord = packets[prevIdx * 4 + 1];
                *(u32*)(insertPos + -0x10) = packets[prevIdx * 4];
                *(u32*)(insertPos + -0xc) = tmpWord;
                tmpWord = packets[prevIdx * 4 + 3];
                *(u32*)(insertPos + -8) = packets[prevIdx * 4 + 2];
                *(u32*)(insertPos + -4) = tmpWord;
                insertPos = insertPos + gap * -0x10;
                j = j - gap;
            }
            packets[j * 4] = word0;
            packets[j * 4 + 1] = word1;
            packets[j * 4 + 2] = sortKey;
            packets[j * 4 + 3] = word3;
            src = src + 4;
            byteOff = byteOff + 0x10;
        }
    }
    return;
}

void lightmap_renderQueuedObject(u16* object)
{
    int val;

    val = FUN_80017a54((int)object);
    if (*(int*)(val + 0x58) == 0)
    {
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, object);
        FUN_8003f9f8();
        FUN_8003b878(0, 0, 0, 0, object, 1);
        FUN_80006994();
        if ((*(int*)(object + 0x32) == 0) || (*(int*)(*(int*)(object + 0x32) + 0xc) == 0))
        {
            if (*(short*)(*(int*)(object + 0x28) + 0x48) == 3)
            {
                FUN_80060a64(object, val);
            }
        }
        else
        {
            FUN_80061194();
        }
        FUN_80006988();
    }
    else
    {
        FUN_8003d97c(object, val);
    }
    return;
}

void lightmap_flushQueuedRenderPackets(void)
{
    u8 bval;
    float* mtx;
    int entryObj;
    int ref;
    int i;
    int* packet;
    u32 convHi0;
    u32 convLo0;
    u32 convHi1;
    u32 convLo1;
    u32 convHi2;
    u32 convLo2;
    float mtxBuf[28];

    FUN_80286830();
    lightmap_sortQueuedRenderPackets();
    packet = &DAT_8037ed20;
    for (i = 0; i < DAT_803ddab0; i = i + 1)
    {
        switch (packet[3])
        {
        case 0:
            expgfx_renderSourcePools(*packet, 0);
            lightmap_renderQueuedObject((u16*)*packet);
            expgfx_renderSourcePools(*packet, 1);
            break;
        case 1:
            entryObj = *packet;
            FUN_80017a54(entryObj);
            ref = FUN_80017a98();
            if (entryObj == ref)
            {
                bval = FUN_80294c20(entryObj);
                if (bval == 0)
                {
                    FUN_802950c4(entryObj, '\x01', '\x01');
                }
            }
            else
            {
                FUN_800404cc(entryObj);
            }
            break;
        case 2:
            FUN_80006994();
            FUN_80061194();
            FUN_80006988();
            break;
        case 3:
            FUN_80006994();
            ref = FUN_80017a54(*packet);
            FUN_80060a64((u16*)*packet, ref);
            FUN_80006988();
            break;
        case 4:
            ref = packet[1];
            FUN_8025a608(0, 1, 0, 1, 0, 0, 2);
            FUN_8025a608(2, 0, 0, 1, 0, 0, 2);
            FUN_80080f88(0, (u8*)&convHi2, (u8*)((int)&convHi2 + 1), (u8*)((int)&convHi2 + 2));
            convLo2 = convHi2;
            FUN_8025a2ec(0, &convLo2);
            FUN_8025a5bc(1);
            mtx = (float*)FUN_80006974();
            FUN_80247618(mtx, (float*)(ref + 0xc), mtxBuf);
            FUN_8005fab0(ref, mtxBuf);
            FUN_8005daec(*packet, packet[1], mtxBuf);
            break;
        case 5:
            ref = packet[1];
            FUN_8025a608(0, 1, 0, 1, 0, 0, 2);
            FUN_8025a608(2, 0, 0, 1, 0, 0, 2);
            FUN_80080f88(0, (u8*)&convHi1, (u8*)((int)&convHi1 + 1), (u8*)((int)&convHi1 + 2));
            convLo1 = convHi1;
            FUN_8025a2ec(0, &convLo1);
            FUN_8025a5bc(1);
            mtx = (float*)FUN_80006974();
            FUN_80247618(mtx, (float*)(ref + 0xc), mtxBuf);
            FUN_8005fab0(ref, mtxBuf);
            FUN_8005d984(*packet, packet[1], mtxBuf);
            break;
        case 6:
            ref = packet[1];
            FUN_8025a608(0, 1, 0, 1, 0, 0, 2);
            FUN_8025a608(2, 0, 0, 1, 0, 0, 2);
            FUN_80080f88(0, (u8*)&convHi0, (u8*)((int)&convHi0 + 1), (u8*)((int)&convHi0 + 2));
            convLo0 = convHi0;
            FUN_8025a2ec(0, &convLo0);
            FUN_8025a5bc(1);
            mtx = (float*)FUN_80006974();
            FUN_80247618(mtx, (float*)(ref + 0xc), mtxBuf);
            FUN_8005fab0(ref, mtxBuf);
            FUN_8005d85c(*packet, packet[1], mtxBuf);
            break;
        case 7:
            drawGlow(*packet, packet[1]);
            break;
        case 8:
            FUN_8006f09c();
            break;
        case 9:
            (**(VtableFn**)(*DAT_803dd718 + 0xc))(0, 0);
        }
        packet = packet + 4;
    }
    FUN_8028687c();
    return;
}

extern u32 lbl_8037E0C0[];
extern s32 lbl_803DCE30;
extern int Camera_GetViewMatrix(void);
extern void PSMTXMultVec(int m, f32* in, f32* out);
#pragma dont_inline on
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
    PSMTXMultVec(Camera_GetViewMatrix(), stk, stk);
    t = (s32) - stk[2] + offset;
    v = t < 0 ? 0 : (t > 0x7ffffff ? 0x7ffffff : t);
    lbl_8037E0C0[lbl_803DCE30 * 4] = (u32)obj;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = v | ((b & 0xff) << 27);
}
#pragma dont_inline reset

extern f32 CurrTiming_803DEC20;

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
    lfs f3, CurrTiming_803DEC20
    lfs f6, 40(r30)
    fmadds f9, f2, f3, f6
    psq_l f4, 8(r29), 1, 5
    psq_l f2, 16(r29), 1, 5
    lfs f7, 56(r30)
    fmadds f10, f2, f3, f7
    psq_l f5, 10(r29), 1, 5
    lfs f2, displayOffsetH_803DEBFC
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

u32 gVisibleObjectSortKeys[0x400];
extern int gLightmapDeferredObjectCount;
extern s16 gVisibleObjectSortKeyCount;
extern void objRender(int a, int b, int c, int d, void* obj, int f);

typedef struct
{
    u32 a, b, c, d;
} LightmapQEnt;

typedef struct
{
    u8 pad[0x4114];
    u32 deferred[20];
} LightmapDrawQueue;

void renderObjects(s8* arg0)
{
    int i;
    u32 flags;
    int idx;
    u8* obj;
    u8* state;
    int* p;
    int slot;
    int* objects;
    u32* keys;
    LightmapDrawQueue* qbase;
    LightmapQEnt* q;

    qbase = (LightmapDrawQueue*)lbl_8037E0C0;
    q = (LightmapQEnt*)lbl_8037E0C0;
    objects = ObjList_GetObjects((int*)0, 0);
    keys = (u32*)((u8*)qbase + 0x8818);
    for (i = 1; i < gVisibleObjectSortKeyCount; i++)
    {
        idx = keys[i] & 0x3ff;
        obj = (u8*)objects[idx];
        flags = ((GameObject*)obj)->anim.modelInstance->flags;
        if ((flags & 0x800) != 0 || ((((GameObject*)obj)->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER) != 0))
        {
            if (arg0[idx] != 0 && gLightmapDeferredObjectCount < 0x14)
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
            objRender(0, 0, 0, 0, obj, 1);
            p = (int*)((GameObject*)obj)->anim.modelState;
            if (p != NULL && ((GameObject*)obj)->anim.modelState->shadowCastSlot != NULL)
            {
                renderShadowType3(obj, 0x13, 0);
                *(u32*)((u8*)&q->d + lbl_803DCE30 * 16) = 2;
                lbl_803DCE30++;
            }
            else if (((GameObject*)obj)->anim.modelInstance->shadowType == 3 && (((GameObject*)obj)->anim.flags
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

extern s8 curMapType;
extern int lbl_803DCEA8;
extern void Camera_UpdateProjection(int a, int b);
extern void Camera_EnableViewYOffset(void);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_RebuildProjectionMatrix(void);
extern void playerVecFn_8005a9b0(void);
extern void updateLights(void);
extern void screenFn_8000e944(int v);

void sceneRender(void)
{
    renderFlags |= 0x21;
    if (curMapType == 1 || curMapType == 3)
    {
        renderFlags &= ~1LL;
    }
    Camera_UpdateProjection(0, 0);
    updateVisibleGeometry();
    playerVecFn_8005a9b0();
    Camera_EnableViewYOffset();
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    updateLights();
    lbl_803DCEA8 = Camera_GetCurrentViewSlot();
    sceneDraw();
    screenFn_8000e944(0);
    renderFlags &= ~2LL;
}

void doNothing_beforeTitleScreen(void)
{
}

void doNothing_8005D148(void)
{
}

void doNothing_8005D14C(void)
{
}

u32 getDrawDistanceFlag_8005cd48(void) { return renderFlags & RENDERFLAG_DRAW_DISTANCE; }
int isWidescreen(void) { return renderFlags & RENDERFLAG_WIDESCREEN; }
u32 shouldDrawShadows(void) { return renderFlags & RENDERFLAG_DRAW_SHADOWS; }
u32 shouldDrawClouds(void) { return renderFlags & RENDERFLAG_DRAW_CLOUDS; }

u32 isOvercast(void)
{
    u32 v = renderFlags & RENDERFLAG_OVERCAST;
    u32 t = ((u32) - (s32)v | v) >> 31;
    return t;
}

void gameFlagFn_8005cd24(int v)
{
    if (v != 0) renderFlags |= 0x20000;
    else renderFlags &= ~0x20000;
}

void titleScreenFn_8005cdd4(int v)
{
    if (v != 0) renderFlags &= ~0x2000;
    else renderFlags |= 0x2000;
}

void gameFlagFn_8005ce6c(int v)
{
    if (v != 0) renderFlags |= 0x20;
    else renderFlags &= ~0x20;
}

void setIsOvercast(int v)
{
    if (v != 0) renderFlags |= RENDERFLAG_OVERCAST;
    else renderFlags &= ~RENDERFLAG_OVERCAST;
}

void fn_8005CECC(int v)
{
    if (v != 0) renderFlags |= 0x80000;
    else renderFlags &= ~0x80000;
}

void setPendingMapLoad(int v)
{
    if (v != 0) renderFlags |= RENDERFLAG_PENDING_MAP_LOAD;
    else renderFlags &= ~RENDERFLAG_PENDING_MAP_LOAD;
}

extern u8 gLoadedRomListPages[0x1e0];

void* RomList_GetLoadedPages(void)
{
    return gLoadedRomListPages;
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
extern void* gMapBlockLayerTables[];

int isInBounds(f32 x, f32 z)
{
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)lbl_803DCDD0);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)lbl_803DCDD4);
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

extern void** lbl_803DCE9C;

int objPosToMapBlockIdx(f32 x, f32 y, f32 z)
{
    int ix = (int)(fastFloorf(x / gMapBlockWorldSize) - (f32)lbl_803DCDD0);
    int iz = (int)(fastFloorf(z / gMapBlockWorldSize) - (f32)lbl_803DCDD4);
    int i;
    if (ix < 0 || ix >= 16) return -1;
    if (iz < 0 || iz >= 16) return -1;
    ix = ix + (iz << 4);
    for (i = 0; i < MAP_BLOCK_LAYER_COUNT; i++)
    {
        s8* table = gMapBlockLayerTables[i];
        int idx = table[ix];
        if (idx > -1)
        {
            int* block = lbl_803DCE9C[idx];
            if (y > (f32)(*(s16*)((char*)block + 138) - 50) &&
                y < (f32)(*(s16*)((char*)block + 140) + 50))
            {
                return table[ix];
            }
        }
    }
    return -1;
}

extern void fn_800704FC(int a, int b, int c);

void fn_8005D0BC(int unused, int a, int b, int c)
{
    fn_800704FC(a, b, c);
}

extern void _gxSetTevColor1(int a, int b, int c, int d);
extern void _gxSetTevColor2(int a, int b, int c, int d);

void _textSetColor(int unused, int a, int b, int c, int d)
{
    _gxSetTevColor1(a, b, c, d);
}

void setTextColor(int unused, int a, int b, int c, int d)
{
    _gxSetTevColor2(a, b, c, d);
}

extern u8 lbl_803DCE98; /* count of allocated blocks */
void* mapGetBlockIdx(int layer)
{
    return gMapBlockLayerTables[layer];
}

void* mapGetBlock(int i)
{
    if (i < 0 || i >= lbl_803DCE98) return 0;
    return lbl_803DCE9C[i];
}

void* mapGetBlockAtPos(int x, int y, int layer)
{
    s8* table = gMapBlockLayerTables[layer];
    s32 idx;
    if (x < 0 || y < 0 || x >= 0x10 || y >= 0x10) return 0;
    idx = table[x + (y << 4)];
    if (idx < 0 || idx >= lbl_803DCE98) return 0;
    return lbl_803DCE9C[idx];
}

extern f32 shdwChanged_803DEC18;
extern f32 widescreenAspect_803DEC1C;
extern f32 lbl_803DB670;
extern void Camera_SetAspectRatio(f32 aspectRatio);

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

extern void* saveGameGetEnvState(void);

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

extern void modelRenderInstrsState_init(int* state, void* buf, int s1, int s2);
extern void modelRenderInstrsState_setBit(int* state, int bit);
extern void mapBlockRender_drawDimmedAabbLights(int* p1, int* obj, float* p3);
extern int mapBlockRender_setLightmapShader(int* obj, int* state);
extern void mapBlockRender_drawLightmapIndirectPasses(int* obj, int v, int* state, float* p3);

#pragma dont_inline on
void modelRenderFn_8005d4ec(int* p1, int* obj, float* p3)
{
    int state[5];
    int countShifted;
    int cursor;
    u32 v;
    int* base;
    int newR;
    int nibble;
    int i;
    u8* s0;

    countShifted = (int)*(u16*)((char*)obj + 0x84) << 3;
    modelRenderInstrsState_init(state, *(void**)((char*)obj + 0x78), countShifted, countShifted);
    modelRenderInstrsState_setBit(state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    mapBlockRender_drawDimmedAabbLights(p1, obj, p3);
    newR = mapBlockRender_setLightmapShader(obj, state);
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
    mapBlockRender_drawLightmapIndirectPasses(obj, newR, state, p3);
}
#pragma dont_inline reset

extern void fn_8000F8F8(void);
extern void Camera_ApplyFullViewport(void);
extern int mapBlockRender_setShader(int p1, int* obj, int* state);
extern void mapBlockRender_callList(int p1, int p2, int* obj, int v, int* state, float* p3);

#pragma dont_inline on
void modelRenderFn_8005d894(int* p1, int* obj, float* p3)
{
    int state[5];
    int countShifted;
    int newR;
    int cursor;
    u32 v;
    int* base;
    int nibble;
    int i;
    u8* s0;

    fn_8000F8F8();
    countShifted = (int)*(u16*)((char*)obj + 0x86) << 3;
    modelRenderInstrsState_init(state, *(void**)&((GameObject *)obj)->anim.banks, countShifted, countShifted);
    modelRenderInstrsState_setBit(state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    newR = mapBlockRender_setShader(1, obj, state);
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
    mapBlockRender_callList(1, 1, obj, newR, state, p3);
    Camera_ApplyFullViewport();
}
#pragma dont_inline reset

extern void PSMTXConcat(f32 * a, f32 * b, f32 * ab);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern void gxTextureSetupFn_8007cf7c(void);
extern f32 lbl_80396850[12];
extern f32 lbl_80396820[12];

#pragma dont_inline on
void modelRenderFn_8005d69c(int* p1, int* obj, float* p3)
{
    int state[5];
    f32 m[12];
    int countShifted;
    int newR;
    int cursor;
    u32 v;
    int* base;
    int nibble;
    int i;
    u8* s0;

    PSMTXConcat(lbl_80396850, p3, m);
    GXLoadTexMtxImm(m, GX_TEXMTX0, GX_MTX3x4);
    PSMTXConcat(lbl_80396820, p3, m);
    GXLoadTexMtxImm(m, GX_TEXMTX1, GX_MTX3x4);
    gxTextureSetupFn_8007cf7c();
    countShifted = (int)*(u16*)((char*)obj + 0x88) << 3;
    modelRenderInstrsState_init(state, *(void**)&((GameObject *)obj)->anim.previousLocalPosX, countShifted, countShifted);
    modelRenderInstrsState_setBit(state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    newR = mapBlockRender_setShader(1, obj, state);
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
    mapBlockRender_callList(1, 1, obj, newR, state, p3);
}
#pragma dont_inline reset

extern void* lbl_803DCEA0;

int* mapRomListFindItem(int needle, int* out_idx, int* out_outer, int* out_type, int* out_lastpage)
{
    int inner_idx;
    int outer;
    int* page;
    int total_offset;
    int* p;
    u16 limit;
    int sz;

    for (outer = 0; outer < 0x78; outer++)
    {
        page = ((int**)gLoadedRomListPages)[outer];
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

typedef struct
{
    u8 r, g, b, a;
} GXColor8;

extern u8 framesThisStep;
extern int* Obj_GetActiveModel(int* obj);
extern void objShadowFn_80062498(int* obj, int p2, int p3, u8 frames);
extern void objDrawFn_80061654(int* obj, int* model);
extern void fn_8000F9B4(void);
extern int playerIsDisguised(int* obj);
extern void fn_802B4ED8(int* obj, int a, int b);
extern void objRenderFuzz(int* obj);
extern void drawFn_8006f500(void);
void objDrawFn_8005da48(int* obj);
void lightmap_sortTransparentDrawQueue(void);
extern void objGetColor(int slot, u8* red, u8* green, u8* blue);
extern void GXSetChanCtrl(GXChannelID chan, GXBool enable, GXColorSrc amb_src, GXColorSrc mat_src, u32 light_mask, GXDiffuseFn diff_fn, GXAttnFn attn_fn);
extern void GXSetChanAmbColor(int chan, GXColor8* c);
extern void GXSetNumChans(u8 nChans);
extern void setupToRenderMapBlock(int* block, void* posMtx);
extern u32 cloudGetLayerTextureSize(f32 * a, f32 * b);
extern u32 lbl_803DCE34;
extern f32 shdwChangeMode_803DEC10;
extern f32* Camera_GetInverseViewMatrix(void);
extern void mapDebugRender(void* p);
extern void fn_80062894(void);
extern void fn_80062808(void);
extern u16 lbl_803DCEAC;
extern u8 lbl_803DCE06;

void getVisibleObjects(s8 * opacity);


extern s32 heatEffectIntensity;

extern u8 gLightmapScreenImageEnabled;
extern void screenImageDraw(void);
extern void lightningRenderActive(void);
extern s8 lbl_8030E65C[];
extern s8 lbl_8030E66C[];
void renderSceneGeometry(int* p1, s8* order);
extern u8 CameraShake_IsActive(void);
extern u8 bEnableMotionBlur;
extern f32 lbl_803DB62C;
extern void renderMotionBlur(f32 v);
extern int getHudHiddenFrameCount(void);

extern u8 bEnableBlurFilter;
extern f32 lbl_803DCE50;
extern f32 lbl_803DCE4C;
extern f32 blurFilterArea;
extern u8 bBlurFilterUseArea;
extern u8 bBiggerBlurFilter;
extern void doBlurFilter(f32 a, f32 b, f32 c, u8 d, u8 e);
extern void doHeatEffect(int v);
extern void quakeSpellTextureFn_8016dbf4(void);
extern u8 bEnableDistortionFilter;
extern f32 distortionFilterAngle1;
extern f32 distortionFilterAngle2;
extern char distortionFilterColor;
extern void doDistortionFilter(void* buf, f32 a2, void* color, f32 a1);
extern void renderGlows(void);
extern u8 bEnableMonochromeFilter;
extern char colorFilterColor;
extern void doColorFilter(void* color);
extern u8 bEnableSpiritVision;
extern void doSpiritVisionFilter(void);
extern u8 bEnableViewFinderHud;
extern f32 lbl_803DEC14;
extern void drawViewFinderAperture(f32 a, f32 b, int c, int d);
extern s32 bEnableColorFilter;

void sceneDraw(void)
{
    char* q;
    int i;
    u8* cursor;
    int* player;
    u8 flag;
    int t;
    GXColor8 c;
    f32 skyA;
    f32 skyB;
    GXColor8 ccopy;
    s8 buf[616];

    q = (char*)lbl_8037E0C0;
    lbl_803DCE34 = cloudGetLayerTextureSize(&skyA, &skyB);
    if (lbl_803DCE34 != 0)
    {
        *(f32*)(q + 0x3f48) = shdwChangeMode_803DEC10;
        *(f32*)(q + 0x3f4c) = lbl_803DEBCC;
        *(f32*)(q + 0x3f50) = lbl_803DEBCC;
        *(f32*)(q + 0x3f54) = shdwChangeMode_803DEC10 * playerMapOffsetX + skyA;
        *(f32*)(q + 0x3f58) = lbl_803DEBCC;
        *(f32*)(q + 0x3f5c) = lbl_803DEBCC;
        *(f32*)(q + 0x3f60) = shdwChangeMode_803DEC10;
        *(f32*)(q + 0x3f64) = shdwChangeMode_803DEC10 * playerMapOffsetZ + skyB;
        *(f32*)(q + 0x3f68) = lbl_803DEBCC;
        *(f32*)(q + 0x3f6c) = lbl_803DEBCC;
        *(f32*)(q + 0x3f70) = lbl_803DEBCC;
        *(f32*)(q + 0x3f74) = lbl_803DEBDC;
        PSMTXConcat((f32*)(q + 0x3f48), (f32*)Camera_GetInverseViewMatrix(),
                    (f32*)(q + 0x3f48));
    }
    mapDebugRender(q + 0x4164);
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
    Camera_UpdateProjection(0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    t = 0;
    if ((renderFlags & 0x40) != 0 && (renderFlags & 0x80000) == 0)
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
        screenImageDraw();
    }
    lightningRenderActive();
    (*gSky2Interface)->applyFogColor(0);
    gLightmapDeferredObjectCount = 0;
    getAmbientColor(0, (u8*)&c, (u8*)&c + 1, (u8*)&c + 2);
    GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    ccopy = c;
    GXSetChanAmbColor(GX_COLOR0, &ccopy);
    GXSetNumChans(1);
    renderSceneGeometry((int*)0, lbl_8030E65C);
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
        objRender(0, 0, 0, 0, (void*)*(u32*)cursor, 1);
        cursor += 4;
    }
    renderParticles();
    renderSceneGeometry((int*)1, lbl_8030E66C);
    renderSceneGeometry((int*)2, lbl_8030E66C);
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = 0x78000000;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 8;
    lbl_803DCE30++;
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = 0x50000000;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 9;
    lbl_803DCE30++;
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
        doDistortionFilter(q + 0x4108, distortionFilterAngle2, &distortionFilterColor,
                           distortionFilterAngle1);
    }
    renderGlows();
    (*gCameraInterface)->minimapShowHelpTextForTarget(0, 0, 0, 0);
    if (bEnableMonochromeFilter != 0)
    {
        doColorFilter(&colorFilterColor);
    }
    else if (bEnableSpiritVision != 0)
    {
        doSpiritVisionFilter();
    }
    if (bEnableViewFinderHud != 0)
    {
        drawViewFinderAperture(lbl_803DEC14, shdwChanged_803DEC18, 0x40, 0);
    }
    if (bEnableColorFilter == 1)
    {
        doColorFilter(&colorFilterColor);
    }
    setShadowFlag_803db658(0);
}

void sceneDrawTransparentPolys(void)
{
    int (*e)[4];
    int i;
    int* block;
    int* player;
    GXColor8 c4copy, c4;
    GXColor8 c5copy, c5;
    GXColor8 c6copy, c6;
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
            objDrawFn_8005da48((int*)e[i][0]);
            expgfx_renderSourcePools(e[i][0], 1);
            break;
        case 1:
            block = (int*)e[i][0];
            Obj_GetActiveModel(block);
            player = Obj_GetPlayerObject();
            if (block == player)
            {
                if (playerIsDisguised(block) == 0)
                {
                    fn_802B4ED8(block, 1, 1);
                }
            }
            else
            {
                objRenderFuzz(block);
            }
            break;
        case 2:
            fn_8000F9B4();
            objShadowFn_80062498((int*)e[i][0], 0, 0, framesThisStep);
            Camera_ApplyFullViewport();
            break;
        case 3:
            fn_8000F9B4();
            objDrawFn_80061654((int*)e[i][0], Obj_GetActiveModel((int*)e[i][0]));
            Camera_ApplyFullViewport();
            break;
        case 4:
            block = (int*)e[i][1];
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            objGetColor(0, (u8*)&c4, (u8*)&c4 + 1, (u8*)&c4 + 2);
            c4copy = c4;
            GXSetChanAmbColor(GX_COLOR0, &c4copy);
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
            c5copy = c5;
            GXSetChanAmbColor(GX_COLOR0, &c5copy);
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
            c6copy = c6;
            GXSetChanAmbColor(GX_COLOR0, &c6copy);
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

extern void mapFn_80057d24(int x, int z, int* box0, int* box1, int* box2, int* box3, int layer,
                           int one, int v);
extern int mapRectFn_8005a728(int row, int col, u8* block);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void renderMapBlock(u8* block, int* p1);
extern int lbl_8038228C[];
extern s32 lbl_803DCE88;
extern s32 lbl_803DCEC0;
extern f32 lbl_803DCE58;
extern f32 lbl_803DCE54;

typedef union
{
    double d;

    struct
    {
        u32 hi;
        u32 lo;
    } u;
} F64Cvt;

void renderSceneGeometry(int* p1, s8* order)
{
    u8 map[256];
    int box0[4];
    int box1[4];
    int box2[4];
    int box3[4];
    void** layerTablePtr;
    int* layerFlagPtr;
    int idx;
    int y, x0;
    int k;
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
        lbl_803DCE88 = *layerFlagPtr;
        mapFn_80057d24(lbl_803DCDD0 + 7, lbl_803DCDD4 + 7, box0, box1, box2, box3, layer, 1,
                       lbl_803DCEC0);
        p = map;
        for (k = 0; k < 256; k++)
        {
            *p = 0;
            p++;
        }
        for (y = box0[2]; y <= box0[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box0[0];
            for (x0 = box0[0]; x0 <= box0[1]; x0++)
            {
                p[7] = 1;
                p++;
            }
        }
        for (y = box1[2]; y <= box1[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box1[0];
            for (x0 = box1[0]; x0 <= box1[1]; x0++)
            {
                p[7] = 1;
                p++;
            }
        }
        for (y = box2[2]; y <= box2[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box2[0];
            for (x0 = box2[0]; x0 <= box2[1]; x0++)
            {
                p[7] = 1;
                p++;
            }
        }
        for (y = box3[2]; y <= box3[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box3[0];
            for (x0 = box3[0]; x0 <= box3[1]; x0++)
            {
                p[7] = 1;
                p++;
            }
        }
        for (oi = 0; oi < 16; oi++)
        {
            row = order[oi];
            rowF = worldSize * (f32)row;
            for (ii = 0; ii < 16; ii++)
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
                    blk = lbl_803DCE9C[idx];
                    *(u16*)(blk + 4) ^= 1;
                    if (map[cell] == 0)
                    {
                        goto next;
                    }
                }
                if (idx > -1 && mapRectFn_8005a728(row, col, blk) != 0)
                {
                    lbl_803DCE58 = rowF;
                    colF = gMapBlockWorldSize * (f32)col;
                    lbl_803DCE54 = colF;
                    PSMTXTrans((f32*)(blk + 0xc), rowF, (f32)(int)*(s16*)(blk + 0x8e), colF);
                    renderMapBlock(blk, p1);
                }
            next:;
            }
        }
        layerTablePtr--;
        layerFlagPtr--;
        layer--;
    }
    while (layer >= 0);
}

typedef struct
{
    u32 a;
    u32 b;
    u32 key;
    u32 d;
} LightSortEntry;

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


extern int ObjList_PartitionForRender(int* count);
extern int objUpdateOpacity(u8 * obj);
extern void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, int* a, int* b, f32* depth, f32* out);
extern void shadowCreate(u8 * obj);
extern void shadowRenderFn_8006b558(u8 * obj);
extern void renderShadows(int a, int b, int c);
void sortVisibleObjectKeysDescending(u32* arr, int n);

#pragma opt_loop_invariants off
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
    int a, b;
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
                *(u16*)(att + 0xb0) &= ~0x800;
            }
            sub += 4;
        }
        if (i >= part)
        {
            *cur = objUpdateOpacity(o);
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
                        shadowCreate(o);
                    }
                    else if (t == 4)
                    {
                        shadowRenderFn_8006b558(o);
                    }
                }
                if (gVisibleObjectSortKeyCount < 1000)
                {
                    key = 0;
                    model = Obj_GetActiveModel((int*)o);
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
                        if ((((ObjAnimComponent*)o)->modelInstance->flags & 0x800) != 0 ||
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
#pragma opt_loop_invariants reset

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

extern void objRenderFn_8003d980(int* obj, int* model);

void objDrawFn_8005da48(int* obj)
{
    int* model = Obj_GetActiveModel(obj);
    if (*(void**)((char*)model + 0x58) != NULL)
    {
        objRenderFn_8003d980(obj, model);
    }
    else
    {
        void* shadow;
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, obj);
        renderResetFn_8003fc60();
        objRender(0, 0, 0, 0, obj, 1);
        fn_8000F9B4();
        shadow = ((GameObject*)obj)->anim.modelState;
        if (shadow != NULL && ((ObjModelState*)shadow)->shadowCastSlot != NULL)
        {
            objShadowFn_80062498(obj, 0, 0, framesThisStep);
        }
        else if (((ObjAnimComponent*)obj)->modelInstance->shadowType == 3)
        {
            objDrawFn_80061654(obj, model);
        }
        Camera_ApplyFullViewport();
    }
}

extern void loadAssetFileById(void** out, int id);
extern void* lbl_803DCE94;
extern void* lbl_803DCE8C;
extern void* lbl_803DCE78;
extern void* lbl_803DCE7C;
extern void* lbl_803DCE80;
extern void* lbl_803DCE84;
extern s16 lbl_803DCE90;
extern s16 lbl_803DCEBA;
extern s16 lbl_803DCEB8;
extern void* lbl_803DCE6C;
extern void* lbl_803DCE68;

#pragma opt_propagation off
void initMapBlocks(void)
{
    u8* mb = (u8*)lbl_8037E0C0;
    u32 zero;
    u32* q;
    u16* p;
    void* tmp;
    int i;

    renderFlags = 0;
    lbl_803DCE9C = mmAlloc(0x100, 5, 0);
    lbl_803DCE94 = mmAlloc(0x80, 5, 0);
    lbl_803DCE8C = mmAlloc(0x40, 5, 0);
    lbl_803DCE78 = mmAlloc(0xd48, 5, 0);
    *(u32*)(mb + 0x41f4) = (u32)mmAlloc(0x500, 5, 0);
    *(u32*)(mb + 0x41e0) = (u32)mmAlloc(0x3c00, 5, 0);
    *(u32*)(mb + 0x41cc) = (u32)mmAlloc(0x500, 5, 0);

    *(u32*)(mb + 0x41f8) = *(u32*)(mb + 0x41f4) + 0x100;
    *(u32*)(mb + 0x41e4) = *(u32*)(mb + 0x41e0) + 0xc00;
    *(u32*)(mb + 0x41d0) = *(volatile u32*)(mb + 0x41cc) + 0x100;
    *(u32*)(mb + 0x41fc) = *(volatile u32*)(mb + 0x41f8) + 0x100;
    *(u32*)(mb + 0x41e8) = *(volatile u32*)(mb + 0x41e4) + 0xc00;
    *(u32*)(mb + 0x41d4) = *(volatile u32*)(mb + 0x41d0) + 0x100;
    *(u32*)(mb + 0x4200) = *(volatile u32*)(mb + 0x41fc) + 0x100;
    *(u32*)(mb + 0x41ec) = *(volatile u32*)(mb + 0x41e8) + 0xc00;
    *(u32*)(mb + 0x41d8) = *(volatile u32*)(mb + 0x41d4) + 0x100;
    *(u32*)(mb + 0x4204) = *(volatile u32*)(mb + 0x4200) + 0x100;
    *(u32*)(mb + 0x41f0) = *(volatile u32*)(mb + 0x41ec) + 0xc00;
    *(u32*)(mb + 0x41dc) = *(volatile u32*)(mb + 0x41d8) + 0x100;

    loadAssetFileById(&lbl_803DCE7C, 0x1e);
    loadAssetFileById(&lbl_803DCE80, 0x29);

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

    loadAssetFileById(&lbl_803DCE84, 0x27);

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
#pragma opt_propagation reset

extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(GXAttr attr, GXAttrType type);
extern void GXBegin(GXPrimitive type, GXVtxFmt vtxfmt, u16 nverts);

typedef union
{
    u8 u8;
    s16 s16;
    u16 u16;
    u32 u32;
    f32 f32;
} WGPipe;

WGPipe wgfifo : (0xCC008000);

static inline void GXPosition3s16(const s16 x, const s16 y, const s16 z)
{
    wgfifo.s16 = x;
    wgfifo.s16 = y;
    wgfifo.s16 = z;
}

static inline void GXColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    wgfifo.u8 = r;
    wgfifo.u8 = g;
    wgfifo.u8 = b;
    wgfifo.u8 = a;
}

static inline void GXTexCoord2s16(const s16 s, const s16 t)
{
    wgfifo.s16 = s;
    wgfifo.s16 = t;
}

static inline void GXPosition1x8(const u8 x) { wgfifo.u8 = x; }

#pragma peephole on
void drawFn_8005cf8c(int vertexBase, u8* triList, int triCount)
{
    s16* posPtr;
    int clrPtr, texPtr;
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
        for (vtx = 0; vtx < 3; vtx++)
        {
            GXPosition1x8(0);
            posPtr = (s16*)(vertexBase + triList[vtx + 1] * 0x10);
            GXPosition3s16(posPtr[0], posPtr[1], posPtr[2]);
            clrPtr = vertexBase + triList[vtx + 1] * 0x10;
            GXColor4u8(*(u8*)(clrPtr + 0xc), *(u8*)(clrPtr + 0xd), *(u8*)(clrPtr + 0xe),
                       *(u8*)(clrPtr + 0xf));
            texPtr = vertexBase + triList[vtx + 1] * 0x10;
            GXTexCoord2s16(*(s16*)(texPtr + 8), *(s16*)(texPtr + 10));
        }
        triList = triList + 0x10;
    }
}

extern void envFxFn_80088884(void);
extern void* gMinimapInterface;
extern void* lbl_803DCAB0;
extern int textureAnimFn_80053f2c(void* tex, void* a, void* b);

extern f32 timeDelta;
extern s32 lbl_803DCE00;

#pragma fp_contract off
#pragma peephole off
void updateEnvironment(int mode)
{
    if (mode == 0)
    {
        char* entry;
        void* tex;
        int i, byteOffset, k;
        f32 deltaY;

        envFxFn_80088884();
        (*gCloudActionInterface)->scrollTexture();
        (*gSky2Interface)->run();
        (*gSkyInterface)->updateTimeOfDay();
        (*gNewCloudsInterface)->run();

        i = 0;
        byteOffset = i;
        do
        {
            entry = (char*)lbl_803DCE6C + byteOffset;
            if (*(s16*)(entry + 12) != 0 && (tex = *(void**)entry) != NULL &&
                *(u16*)((char*)tex + 0x10) != 0x100 && *(u16*)((char*)tex + 0x14) != 0)
            {
                textureAnimFn_80053f2c(tex, entry + 8, entry + 4);
            }
            byteOffset += 0x10;
            i++;
        }
        while (i < 80);

        i = 0;
        byteOffset = i;
        for (; i < 58; i++)
        {
            entry = (char*)lbl_803DCE68 + byteOffset;
            if (*(u8*)(entry + 12) != 0)
            {
                deltaY = (f32) * (s16*)(entry + 10) * timeDelta;
                *(f32*)entry = *(f32*)entry + (f32) * (s16*)(entry + 8) * timeDelta;
                *(f32*)(entry + 4) = *(f32*)(entry + 4) + deltaY;
            }
            byteOffset += 0x10;
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
#pragma fp_contract reset
