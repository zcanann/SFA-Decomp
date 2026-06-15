#include "main/game_object.h"
#include "main/camera_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frustum.h"
#include "main/lightmap.h"
#include "main/newclouds.h"
#include "main/objlib.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"

extern undefined4 FUN_80006934();
extern undefined4 FUN_8000694c();
extern undefined4 FUN_80006974();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern undefined4 FUN_80006994();
extern void* FUN_800069a8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern undefined4 FUN_800069f4();
extern undefined4 FUN_8001761c();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_8003d97c();
extern undefined4 FUN_8003f9f8();
extern undefined4 FUN_800404cc();
extern undefined4 FUN_800566ec();
extern int FUN_80057ce8();
extern undefined4 FUN_80057fd0();
extern undefined4 mapBlockRender_setVtxDcrs();
extern undefined4 FUN_8005fab0();
extern undefined4 FUN_8005fb68();
extern undefined4 FUN_80060a64();
extern undefined4 FUN_80061194();
extern undefined4 FUN_8006f09c();
extern undefined4 FUN_80071fb4();
extern undefined4 FUN_80080f88();
extern void* FUN_800e87a8();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80259000();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_80286818();
extern undefined4 FUN_80286830();
extern undefined4 FUN_80286864();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_802924c4();
extern byte FUN_80294c20();
extern undefined4 FUN_802950c4();
extern undefined4 builtin_strncpy();

extern undefined4 DAT_8037ed10;
extern int DAT_8037ed20;
extern undefined4 DAT_8037ed28;
extern undefined4 DAT_80382efc;
extern undefined4 DAT_80382f00;
extern int DAT_80382f14;
extern int DAT_80382f24;
extern int DAT_803870c8;
extern ModgfxInterface** gModgfxInterface;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803dda50;
extern undefined4 DAT_803dda54;
extern undefined4 DAT_803dda68;
extern undefined4 DAT_803ddab0;
extern undefined4 DAT_803ddb08;
extern undefined4 DAT_803ddb18;
extern undefined4 DAT_803ddb1c;
extern undefined4 DAT_803ddb24;
extern undefined4 DAT_803ddb28;
extern undefined4 DAT_803ddb40;
extern undefined4 DAT_cc008000;
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
extern f32 Camera_GetFovY(void);
extern f32 encoderType_803DEBF8;
extern f32 displayOffsetH_803DEBFC;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DEBCC;
extern f32 lbl_803DEBDC;
extern f32 changeMode_803DEC00;
extern f32 lbl_803DEC04;
extern F32Pair changed_803DEC08;
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 gViewFrustumPlanes[];
extern f32 fn_80293AC4(int v);
extern f32 fn_80293D0C(int v);
extern f32 sqrtf(f32 v);
extern f32 fn_80292248(f32 v);
extern f32 floor(f32 v);
extern f32 fn_802943F4(f32 v);

#pragma scheduling off
#pragma peephole off
void updateVisibleGeometry(void)
{
    u8* cam;
    f32* py;
    f32* pz;
    f32* pd;
    int n;
    f32 scale;
    f32 xx, yy, zz;
    f32 tt, ff, ss;
    f32 negff, negss;
    f32 ratio2;
    u16 fov;
    f32 oz, oy, ox;
    PosRot st;
    f32 m[17];

    cam = (u8*)Camera_GetCurrentViewSlot();
    py = &gViewFrustumPlanes[1];
    pz = &gViewFrustumPlanes[2];
    pd = &gViewFrustumPlanes[3];
    n = 0;
    if ((renderFlags & 8) != 0 || (renderFlags & 0x10000) != 0)
    {
        scale = Camera_GetFovY() / encoderType_803DEBF8;
    }
    else
    {
        scale = Camera_GetFovY() * displayOffsetH_803DEBFC;
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
    Matrix_TransformPoint(m, lbl_803DEBCC, lbl_803DEBCC, changeMode_803DEC00, &ox, &oy, &oz);
    gViewFrustumPlanes[n * 5] = ox;
    py[n * 5] = oy;
    pz[n * 5] = oz;
    pd[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    n++;
    fov = (int)(lbl_803DEC04 * scale) & 0xffff;
    tt = fn_80293AC4(fov);
    ratio2 = fn_80293D0C(fov) / tt;
    ratio2 = ratio2 * ratio2;
    tt = fn_80292248(sqrtf(changed_803DEC08.lo * (changed_803DEC08.lo * ratio2) + ratio2));
    ff = floor(tt);
    ss = fn_802943F4(tt);
    negff = -ff;
    Matrix_TransformPoint(m, ss, lbl_803DEBCC, negff, &ox, &oy, &oz);
    gViewFrustumPlanes[n * 5] = ox;
    py[n * 5] = oy;
    pz[n * 5] = oz;
    pd[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    n++;
    negss = -ss;
    Matrix_TransformPoint(m, negss, lbl_803DEBCC, negff, &ox, &oy, &oz);
    gViewFrustumPlanes[n * 5] = ox;
    py[n * 5] = oy;
    pz[n * 5] = oz;
    pd[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    n++;
    Matrix_TransformPoint(m, lbl_803DEBCC, negss, negff, &ox, &oy, &oz);
    gViewFrustumPlanes[n * 5] = ox;
    py[n * 5] = oy;
    pz[n * 5] = oz;
    pd[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    n++;
    Matrix_TransformPoint(m, lbl_803DEBCC, ss, negff, &ox, &oy, &oz);
    gViewFrustumPlanes[n * 5] = ox;
    py[n * 5] = oy;
    pz[n * 5] = oz;
    pd[n * 5] = -(zz * oz + (xx * ox + yy * oy));
    n++;
    frustumPlanes_updateAabbCornerIndices((FrustumPlane*)gViewFrustumPlanes, 5);
}

undefined4 FUN_8005af70(int idx)
{
    if ((-1 < idx) && (idx < (int)(uint)DAT_803ddb18))
    {
        return *(undefined4*)(DAT_803ddb1c + idx * 4);
    }
    return 0;
}

extern s16* lbl_803822A0[];
extern f32 gMapBlockWorldSize;
extern f32 fastFloorf(f32 v);
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

int FUN_8005b398(undefined8 param_1, double y)
{
    int block;
    int* layerTable;
    int cellX;
    int cellZ;
    double coord;
    undefined8 cvtTmp;

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
                    (cvtTmp = (double)CONCAT44(0x43300000,
                                                 (int)*(short*)(block + 0x8c) + 0x32U ^ 0x80000000),
                        y < (double)(float)(cvtTmp - DOUBLE_803df840)))
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
    uint cmpKey;
    int insertPtr;
    int srcPtr;
    int i;
    int j;
    uint key;
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
                key = *(uint*)(srcPtr + -4);
                insertPtr = queueBase + scratch;
                j = i;
                while ((gap < j &&
                    (cmpKey = *(uint*)(queueBase + (j - gap) * 4 + -4), cmpKey < key)))
                {
                    *(uint*)(insertPtr + -4) = cmpKey;
                    insertPtr = insertPtr + gap * -4;
                    j = j - gap;
                }
                *(uint*)(queueBase + j * 4 + -4) = key;
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

void FUN_8005bdbc(void)
{
    char* extraout_r4;
    char* pcVar1;
    int iVar2;
    int iVar3;
    char* pcVar4;
    int cellTable;
    int iVar6;
    int layer;
    int iVar8;
    uint uVar9;
    uint uVar10;
    undefined4* layerDat;
    int* layerTbl;
    int iVar13;
    double in_f29;
    double dVar14;
    double in_f30;
    double dVar15;
    double in_f31;
    double dVar16;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    int local_1c0;
    int local_1bc;
    int local_1b8;
    int local_1b4;
    int local_1b0;
    int local_1ac;
    int local_1a8;
    int local_1a4;
    int local_1a0;
    int local_19c;
    int local_198;
    int local_194;
    int local_190;
    int local_18c;
    int local_188;
    int local_184;
    char local_180[256];
    undefined4 local_80;
    uint uStack_7c;
    undefined4 local_78;
    uint uStack_74;
    float local_28;
    float fStack_24;
    float local_18;
    float fStack_14;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
    local_28 = (float)in_f29;
    fStack_24 = (float)in_ps29_1;
    FUN_80286818();
    layer = 4;
    layerTbl = &DAT_80382f24;
    layerDat = &DAT_80382efc;
    dVar15 = (double)lbl_803DF834;
    dVar16 = DOUBLE_803df840;
    do
    {
        cellTable = *layerTbl;
        DAT_803ddb08 = *layerDat;
        FUN_800566ec(DAT_803dda50 + 7, DAT_803dda54 + 7, &local_190, &local_1a0, &local_1b0, &local_1c0, layer
                     , 1, DAT_803ddb40);
        pcVar1 = local_180;
        iVar13 = 8;
        do
        {
            *pcVar1 = '\0';
            pcVar1[1] = '\0';
            pcVar1[2] = '\0';
            pcVar1[3] = '\0';
            pcVar1[4] = '\0';
            pcVar1[5] = '\0';
            pcVar1[6] = '\0';
            pcVar1[7] = '\0';
            pcVar1[8] = '\0';
            pcVar1[9] = '\0';
            pcVar1[10] = '\0';
            pcVar1[0xb] = '\0';
            pcVar1[0xc] = '\0';
            pcVar1[0xd] = '\0';
            pcVar1[0xe] = '\0';
            pcVar1[0xf] = '\0';
            pcVar1[0x10] = '\0';
            pcVar1[0x11] = '\0';
            pcVar1[0x12] = '\0';
            pcVar1[0x13] = '\0';
            pcVar1[0x14] = '\0';
            pcVar1[0x15] = '\0';
            pcVar1[0x16] = '\0';
            pcVar1[0x17] = '\0';
            pcVar1[0x18] = '\0';
            pcVar1[0x19] = '\0';
            pcVar1[0x1a] = '\0';
            pcVar1[0x1b] = '\0';
            pcVar1[0x1c] = '\0';
            pcVar1[0x1d] = '\0';
            pcVar1[0x1e] = '\0';
            pcVar1[0x1f] = '\0';
            pcVar1 = pcVar1 + 0x20;
            iVar13 = iVar13 + -1;
            iVar8 = local_188;
        }
        while (iVar13 != 0);
        for (; iVar13 = local_198, iVar8 <= local_184; iVar8 = iVar8 + 1)
        {
            pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_190;
            uVar10 = (local_18c + 1) - local_190;
            if (local_190 <= local_18c)
            {
                uVar9 = uVar10 >> 3;
                if (uVar9 != 0)
                {
                    do
                    {
                        builtin_strncpy(pcVar1 + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        pcVar1 = pcVar1 + 8;
                        uVar9 = uVar9 - 1;
                    }
                    while (uVar9 != 0);
                    uVar10 = uVar10 & 7;
                    if (uVar10 == 0) goto LAB_8005bfc4;
                }
                do
                {
                    pcVar1[7] = '\x01';
                    pcVar1 = pcVar1 + 1;
                    uVar10 = uVar10 - 1;
                }
                while (uVar10 != 0);
            }
        LAB_8005bfc4:
            ;
        }
        for (; iVar8 = local_1a8, iVar13 <= local_194; iVar13 = iVar13 + 1)
        {
            pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1a0;
            uVar10 = (local_19c + 1) - local_1a0;
            if (local_1a0 <= local_19c)
            {
                uVar9 = uVar10 >> 3;
                if (uVar9 != 0)
                {
                    do
                    {
                        builtin_strncpy(pcVar1 + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        pcVar1 = pcVar1 + 8;
                        uVar9 = uVar9 - 1;
                    }
                    while (uVar9 != 0);
                    uVar10 = uVar10 & 7;
                    if (uVar10 == 0) goto LAB_8005c058;
                }
                do
                {
                    pcVar1[7] = '\x01';
                    pcVar1 = pcVar1 + 1;
                    uVar10 = uVar10 - 1;
                }
                while (uVar10 != 0);
            }
        LAB_8005c058:
            ;
        }
        for (; iVar13 = local_1b8, iVar8 <= local_1a4; iVar8 = iVar8 + 1)
        {
            pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_1b0;
            uVar10 = (local_1ac + 1) - local_1b0;
            if (local_1b0 <= local_1ac)
            {
                uVar9 = uVar10 >> 3;
                if (uVar9 != 0)
                {
                    do
                    {
                        builtin_strncpy(pcVar1 + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        pcVar1 = pcVar1 + 8;
                        uVar9 = uVar9 - 1;
                    }
                    while (uVar9 != 0);
                    uVar10 = uVar10 & 7;
                    if (uVar10 == 0) goto LAB_8005c0ec;
                }
                do
                {
                    pcVar1[7] = '\x01';
                    pcVar1 = pcVar1 + 1;
                    uVar10 = uVar10 - 1;
                }
                while (uVar10 != 0);
            }
        LAB_8005c0ec:
            ;
        }
        for (; iVar13 <= local_1b4; iVar13 = iVar13 + 1)
        {
            pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1c0;
            uVar10 = (local_1bc + 1) - local_1c0;
            if (local_1c0 <= local_1bc)
            {
                uVar9 = uVar10 >> 3;
                if (uVar9 != 0)
                {
                    do
                    {
                        builtin_strncpy(pcVar1 + 7, "\x01\x01\x01\x01\x01\x01\x01\x01", 8);
                        pcVar1 = pcVar1 + 8;
                        uVar9 = uVar9 - 1;
                    }
                    while (uVar9 != 0);
                    uVar10 = uVar10 & 7;
                    if (uVar10 == 0) goto LAB_8005c180;
                }
                do
                {
                    pcVar1[7] = '\x01';
                    pcVar1 = pcVar1 + 1;
                    uVar10 = uVar10 - 1;
                }
                while (uVar10 != 0);
            }
        LAB_8005c180:
            ;
        }
        iVar13 = 0;
        pcVar1 = extraout_r4;
        do
        {
            uVar10 = (uint) * pcVar1;
            iVar8 = 0;
            uStack_7c = uVar10 ^ 0x80000000;
            local_80 = 0x43300000;
            dVar14 = (double)(float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,
                                                                               uVar10 ^ 0x80000000) -
                dVar16));
            pcVar4 = extraout_r4;
            do
            {
                uVar9 = (uint) * pcVar4;
                iVar3 = uVar10 + uVar9 * 0x10;
                iVar2 = (int)*(char*)(cellTable + iVar3);
                if (iVar2 < 0)
                {
                    iVar6 = 0;
                LAB_8005c210:
                    if ((-1 < iVar2) && (iVar2 = FUN_80057ce8(uVar10, uVar9, iVar6), iVar2 != 0))
                    {
                        lbl_803DDAD8 = (float)dVar14;
                        uStack_7c = uVar9 ^ 0x80000000;
                        local_80 = 0x43300000;
                        lbl_803DDAD4 =
                            lbl_803DF834 * (f32)(s32)
                        uStack_7c;
                        uStack_74 = (int)*(short*)(iVar6 + 0x8e) ^ 0x80000000;
                        local_78 = 0x43300000;
                        FUN_80247a48(dVar14, (f64)(f32)(s32)uStack_74, (double)lbl_803DDAD4,
                                     (undefined4*)(iVar6 + 0xc));
                        FUN_8005fb68();
                    }
                }
                else
                {
                    iVar6 = *(int*)(DAT_803ddb1c + iVar2 * 4);
                    *(ushort*)(iVar6 + 4) = *(ushort*)(iVar6 + 4) ^ 1;
                    if (local_180[iVar3] != '\0') goto LAB_8005c210;
                }
                iVar8 = iVar8 + 1;
                pcVar4 = pcVar4 + 1;
            }
            while (iVar8 < 0x10);
            iVar13 = iVar13 + 1;
            pcVar1 = pcVar1 + 1;
        }
        while (iVar13 < 0x10);
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

void FUN_8005cff0(int param_1)
{
    if (param_1 == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xfffdffff;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x20000;
    }
    return;
}

undefined4 FUN_8005d018(char param_1)
{
    if (param_1 == '\0')
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

uint FUN_8005d06c(void)
{
    return DAT_803dda68 & 8;
}

void FUN_8005d0ac(int param_1)
{
    undefined4* puVar1;

    puVar1 = FUN_800e87a8();
    if (param_1 == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xffffffbf;
        *(byte*)(puVar1 + 0x10) = *(byte*)(puVar1 + 0x10) & 0xf7;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x40;
        *(byte*)(puVar1 + 0x10) = *(byte*)(puVar1 + 0x10) | 8;
    }
    return;
}

void FUN_8005d17c(int param_1)
{
    undefined4* puVar1;

    puVar1 = FUN_800e87a8();
    if (param_1 == 0)
    {
        DAT_803dda68 = DAT_803dda68 & 0xffffffaf;
        *(byte*)(puVar1 + 0x10) = *(byte*)(puVar1 + 0x10) & 0xf6;
    }
    else
    {
        DAT_803dda68 = DAT_803dda68 | 0x50;
        *(byte*)(puVar1 + 0x10) = *(byte*)(puVar1 + 0x10) | 9;
    }
    return;
}

void FUN_8005d1e8(int param_1)
{
    if (param_1 == 0)
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
    volatile byte* fifo8;
    volatile ushort* fifo16;
    undefined2* vtx;
    int idx;
    int vtxAddr;
    int i;
    int corner;
    int cornerCount;

    fifo8 = (volatile byte*)&DAT_cc008000;
    fifo16 = (volatile ushort*)&DAT_cc008000;
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
            vtx = (undefined2*)(vtxTable + (uint) * (byte*)(indices + idx) * 0x10);
            *fifo16 = *vtx;
            *fifo16 = vtx[1];
            *fifo16 = vtx[2];
            vtxAddr = vtxTable + (uint) * (byte*)(indices + idx) * 0x10;
            *fifo8 = *(undefined*)(vtxAddr + 0xc);
            *fifo8 = *(undefined*)(vtxAddr + 0xd);
            *fifo8 = *(undefined*)(vtxAddr + 0xe);
            *fifo8 = *(undefined*)(vtxAddr + 0xf);
            idx = vtxTable + (uint) * (byte*)(indices + idx) * 0x10;
            *fifo16 = *(undefined2*)(idx + 8);
            *fifo16 = *(undefined2*)(idx + 10);
            corner = corner + 1;
            cornerCount = cornerCount + -1;
        }
        while (cornerCount != 0);
        indices = indices + 0x10;
    }
    return;
}

void FUN_8005d370(undefined4 param_1, undefined param_2, undefined param_3, undefined param_4,
                  undefined param_5)
{
    FUN_80071fb4(param_2, param_3, param_4, param_5);
    return;
}

void lightmap_queueObjectRenderEntry(int object, int sortGroup, int depthBias)
{
    int idx;
    uint sortKey;
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
    else if (0x7ffffff < (int)sortKey)
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
    undefined4 word1;
    undefined4 word3;
    undefined4 tmpWord;
    int prevIdx;
    int i;
    int gap;
    undefined4 word0;
    uint sortKey;
    int insertPos;
    undefined4* src;
    undefined4* packets;
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
                (prevIdx = j - gap, (uint)packets[prevIdx * 4 + 2] < sortKey)))
            {
                tmpWord = packets[prevIdx * 4 + 1];
                *(undefined4*)(insertPos + -0x10) = packets[prevIdx * 4];
                *(undefined4*)(insertPos + -0xc) = tmpWord;
                tmpWord = packets[prevIdx * 4 + 3];
                *(undefined4*)(insertPos + -8) = packets[prevIdx * 4 + 2];
                *(undefined4*)(insertPos + -4) = tmpWord;
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

void lightmap_renderQueuedObject(ushort* object)
{
    int val;

    val = FUN_80017a54((int)object);
    if (*(int*)(val + 0x58) == 0)
    {
        (*gModgfxInterface)->renderEffects(NULL, 0, 0, 1, object);
        FUN_8003f9f8();
        FUN_8003b878(0, 0, 0, 0, (int)object, 1);
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
    byte bval;
    float* mtx;
    int entryObj;
    int ref;
    int i;
    int* packet;
    undefined4 convHi0;
    uint convLo0;
    undefined4 convHi1;
    uint convLo1;
    undefined4 convHi2;
    uint convLo2;
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
            lightmap_renderQueuedObject((ushort*)*packet);
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
            FUN_80060a64((ushort*)*packet, ref);
            FUN_80006988();
            break;
        case 4:
            ref = packet[1];
            FUN_8025a608(0, 1, 0, 1, 0, 0, 2);
            FUN_8025a608(2, 0, 0, 1, 0, 0, 2);
            FUN_80080f88(0, (byte*)&convHi2, (byte*)((int)&convHi2 + 1), (byte*)((int)&convHi2 + 2));
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
            FUN_80080f88(0, (byte*)&convHi1, (byte*)((int)&convHi1 + 1), (byte*)((int)&convHi1 + 2));
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
            FUN_80080f88(0, (byte*)&convHi0, (byte*)((int)&convHi0 + 1), (byte*)((int)&convHi0 + 2));
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
            (**(code**)(*DAT_803dd718 + 0xc))(0, 0);
        }
        packet = packet + 4;
    }
    FUN_8028687c();
    return;
}

extern u32 lbl_8037E0C0[];
extern s32 lbl_803DCE30;
extern void sceneDrawTransparentPolys(void);
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
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = (u32)v | ((b & 0xff) << 27);
}
#pragma dont_inline reset

extern f32 CurrTiming_803DEC20;

void fn_8005D3B4(u8* obj, u8* model, s32 b)
{
    f32 stk[3];
    s32 t, v;
    f32 timing;
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    timing = CurrTiming_803DEC20;
    stk[0] = displayOffsetH_803DEBFC *
    (((f32)((GameObject*)obj)->anim.flags * timing + *(f32*)(model + 0x18)) +
        ((f32) * (s16*)(obj + 12) * timing + *(f32*)(model + 0x18)));
    stk[1] = displayOffsetH_803DEBFC *
    (((f32) * (s16*)(obj + 8) * timing + *(f32*)(model + 0x28)) +
        ((f32) * (s16*)(obj + 14) * timing + *(f32*)(model + 0x28)));
    stk[2] = displayOffsetH_803DEBFC *
    (((f32) * (s16*)(obj + 10) * timing + *(f32*)(model + 0x38)) +
        ((f32) * (s16*)(obj + 16) * timing + *(f32*)(model + 0x38)));
    PSMTXMultVec(Camera_GetViewMatrix(), stk, stk);
    t = (s32) - stk[2];
    v = t < 0 ? 0 : (t > 0x7ffffff ? 0x7ffffff : t);
    lbl_8037E0C0[lbl_803DCE30 * 4] = (u32)obj;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 1] = (u32)model;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = (u32)v | ((b & 0xff) << 27);
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
    lbl_8037E0C0[lbl_803DCE30 * 4 + 2] = (u32)v | 0x38000000;
    lbl_8037E0C0[lbl_803DCE30 * 4 + 3] = 7;
    lbl_803DCE30++;
}

extern u32 gVisibleObjectSortKeys[];
extern int lbl_803DCDF0;
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
    int idx;
    u8* obj;
    u8* state;
    u32 flags;
    int* p;
    int slot;
    int* objects;
    u32* keys;
    LightmapDrawQueue* qbase;

    qbase = (LightmapDrawQueue*)lbl_8037E0C0;
    objects = (int*)ObjList_GetObjects((int*)0, (int*)0);
    keys = (u32*)((u8*)qbase + 0x8818);
    for (i = 1; i < (int)gVisibleObjectSortKeyCount; i++)
    {
        idx = keys[i] & 0x3ff;
        obj = (u8*)objects[idx];
        flags = ((GameObject*)obj)->anim.modelInstance->flags;
        if ((flags & 0x800) != 0 || ((((GameObject*)obj)->anim.modelInstance->renderFlags & 0x10) != 0))
        {
            if (arg0[idx] != 0 && lbl_803DCDF0 < 0x14)
            {
                slot = lbl_803DCDF0;
                lbl_803DCDF0 = slot + 1;
                qbase->deferred[slot] = (u32)obj;
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
                ((LightmapQEnt*)qbase)[lbl_803DCE30].d = 2;
                lbl_803DCE30++;
            }
            else if (((GameObject*)obj)->anim.modelInstance->shadowType == 3 && (((GameObject*)obj)->anim.flags
                & OBJANIM_FLAG_HIDDEN) == 0 && (((GameObject*)obj)->anim.modelState->flags &
                OBJ_MODEL_STATE_SHADOW_VISIBLE))
            {
                renderShadowType3(obj, 0x13, 0);
                ((LightmapQEnt*)qbase)[lbl_803DCE30].d = 3;
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
extern void sceneDraw(void);
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

u32 getDrawDistanceFlag_8005cd48(void) { return renderFlags & 0x10000; }
u32 isWidescreen(void) { return renderFlags & 0x8; }
u32 shouldDrawShadows(void) { return renderFlags & 0x80; }
u32 shouldDrawClouds(void) { return renderFlags & 0x10; }

u32 isOvercast(void)
{
    u32 v = renderFlags & 0x40000;
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
    if (v != 0) renderFlags |= 0x40000;
    else renderFlags &= ~0x40000;
}

void fn_8005CECC(int v)
{
    if (v != 0) renderFlags |= 0x80000;
    else renderFlags &= ~0x80000;
}

void setPendingMapLoad(int v)
{
    if (v != 0) renderFlags |= 0x1000;
    else renderFlags &= ~0x1000;
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
    ix = (s32)fastFloorf(x / gMapBlockWorldSize);
    iz = (s32)fastFloorf(z / gMapBlockWorldSize);
    s = gMapBlockWorldSize;
    *outX = s * (f32)ix;
    *outZ = s * (f32)iz;
}

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
        for (i = 0; i < 5; i++)
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
    for (i = 0; i < 5; i++)
    {
        s8* table = (s8*)gMapBlockLayerTables[i];
        int idx = table[ix];
        if (idx > -1)
        {
            int* block = (int*)lbl_803DCE9C[idx];
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
    s8* table = (s8*)gMapBlockLayerTables[layer];
    s32 idx;
    if (x < 0 || y < 0 || x >= 0x10 || y >= 0x10) return 0;
    idx = table[x + (y << 4)];
    if (idx < 0 || idx >= lbl_803DCE98) return 0;
    return lbl_803DCE9C[idx];
}

extern f32 shdwChanged_803DEC18;
extern f32 widescreenAspect_803DEC1C;
extern f32 lbl_803DB670;
extern void Camera_SetAspectRatio(f32 ratio);

int setWidescreen(u8 v)
{
    if (v != 0)
    {
        renderFlags |= 0x8;
        Camera_SetAspectRatio(widescreenAspect_803DEC1C);
    }
    else
    {
        renderFlags &= ~8LL;
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

    countShifted = (int)*(u16*)((char*)obj + 0x84) << 3;
    modelRenderInstrsState_init(state, *(void**)((char*)obj + 0x78), countShifted, countShifted);
    modelRenderInstrsState_setBit(state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    mapBlockRender_drawDimmedAabbLights(p1, obj, p3);
    newR = mapBlockRender_setLightmapShader(obj, state);
    state[4] += 4;
    mapBlockRender_setVtxDcrs(1, (int)obj, newR, (int)state);
    cursor = state[4] + 4;
    state[4] = cursor;
    countShifted = cursor >> 3;
    v = ((u8*)state[0])[countShifted];
    base = (int*)(state[0] + countShifted);
    v = v | ((u32) * (u8*)((char*)base + 1) << 8);
    v = v | ((u32) * (u8*)((char*)base + 2) << 16);
    state[4] += 4;
    nibble = (v >> (cursor & 7)) & 0xf;
    for (i = 0; i < nibble; i++)
    {
        *(volatile int*)&state[4] = state[4] + 8;
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

    fn_8000F8F8();
    countShifted = (int)*(u16*)((char*)obj + 0x86) << 3;
    modelRenderInstrsState_init(state, *(void**)&((GameObject *)obj)->anim.banks, countShifted, countShifted);
    modelRenderInstrsState_setBit(state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    newR = mapBlockRender_setShader(1, obj, state);
    state[4] += 4;
    mapBlockRender_setVtxDcrs(1, (int)obj, newR, (int)state);
    cursor = state[4] + 4;
    state[4] = cursor;
    countShifted = cursor >> 3;
    v = ((u8*)state[0])[countShifted];
    base = (int*)(state[0] + countShifted);
    v = v | ((u32) * (u8*)((char*)base + 1) << 8);
    v = v | ((u32) * (u8*)((char*)base + 2) << 16);
    state[4] += 4;
    nibble = (v >> (cursor & 7)) & 0xf;
    for (i = 0; i < nibble; i++)
    {
        *(volatile int*)&state[4] = state[4] + 8;
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
    u32 v;
    int* base;
    int cursor;
    int nibble;
    int i;

    PSMTXConcat(lbl_80396850, p3, m);
    GXLoadTexMtxImm(m, 30, 0);
    PSMTXConcat(lbl_80396820, p3, m);
    GXLoadTexMtxImm(m, 33, 0);
    gxTextureSetupFn_8007cf7c();
    countShifted = (int)*(u16*)((char*)obj + 0x88) << 3;
    modelRenderInstrsState_init(state, *(void**)&((GameObject *)obj)->anim.previousLocalPosX, countShifted, countShifted);
    modelRenderInstrsState_setBit(state, (int)*(u16*)((char*)p1 + 0x14));
    state[4] += 4;
    newR = mapBlockRender_setShader(1, obj, state);
    state[4] += 4;
    mapBlockRender_setVtxDcrs(1, (int)obj, newR, (int)state);
    state[4] += 4;
    cursor = state[4];
    countShifted = cursor >> 3;
    v = ((u8*)state[0])[countShifted];
    base = (int*)(state[0] + countShifted);
    v = v | ((u32) * (u8*)((char*)base + 1) << 8);
    v = v | ((u32) * (u8*)((char*)base + 2) << 16);
    state[4] += 4;
    nibble = (v >> (cursor & 7)) & 0xf;
    for (i = 0; i < nibble; i++)
    {
        *(volatile int*)&state[4] = state[4] + 8;
    }
    state[4] += 4;
    mapBlockRender_callList(1, 1, obj, newR, state, p3);
}
#pragma dont_inline reset

extern void* lbl_803DCEA0;

int* mapRomListFindItem(int needle, int* out_idx, int* out_outer, int* out_type, int* out_lastpage)
{
    int outer;
    int* page;
    int* p;
    int inner_idx;
    int total_offset;
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

        while (total_offset < (int)limit)
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
extern int* Obj_GetPlayerObject(void);
extern int playerIsDisguised(int* obj);
extern void fn_802B4ED8(int* obj, int a, int b);
extern void objRenderFuzz(int* obj);
extern void drawFn_8006f500(void);
void objDrawFn_8005da48(int* obj);
void lightmap_sortTransparentDrawQueue(void);
extern void objGetColor(int slot, u8* red, u8* green, u8* blue);
extern void GXSetChanCtrl(int a, int b, int c, int d, int e, int f, int g);
extern void GXSetChanAmbColor(int chan, GXColor8* c);
extern void GXSetNumChans(int n);
extern void setupToRenderMapBlock(int* block, void* posMtx);

extern u32 cloudGetLayerTextureSize(f32 * a, f32 * b);
extern u32 lbl_803DCE34;
extern f32 shdwChangeMode_803DEC10;
extern int Camera_GetInverseViewMatrix(void);
extern void mapDebugRender(void* p);
extern void fn_80062894(void);
extern void fn_80062808(void);
extern u16 lbl_803DCEAC;
extern u8 lbl_803DCE06;
extern void drawReflectionTexture(void);
void getVisibleObjects(s8 * opacity);
extern void gxTextureFn_80052efc(void);
extern void perspectiveFn_80129db4(void);
extern void GXPixModeSync(void);
extern s32 heatEffectIntensity;
extern void drawSkyStars(void);
extern u8 lbl_803DCE05;
extern void screenImageDraw(void);
extern void lightningRenderActive(void);
extern void getAmbientColor(int slot, u8* r, u8* g, u8* b);
extern s8 lbl_8030E65C[];
extern s8 lbl_8030E66C[];
void renderSceneGeometry(int* p1, s8* order);
extern void renderResetFn_8003fc60(void);
extern u8 CameraShake_IsActive(void);
extern u8 bEnableMotionBlur;
extern f32 lbl_803DB62C;
extern void renderMotionBlur(f32 v);
extern int getHudHiddenFrameCount(void);
extern void updateReflectionTextures(void);
extern u8 bEnableBlurFilter;
extern f32 lbl_803DCE50;
extern f32 lbl_803DCE4C;
extern f32 blurFilterArea;
extern u8 bBlurFilterUseArea;
extern u8 bBiggerBlurFilter;
extern void doBlurFilter(f32 a, f32 b, f32 c, u8 d, u8 e);
extern void doHeatEffect(int v);
void sceneDrawTransparentPolys(void);
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
extern void setShadowFlag_803db658(int v);

void sceneDraw(void)
{
    char* q;
    u8* cursor;
    int* player;
    u8 flag;
    int t;
    int i;
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
    if ((renderFlags & 0x40000) != 0)
    {
        (*gSkyInterface)->renderTimeOfDayBackdrop(0, 0);
        if (flag != 0)
        {
            drawSkyStars();
        }
        (*gSkyInterface)->render();
        if ((renderFlags & 0x10) != 0)
        {
            (*gCloudActionInterface)->renderClouds(0, 0, 0, 0);
        }
    }
    else
    {
        (*gSkyInterface)->render();
        (*gCloudActionInterface)->renderClouds(0, 0, 0, 0);
        drawSkyStars();
    }
    if (lbl_803DCE05 != 0)
    {
        screenImageDraw();
    }
    lightningRenderActive();
    (*gSky2Interface)->applyFogColor(0);
    lbl_803DCDF0 = 0;
    getAmbientColor(0, (u8*)&c, (u8*)&c + 1, (u8*)&c + 2);
    GXSetChanCtrl(0, 1, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    ccopy = c;
    GXSetChanAmbColor(0, &ccopy);
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
    for (; i < lbl_803DCDF0; i++)
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
    ((u32*)(q + 8))[lbl_803DCE30 * 4] = 0x78000000;
    ((u32*)(q + 12))[lbl_803DCE30 * 4] = 8;
    lbl_803DCE30++;
    if (lbl_803DCE30 == 1000)
    {
        sceneDrawTransparentPolys();
        lbl_803DCE30 = 0;
    }
    ((u32*)(q + 8))[lbl_803DCE30 * 4] = 0x50000000;
    ((u32*)(q + 12))[lbl_803DCE30 * 4] = 9;
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
    int* e;
    int i;
    int* block;
    int* player;
    GXColor8 c4copy, c4;
    GXColor8 c5copy, c5;
    GXColor8 c6copy, c6;
    f32 m[16];

    lightmap_sortTransparentDrawQueue();
    i = 0;
    e = (int*)&lbl_8037E0C0;
    for (; i < lbl_803DCE30; i++)
    {
        switch (e[3])
        {
        case 0:
            expgfx_renderSourcePools(*e, 0);
            objDrawFn_8005da48((int*)*e);
            expgfx_renderSourcePools(*e, 1);
            break;
        case 1:
            block = (int*)*e;
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
            objShadowFn_80062498((int*)*e, 0, 0, framesThisStep);
            Camera_ApplyFullViewport();
            break;
        case 3:
            fn_8000F9B4();
            objDrawFn_80061654((int*)*e, Obj_GetActiveModel((int*)*e));
            Camera_ApplyFullViewport();
            break;
        case 4:
            block = (int*)e[1];
            GXSetChanCtrl(0, 1, 0, 1, 0, 0, 2);
            GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
            objGetColor(0, (u8*)&c4, (u8*)&c4 + 1, (u8*)&c4 + 2);
            c4copy = c4;
            GXSetChanAmbColor(0, &c4copy);
            GXSetNumChans(1);
            PSMTXConcat((f32*)Camera_GetViewMatrix(), (f32*)(block + 3), m);
            setupToRenderMapBlock(block, m);
            modelRenderFn_8005d894((int*)*e, (int*)e[1], m);
            break;
        case 5:
            block = (int*)e[1];
            GXSetChanCtrl(0, 1, 0, 1, 0, 0, 2);
            GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
            objGetColor(0, (u8*)&c5, (u8*)&c5 + 1, (u8*)&c5 + 2);
            c5copy = c5;
            GXSetChanAmbColor(0, &c5copy);
            GXSetNumChans(1);
            PSMTXConcat((f32*)Camera_GetViewMatrix(), (f32*)(block + 3), m);
            setupToRenderMapBlock(block, m);
            modelRenderFn_8005d69c((int*)*e, (int*)e[1], m);
            break;
        case 6:
            block = (int*)e[1];
            GXSetChanCtrl(0, 1, 0, 1, 0, 0, 2);
            GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
            objGetColor(0, (u8*)&c6, (u8*)&c6 + 1, (u8*)&c6 + 2);
            c6copy = c6;
            GXSetChanAmbColor(0, &c6copy);
            GXSetNumChans(1);
            PSMTXConcat((f32*)Camera_GetViewMatrix(), (f32*)(block + 3), m);
            setupToRenderMapBlock(block, m);
            modelRenderFn_8005d4ec((int*)*e, (int*)e[1], m);
            break;
        case 7:
            drawGlow((uint) * e, e[1]);
            break;
        case 8:
            drawFn_8006f500();
            break;
        case 9:
            (*gWaterfxInterface)->render(0, 0);
        }
        e = e + 4;
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
extern double lbl_803DEBC0;
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
    F64Cvt cv;
    F64Cvt cv2;
    u8 map[256];
    int box0[4];
    int box1[4];
    int box2[4];
    int box3[4];
    void** lt;
    int* lt2;
    int layer;
    s8* table;
    u8* p;
    u32 n;
    int y, x0, x1, y1;
    int k;
    int oi, ii;
    s8 *op, *ip;
    int row, col;
    f32 rowF, colF;
    int cell;
    int idx;
    u8* blk;
    f32 ws;
    double bias;
    int hi;

    layer = 4;
    lt = &gMapBlockLayerTables[4];
    lt2 = &lbl_8038228C[4];
    ws = gMapBlockWorldSize;
    bias = lbl_803DEBC0;
    hi = 0x43300000;
    do
    {
        table = (s8*)*lt;
        lbl_803DCE88 = *lt2;
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
            n = (box0[1] + 1) - box0[0];
            if (box0[0] <= box0[1])
            {
                while (n != 0)
                {
                    p[7] = 1;
                    p++;
                    n--;
                }
            }
        }
        for (y = box1[2]; y <= box1[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box1[0];
            n = (box1[1] + 1) - box1[0];
            if (box1[0] <= box1[1])
            {
                while (n != 0)
                {
                    p[7] = 1;
                    p++;
                    n--;
                }
            }
        }
        for (y = box2[2]; y <= box2[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box2[0];
            n = (box2[1] + 1) - box2[0];
            if (box2[0] <= box2[1])
            {
                while (n != 0)
                {
                    p[7] = 1;
                    p++;
                    n--;
                }
            }
        }
        for (y = box3[2]; y <= box3[3]; y++)
        {
            p = map + (y + 7) * 0x10 + box3[0];
            n = (box3[1] + 1) - box3[0];
            if (box3[0] <= box3[1])
            {
                while (n != 0)
                {
                    p[7] = 1;
                    p++;
                    n--;
                }
            }
        }
        oi = 0;
        op = order;
        for (; oi < 16; oi++)
        {
            row = *op;
            cv.u.lo = row ^ 0x80000000;
            cv.u.hi = hi;
            rowF = ws * (f32)(cv.d - bias);
            ii = 0;
            ip = order;
            for (; ii < 16; ii++)
            {
                col = *ip;
                cell = row + col * 0x10;
                idx = table[cell];
                if (idx < 0)
                {
                    blk = NULL;
                }
                else
                {
                    blk = (u8*)lbl_803DCE9C[idx];
                    *(u16*)(blk + 4) ^= 1;
                    if (map[cell] == 0)
                    {
                        goto next;
                    }
                }
                if (idx > -1 && mapRectFn_8005a728(row, col, blk) != 0)
                {
                    lbl_803DCE58 = rowF;
                    cv.u.lo = col ^ 0x80000000;
                    cv.u.hi = 0x43300000;
                    colF = gMapBlockWorldSize * (f32)(cv.d - lbl_803DEBC0);
                    lbl_803DCE54 = colF;
                    cv2.u.lo = (int)*(s16*)(blk + 0x8e) ^ 0x80000000;
                    cv2.u.hi = 0x43300000;
                    PSMTXTrans((f32*)(blk + 0xc), rowF, (f32)(cv2.d - lbl_803DEBC0), colF);
                    renderMapBlock(blk, p1);
                }
            next:
                ip++;
            }
            op++;
        }
        lt--;
        lt2--;
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
    LightSortEntry* arr;
    LightSortEntry tmp;
    while (gap <= (lbl_803DCE30 - 1) / 9)
        gap = gap * 3 + 1;
    arr = (LightSortEntry*)lbl_8037E0C0;
    while (gap > 0)
    {
        for (i = gap + 1; i <= lbl_803DCE30; i++)
        {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1].key < tmp.key)
            {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}

extern void maybeHudFn_8006c91c(void);
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
    int key;
    int depthInt;
    s8* cur;
    u8* sub;
    u8* att;
    int j;
    u8* s54;
    int* model;
    ObjModelInstance* modelDef;
    u32 tf;
    u32 mode;
    s16 t;
    int t1000;
    int count;
    int a, b;
    f32 depth;

    maybeHudFn_8006c91c();
    objects = (int*)ObjList_GetObjects((int*)0, (int*)0);
    part = ObjList_PartitionForRender(&count);
    i = 0;
    p = objects;
    cur = opacity;
    for (; i < count; i++)
    {
        o = (u8*)*p;
        modelDef = ((ObjAnimComponent*)o)->modelInstance;
        ((GameObject*)o)->objectFlags &= ~0x800;
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
            *cur = (s8)objUpdateOpacity(o);
            if (*cur != 0 || (modelDef->flags & 0x200000) != 0)
            {
                if ((modelDef->flags & 0x80000) != 0)
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
                    depthInt = (int)(changed_803DEC08.hi * (lbl_803DEBDC + depth));
                }
                if ((((GameObject*)o)->anim.flags & OBJANIM_FLAG_HIDDEN) == 0 &&
                    ((GameObject*)o)->anim.modelState != NULL &&
                    (((GameObject*)o)->anim.modelState->flags & OBJ_MODEL_STATE_SHADOW_VISIBLE) != 0)
                {
                    t = modelDef->shadowType;
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
                        ((tf = modelDef->flags) & 0x40000) == 0 &&
                        *(void**)(model + 0x16) == NULL)
                    {
                        key |= 0x80000000;
                        t1000 = 1000 - (depthInt & 0xffff);
                        if ((tf & 0x800000) != 0 && (((GameObject*)o)->colorFadeFlags & 2) == 0)
                        {
                            key |= 0x40000000;
                            key |= (((GameObject*)o)->anim.seqId & 0x3ff) << 20;
                        }
                        gVisibleObjectSortKeys[gVisibleObjectSortKeyCount] =
                            (i & 0x3ff) | (((t1000 & 0x3ff) << 10) | key);
                        gVisibleObjectSortKeyCount++;
                        if ((modelDef->renderFlags & 0x20) != 0 &&
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
                        if ((modelDef->flags & 0x800) != 0 ||
                            (modelDef->renderFlags & 0x10) != 0)
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
                        if ((modelDef->renderFlags & 0x20) != 0 &&
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
                s54 = (void*)((GameObject*)o)->anim.hitReactState;
                if (s54 != NULL && (s54[0x62] & 0x30) != 0)
                {
                    s54[0xaf] = 2;
                }
            }
        }
        p++;
        cur++;
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
    int gap = 1;
    int i, j;
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

extern void* mmAlloc(int size, int heap, int flags);
extern void loadAssetFileById(void** out, int id);
extern void* memset(void* dst, int val, u32 n);
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

void initMapBlocks(void)
{
    u8* mb = (u8*)lbl_8037E0C0;
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

    *(u32*)(mb + 0x41f8) = *(volatile u32*)(mb + 0x41f4) + 0x100;
    *(u32*)(mb + 0x41e4) = *(volatile u32*)(mb + 0x41e0) + 0xc00;
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

    q = (u32*)(mb + 0x83a8);
    for (i = 0; i < 3; i++)
    {
        q[0] = 0;
        q[1] = 0;
        q[2] = 0;
        q[3] = 0;
        q[4] = 0;
        q[5] = 0;
        q[6] = 0;
        q[7] = 0;
        q[8] = 0;
        q[9] = 0;
        q[10] = 0;
        q[11] = 0;
        q[12] = 0;
        q[13] = 0;
        q[14] = 0;
        q[15] = 0;
        q[16] = 0;
        q[17] = 0;
        q[18] = 0;
        q[19] = 0;
        q[20] = 0;
        q[21] = 0;
        q[22] = 0;
        q[23] = 0;
        q[24] = 0;
        q[25] = 0;
        q[26] = 0;
        q[27] = 0;
        q[28] = 0;
        q[29] = 0;
        q[30] = 0;
        q[31] = 0;
        q[32] = 0;
        q[33] = 0;
        q[34] = 0;
        q[35] = 0;
        q[36] = 0;
        q[37] = 0;
        q[38] = 0;
        q[39] = 0;
        q += 40;
    }

    loadAssetFileById(&lbl_803DCE84, 0x27);

    lbl_803DCE90 = 0;
    p = (u16*)lbl_803DCE84;
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

extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXBegin(int prim, int fmt, u16 nverts);

typedef union
{
    u8 u8;
    s16 s16;
    u16 u16;
    u32 u32;
    f32 f32;
} WGPipe;

volatile WGPipe wgfifo : (0xCC008000);

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
void drawFn_8005cf8c(int verts, u8* indices, int count)
{
    s16* p;
    int q, r;
    int i, j;

    GXClearVtxDesc();
    GXSetVtxDesc(0, 1);
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXBegin(0x90, 0, count * 3 & 0xffff);
    for (i = 0; i < count; i++)
    {
        for (j = 0; j < 3; j++)
        {
            GXPosition1x8(0);
            p = (s16*)(verts + indices[j + 1] * 0x10);
            GXPosition3s16(p[0], p[1], p[2]);
            q = verts + indices[j + 1] * 0x10;
            GXColor4u8(*(u8*)(q + 0xc), *(u8*)(q + 0xd), *(u8*)(q + 0xe), *(u8*)(q + 0xf));
            r = verts + indices[j + 1] * 0x10;
            GXTexCoord2s16(*(s16*)(r + 8), *(s16*)(r + 10));
        }
        indices = indices + 0x10;
    }
}

extern void envFxFn_80088884(void);
extern void* gMinimapInterface;
extern void* lbl_803DCAB0;
extern int textureAnimFn_80053f2c(void* tex, void* a, void* b);
extern void loadNextMap(void);
extern f32 timeDelta;
extern s32 lbl_803DCE00;

#pragma fp_contract off
#pragma peephole off
void updateEnvironment(int mode)
{
    if (mode == 0)
    {
        char* e;
        void* tex;
        int i, offs, k;
        f32 dy;

        envFxFn_80088884();
        (*gCloudActionInterface)->scrollTexture();
        (*gSky2Interface)->run();
        (*gSkyInterface)->updateTimeOfDay();
        (*gNewCloudsInterface)->run();

        i = 0;
        offs = i;
        do
        {
            e = (char*)lbl_803DCE6C + offs;
            if (*(s16*)(e + 12) != 0 && (tex = *(void**)e) != NULL &&
                *(u16*)((char*)tex + 0x10) != 0x100 && *(u16*)((char*)tex + 0x14) != 0)
            {
                textureAnimFn_80053f2c(tex, e + 8, e + 4);
            }
            offs += 0x10;
            i++;
        }
        while (i < 80);

        i = 0;
        offs = i;
        for (; i < 58; i++)
        {
            e = (char*)lbl_803DCE68 + offs;
            if (*(u8*)(e + 12) != 0)
            {
                dy = (f32) * (s16*)(e + 10) * timeDelta;
                *(f32*)e = *(f32*)e + (f32) * (s16*)(e + 8) * timeDelta;
                *(f32*)(e + 4) = *(f32*)(e + 4) + dy;
            }
            offs += 0x10;
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
