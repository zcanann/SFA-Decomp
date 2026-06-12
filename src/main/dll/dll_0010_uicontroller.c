#include "main/dll/objfsa_romcurve.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */
#include "main/dll/curve_walker.h"

#include "main/dll/rom_curve_segment_projection.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a18();
extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern RomCurveDef *romCurves[0x514];
extern int nRomCurves;
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined2 DAT_8039d748;
extern undefined4 DAT_8039d768;
extern undefined4 DAT_8039d76a;
extern undefined4 DAT_8039d76c;
extern short DAT_803a0748;
extern undefined4 DAT_803a0768;
extern undefined4 DAT_803a076a;
extern undefined4 DAT_803a076c;
extern undefined4 DAT_803a2390;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de0e0;
extern undefined4 DAT_803de0e4;
extern undefined4 DAT_803de0f0;
extern f64 DOUBLE_803e1260;
extern f64 DOUBLE_803e1268;
extern f64 DOUBLE_803e12a8;
extern f32 lbl_803E1248;
extern f32 lbl_803E124C;
extern f32 lbl_803E1250;
extern f32 lbl_803E1270;
extern f32 lbl_803E1274;
extern f32 lbl_803E1278;
extern f32 lbl_803E1290;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;

extern f32 lbl_803E05F0;

#define OBJFSA_PATCHGROUP_PATCH_COUNT 4

typedef struct ObjfsaPatchPlane
{
    s16 normalX;
    s16 normalZ;
} ObjfsaPatchPlane;

typedef struct ObjfsaPatch
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u16 groupId;
    s16 exit0X;
    s16 exit0Z;
    s16 exit1X;
    s16 exit1Z;
    u8 pad2E[2];
} ObjfsaPatch;

typedef struct ObjfsaWalkGroup
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u8 patchIndices[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroup;

extern ObjfsaPatch lbl_8039CAE8[];
extern ObjfsaWalkGroup lbl_8039FAE8[];
extern u8 lbl_803A1730[];

static inline ObjfsaPatch* Objfsa_GetPatch(int patchIndex)
{
    return &lbl_8039CAE8[patchIndex];
}

static inline ObjfsaWalkGroup* Objfsa_GetWalkGroup(int groupIndex)
{
    return &lbl_8039FAE8[groupIndex];
}

static inline u8* Objfsa_GetPatchGroupPatchList(int groupIndex)
{
    return Objfsa_GetWalkGroup(groupIndex)->patchIndices;
}

static inline u8 Objfsa_IsWalkGroupActive(int groupIndex)
{
    return lbl_803A1730[groupIndex];
}

static inline int Objfsa_IsPointInsidePatch(const float* point, const ObjfsaPatch* patch)
{
    int edgeIndex;

    if (point[1] >= (f32)patch->maxY || (f32)patch->minY >= point[1])
    {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++)
    {
        if (patch->planeOffsets[edgeIndex] +
            point[0] * (f32)patch->planes[edgeIndex].normalX +
            point[2] * (f32)patch->planes[edgeIndex].normalZ >
            lbl_803E05F0)
        {
            return 0;
        }
    }
    return 1;
}

static inline int Objfsa_IsPointInsideWalkGroup(const float* point,
                                                const ObjfsaWalkGroup* walkGroup)
{
    int edgeIndex;

    if (point[1] >= (f32)walkGroup->maxY || (f32)walkGroup->minY >= point[1])
    {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++)
    {
        if (walkGroup->planeOffsets[edgeIndex] +
            point[0] * (f32)walkGroup->planes[edgeIndex].normalX +
            point[2] * (f32)walkGroup->planes[edgeIndex].normalZ >
            lbl_803E05F0)
        {
            return 0;
        }
    }
    return 1;
}

static inline u16 Objfsa_GetLinkedWalkGroup(u16 patchGroupId, uint currentWalkGroupIndex)
{
    if (((countLeadingZeros(0xff - currentWalkGroupIndex) >> 5) & patchGroupId) != 0)
    {
        return (patchGroupId & 0xff00) >> 8;
    }
    return patchGroupId & 0xff;
}

extern u8 lbl_803DD440;

undefined4
FUN_800d9de0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9, float param_10, undefined4 param_11, undefined4 param_12,
             undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    undefined4 uVar2;
    undefined4 extraout_r4;
    undefined4 extraout_r4_00;
    double dVar3;
    double dVar4;

    fVar1 = param_9[0x28];
    if (((fVar1 == 0.0) || (param_9[0x29] == 0.0)) || (param_10 == 0.0))
    {
        uVar2 = 1;
    }
    else
    {
        if (param_9[0x20] == 0.0)
        {
            param_9[0x27] = fVar1;
            param_9[0x28] = param_9[0x29];
            param_9[0x29] = param_10;
            FUN_80003494((uint)(param_9 + 0x2a), (uint)(param_9 + 0x2e), 0x10);
            FUN_80003494((uint)(param_9 + 0x32), (uint)(param_9 + 0x36), 0x10);
            uVar2 = 0x10;
            FUN_80003494((uint)(param_9 + 0x3a), (uint)(param_9 + 0x3e), 0x10);
            param_9[0x2e] = *(float*)((int)param_9[0x28] + 8);
            param_9[0x2f] = *(float*)((int)param_9[0x29] + 8);
            dVar3 = (double)FUN_80293f90();
            param_9[0x30] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x28] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            param_9[0x31] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x29] + 0x2e) * dVar3);
            param_9[0x36] = *(float*)((int)param_9[0x28] + 0xc);
            param_9[0x37] = *(float*)((int)param_9[0x29] + 0xc);
            dVar3 = (double)FUN_80293f90();
            param_9[0x38] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x28] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            param_9[0x39] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x29] + 0x2e) * dVar3);
            param_9[0x3e] = *(float*)((int)param_9[0x28] + 0x10);
            param_9[0x3f] = *(float*)((int)param_9[0x29] + 0x10);
            dVar3 = (double)FUN_80294964();
            param_9[0x40] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x28] + 0x2e) * dVar3);
            dVar4 = (double)FUN_80294964();
            dVar3 = DOUBLE_803e1268;
            dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                     (uint) * (byte*)((int)param_9[0x29] +
                                                                         0x2e)) -
                DOUBLE_803e1268) * dVar4);
            param_9[0x41] = (float)((double)lbl_803E1250 * dVar4);
            if (param_9[0x24] != 0.0)
            {
                FUN_80006a18(dVar4, dVar3, param_3, param_4, param_5, param_6, param_7, param_8, (int)param_9,
                             extraout_r4_00, uVar2, param_12, param_13, param_14, param_15, param_16);
                if (lbl_803E1248 <= *param_9)
                {
                    *param_9 = lbl_803E124C;
                }
            }
        }
        else
        {
            param_9[0x27] = fVar1;
            param_9[0x28] = param_9[0x29];
            param_9[0x29] = param_10;
            FUN_80003494((uint)(param_9 + 0x2e), (uint)(param_9 + 0x2a), 0x10);
            FUN_80003494((uint)(param_9 + 0x36), (uint)(param_9 + 0x32), 0x10);
            uVar2 = 0x10;
            FUN_80003494((uint)(param_9 + 0x3e), (uint)(param_9 + 0x3a), 0x10);
            param_9[0x2a] = *(float*)((int)param_9[0x29] + 8);
            param_9[0x2b] = *(float*)((int)param_9[0x28] + 8);
            dVar3 = (double)FUN_80293f90();
            param_9[0x2c] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x29] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            param_9[0x2d] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x28] + 0x2e) * dVar3);
            param_9[0x32] = *(float*)((int)param_9[0x29] + 0xc);
            param_9[0x33] = *(float*)((int)param_9[0x28] + 0xc);
            dVar3 = (double)FUN_80293f90();
            param_9[0x34] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x29] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            param_9[0x35] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x28] + 0x2e) * dVar3);
            param_9[0x3a] = *(float*)((int)param_9[0x29] + 0x10);
            param_9[0x3b] = *(float*)((int)param_9[0x28] + 0x10);
            dVar3 = (double)FUN_80294964();
            param_9[0x3c] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)param_9[0x29] + 0x2e) * dVar3);
            dVar4 = (double)FUN_80294964();
            dVar3 = DOUBLE_803e1268;
            dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                     (uint) * (byte*)((int)param_9[0x28] +
                                                                         0x2e)) -
                DOUBLE_803e1268) * dVar4);
            param_9[0x3d] = (float)((double)lbl_803E1250 * dVar4);
            if (param_9[0x24] != 0.0)
            {
                FUN_80006a18(dVar4, dVar3, param_3, param_4, param_5, param_6, param_7, param_8, (int)param_9,
                             extraout_r4, uVar2, param_12, param_13, param_14, param_15, param_16);
                if (*param_9 <= lbl_803E1270)
                {
                    *param_9 = lbl_803E1274;
                }
            }
        }
        uVar2 = 0;
    }
    return uVar2;
}

void FUN_800da594(double param_1, float* param_2)
{
    if (lbl_803E1270 < *param_2)
    {
        if (lbl_803E1248 <= *param_2)
        {
            *param_2 = lbl_803E124C;
        }
    }
    else
    {
        *param_2 = lbl_803E1274;
    }
    FUN_80006a10(param_1, param_2);
    return;
}

bool FUN_800da5e8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  float* param_9, float param_10, float param_11, float param_12, undefined4 param_13,
                  undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

void FUN_800da700(undefined4 param_1, undefined4 param_2, int param_3)
{
    float fVar1;
    float fVar2;
    float fVar3;
    float* pfVar4;
    int* piVar5;
    uint uVar6;
    int iVar7;
    int iVar8;
    double dVar9;
    double in_f31;
    double dVar10;
    double in_ps31_1;
    undefined8 uVar11;
    int local_38[12];
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    uVar11 = FUN_80286838();
    pfVar4 = (float*)((ulonglong)uVar11 >> 0x20);
    piVar5 = (int*)(**(code**)(*DAT_803dd71c + 0x10))(local_38);
    dVar10 = (double)lbl_803E1278;
    for (iVar8 = 0; iVar8 < local_38[0]; iVar8 = iVar8 + 1)
    {
        iVar7 = *piVar5;
        if ((((((iVar7 != 0) && (*(char*)(iVar7 + 0x19) == '$')) &&
                        (((uint)uVar11 == 0xffffffff || ((uint) * (byte*)(iVar7 + 3) == (uint)uVar11)))) &&
                    ((param_3 == -1 || (*(char*)(iVar7 + 0x1a) == param_3)))) &&
                (((int)*(short*)(iVar7 + 0x30) == 0xffffffff ||
                    (uVar6 = GameBit_Get((int)*(short*)(iVar7 + 0x30)), uVar6 != 0)))) &&
            ((((int)*(short*)(iVar7 + 0x32) == 0xffffffff ||
                    (uVar6 = GameBit_Get((int)*(short*)(iVar7 + 0x32)), uVar6 == 0)) &&
                (fVar1 = *pfVar4 - *(float*)(iVar7 + 8), fVar2 = pfVar4[1] - *(float*)(iVar7 + 0xc),
                    fVar3 = pfVar4[2] - *(float*)(iVar7 + 0x10),
                    dVar9 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2), dVar9 < dVar10))))
        {
            dVar10 = dVar9;
        }
        piVar5 = piVar5 + 1;
    }
    FUN_80286884();
    return;
}

void FUN_800da850(uint param_1, undefined* param_2)
{
    *param_2 = (char)(param_1 & 0xffff);
    param_2[1] = (char)((param_1 & 0xffff) >> 8);
    return;
}

undefined2
FUN_800db110(float* param_1, int param_2, undefined4 param_3, undefined4 param_4, byte param_5)
{
    byte bVar1;
    uint uVar2;
    uint uVar3;

    bVar1 = 0;
    do
    {
        if (3 < bVar1)
        {
            return 0;
        }
        if (((&DAT_803a2390)[param_2] != '\0') &&
            (uVar2 = (uint)(byte)(&DAT_803a076c)[param_2 * 0x28 + (uint)bVar1], uVar2 != 0))
        {
            if ((param_1[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000
                ) - DOUBLE_803e1260) < param_1[1]))
            {
                param_5 = 0;
                uVar3 = 0;
                while ((param_5 < 4 &&
                    (*(float*)(&DAT_8039d748 + uVar2 * 0x18 + (uint)param_5 * 2 + 8) +
                        *param_1 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d748)[uVar2 * 0x18 + (uVar3 & 0xff)]
                                                 ^ 0x80000000) - DOUBLE_803e1260) +
                        param_1[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d748)
                                                 [uVar2 * 0x18 + (uVar3 & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    param_5 = param_5 + 1;
                    uVar3 = uVar3 + 2;
                }
            }
            if (param_5 == 4)
            {
                return (&DAT_8039d76c)[uVar2 * 0x18];
            }
        }
        bVar1 = bVar1 + 1;
    }
    while (true);
}

void FUN_800db47c(float* param_1, undefined* param_2)
{
    uint uVar1;
    uint uVar2;
    byte bVar3;
    uint uVar4;
    uint uVar5;
    byte unaff_r31;

    uVar2 = FUN_800db820(param_1);
    if ((param_2 != (undefined*)0x0) && ((uVar2 & 0xff) != 0))
    {
        *param_2 = (char)uVar2;
        param_2[1] = 0;
        uVar1 = 1;
        for (bVar3 = 0; bVar3 < 4; bVar3 = bVar3 + 1)
        {
            uVar5 = (uint)bVar3;
            uVar4 = (uint)(byte)(&DAT_803a076c)[(uVar2 & 0xff) * 0x28 + uVar5];
            if (uVar4 == 0)
            {
                *(undefined2*)(param_2 + uVar5 * 2 + 2) = 0;
            }
            else
            {
                *(undefined2*)(param_2 + uVar5 * 2 + 2) = (&DAT_8039d76c)[uVar4 * 0x18];
                if (param_1[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_8039d768)[uVar4 * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260))
                {
                    if ((float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d76a)[uVar4 * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260) < param_1[1])
                    {
                        uVar5 = 0;
                        for (unaff_r31 = 0; unaff_r31 < 4; unaff_r31 = unaff_r31 + 1)
                        {
                            if (lbl_803E1270 <
                                *(float*)(&DAT_8039d748 + uVar4 * 0x18 + (uint)unaff_r31 * 2 + 8) +
                                *param_1 *
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039d748)
                                                         [uVar4 * 0x18 + (uVar5 & 0xff)] ^ 0x80000000)
                                    - DOUBLE_803e1260) +
                                param_1[2] *
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039d748)
                                                         [uVar4 * 0x18 + (uVar5 & 0xff) + 1] ^
                                                         0x80000000) - DOUBLE_803e1260))
                                break;
                            uVar5 = uVar5 + 2;
                        }
                    }
                }
                if (unaff_r31 == 4)
                {
                    param_2[1] = param_2[1] | (byte)uVar1;
                }
            }
            uVar1 = (uVar1 & 0x7f) << 1;
        }
    }
    return;
}

ushort FUN_800db690(float* param_1)
{
    uint uVar1;
    byte bVar2;
    undefined2* puVar3;
    int iVar4;

    puVar3 = &DAT_8039d748;
    iVar4 = DAT_803de0e4;
    if (0 < DAT_803de0e4)
    {
        do
        {
            if ((param_1[1] <
                    (float)((double)CONCAT44(0x43300000, (int)(short)puVar3[0x10] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)puVar3[0x11] ^ 0x80000000) -
                    DOUBLE_803e1260) < param_1[1]))
            {
                bVar2 = 0;
                uVar1 = 0;
                while ((bVar2 < 4 &&
                    (*(float*)(puVar3 + (uint)bVar2 * 2 + 8) +
                        *param_1 *
                        (float)((double)CONCAT44(0x43300000, (int)(short)puVar3[uVar1 & 0xff] ^ 0x80000000) -
                            DOUBLE_803e1260) +
                        param_1[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)puVar3[(uVar1 & 0xff) + 1] ^ 0x80000000) -
                            DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    bVar2 = bVar2 + 1;
                    uVar1 = uVar1 + 2;
                }
                if (bVar2 == 4)
                {
                    return puVar3[0x12];
                }
            }
            puVar3 = puVar3 + 0x18;
            iVar4 = iVar4 + -1;
        }
        while (iVar4 != 0);
    }
    return 0;
}

int FUN_800db820(float* param_1)
{
    short sVar1;
    short sVar2;
    uint uVar3;
    int iVar4;
    byte bVar5;

    sVar2 = (short)DAT_803de0e0;
    if (DAT_803de0e0 == 0xb4)
    {
        sVar1 = 0;
    }
    else
    {
        sVar1 = sVar2 + 1;
    }
    do
    {
        iVar4 = (int)sVar2;
        if (iVar4 == sVar1)
        {
            if ((&DAT_803a2390)[iVar4] != '\0')
            {
                if ((param_1[1] <
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                            DOUBLE_803e1260)) &&
                    ((float)((double)CONCAT44(0x43300000,
                                              (int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000) -
                        DOUBLE_803e1260) < param_1[1]))
                {
                    bVar5 = 0;
                    uVar3 = 0;
                    while ((bVar5 < 4 &&
                        (*(float*)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                            *param_1 *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff)] ^ 0x80000000)
                                - DOUBLE_803e1260) +
                            param_1[2] *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                                     0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                    {
                        bVar5 = bVar5 + 1;
                        uVar3 = uVar3 + 2;
                    }
                    if (bVar5 == 4)
                    {
                        DAT_803de0e0 = (int)sVar2;
                        return (int)sVar2;
                    }
                }
            }
            return 0;
        }
        iVar4 = (int)sVar2;
        if ((&DAT_803a2390)[iVar4] != '\0')
        {
            if ((param_1[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                ) - DOUBLE_803e1260) < param_1[1]))
            {
                bVar5 = 0;
                uVar3 = 0;
                while ((bVar5 < 4 &&
                    (*(float*)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                        *param_1 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                                 ^ 0x80000000) - DOUBLE_803e1260) +
                        param_1[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)
                                                 [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    bVar5 = bVar5 + 1;
                    uVar3 = uVar3 + 2;
                }
                if (bVar5 == 4)
                {
                    DAT_803de0e0 = (int)sVar2;
                    return (int)sVar2;
                }
            }
        }
        iVar4 = (int)sVar1;
        if ((&DAT_803a2390)[iVar4] != '\0')
        {
            if ((param_1[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                ) - DOUBLE_803e1260) < param_1[1]))
            {
                bVar5 = 0;
                uVar3 = 0;
                while ((bVar5 < 4 &&
                    (*(float*)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                        *param_1 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                                 ^ 0x80000000) - DOUBLE_803e1260) +
                        param_1[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)
                                                 [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    bVar5 = bVar5 + 1;
                    uVar3 = uVar3 + 2;
                }
                if (bVar5 == 4)
                {
                    DAT_803de0e0 = (int)sVar1;
                    return (int)sVar1;
                }
            }
        }
        sVar2 = sVar2 + -1;
        if (sVar2 == -1)
        {
            sVar2 = 0xb4;
        }
        sVar1 = sVar1 + 1;
        if (sVar1 == 0xb5)
        {
            sVar1 = 0;
        }
    }
    while (true);
}

undefined4
FUN_800dd3e4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9, undefined4 param_10, uint param_11)
{
    return 0;
}

undefined4
FUN_800dd62c(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9, uint param_10, undefined4 param_11, int param_12, int param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    uint uVar1;
    undefined4 extraout_r4;
    undefined4 extraout_r4_00;
    undefined4 uVar2;
    float fVar3;
    double dVar4;
    double dVar5;

    if (((param_9 != (float*)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0))
    {
        param_9[0x27] = param_9[0x28];
        param_9[0x28] = param_9[0x29];
        FUN_80003494((uint)(param_9 + 0x2a), (uint)(param_9 + 0x2e), 0x10);
        FUN_80003494((uint)(param_9 + 0x32), (uint)(param_9 + 0x36), 0x10);
        FUN_80003494((uint)(param_9 + 0x3a), (uint)(param_9 + 0x3e), 0x10);
        if (param_9[0x20] == 0.0)
        {
            uVar1 = FUN_800dd50c((int)param_9[0x28], -1, param_10);
        }
        else
        {
            uVar1 = FUN_800dd3ec((int)param_9[0x28], -1, param_10);
        }
        if (uVar1 == 0xffffffff)
        {
            param_9[0x29] = 0.0;
        }
        else
        {
            if ((int)uVar1 < 0)
            {
                fVar3 = 0.0;
            }
            else
            {
                param_13 = DAT_803de0f0 + -1;
                param_12 = 0;
                while (param_12 <= param_13)
                {
                    param_10 = param_13 + param_12 >> 1;
                    fVar3 = (float)(int)romCurves[param_10];
                    if (*(uint*)((int)fVar3 + 0x14) < uVar1)
                    {
                        param_12 = param_10 + 1;
                    }
                    else
                    {
                        if (*(uint*)((int)fVar3 + 0x14) <= uVar1) goto LAB_800de544;
                        param_13 = param_10 - 1;
                    }
                }
                fVar3 = 0.0;
            }
        LAB_800de544:
            param_9[0x29] = fVar3;
            if (param_9[0x29] != 0.0)
            {
                if (param_9[0x20] == 0.0)
                {
                    param_9[0x2e] = *(float*)((int)param_9[0x28] + 8);
                    param_9[0x2f] = *(float*)((int)param_9[0x29] + 8);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x29] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    param_9[0x36] = *(float*)((int)param_9[0x28] + 0xc);
                    param_9[0x37] = *(float*)((int)param_9[0x29] + 0xc);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x29] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    param_9[0x3e] = *(float*)((int)param_9[0x28] + 0x10);
                    param_9[0x3f] = *(float*)((int)param_9[0x29] + 0x10);
                    dVar4 = (double)FUN_80294964();
                    param_9[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar5 = (double)FUN_80294964();
                    dVar4 = DOUBLE_803e12a8;
                    dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                             (uint) * (byte*)((int)param_9[0x29
                                                                             ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
                    param_9[0x41] = (float)((double)lbl_803E1290 * dVar5);
                    uVar2 = extraout_r4_00;
                }
                else
                {
                    param_9[0x2e] = *(float*)((int)param_9[0x28] + 8);
                    param_9[0x2f] = *(float*)((int)param_9[0x27] + 8);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x27] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    param_9[0x36] = *(float*)((int)param_9[0x28] + 0xc);
                    param_9[0x37] = *(float*)((int)param_9[0x27] + 0xc);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    param_9[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x27] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    param_9[0x3e] = *(float*)((int)param_9[0x28] + 0x10);
                    param_9[0x3f] = *(float*)((int)param_9[0x27] + 0x10);
                    dVar4 = (double)FUN_80294964();
                    param_9[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)param_9[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar5 = (double)FUN_80294964();
                    dVar4 = DOUBLE_803e12a8;
                    dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                             (uint) * (byte*)((int)param_9[0x27
                                                                             ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
                    param_9[0x41] = (float)((double)lbl_803E1290 * dVar5);
                    uVar2 = extraout_r4;
                }
                if (param_9[0x24] != 0.0)
                {
                    FUN_80006a18(dVar5, dVar4, param_3, param_4, param_5, param_6, param_7, param_8, (int)param_9,
                                 uVar2, param_10, param_12, param_13, fVar3, param_15, param_16);
                }
                if (param_9[0x20] == 0.0)
                {
                    FUN_80006a10((double)lbl_803E12B4, param_9);
                }
                else
                {
                    FUN_80006a10((double)lbl_803E12B0, param_9);
                }
                return 0;
            }
        }
    }
    return 1;
}

undefined4
FUN_800ddf84(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9, float param_10, undefined4 param_11, undefined4 param_12,
             undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

undefined4
FUN_800ddf8c(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9)
{
    undefined4 extraout_r4;
    undefined4 extraout_r4_00;
    undefined4 uVar1;
    int iVar2;
    int iVar3;
    float fVar4;
    uint uVar5;
    float fVar6;
    undefined4 in_r9;
    undefined4 in_r10;
    double dVar7;
    double dVar8;
    uint local_88[4];
    uint local_78[4];
    undefined4 local_68;
    uint uStack_64;
    undefined4 local_60;
    uint uStack_5c;
    undefined4 local_58;
    uint uStack_54;
    undefined4 local_50;
    uint uStack_4c;
    undefined4 local_48;
    uint uStack_44;
    undefined4 local_40;
    uint uStack_3c;
    undefined4 local_38;
    uint uStack_34;
    undefined4 local_30;
    uint uStack_2c;
    undefined4 local_28;
    uint uStack_24;
    undefined4 local_20;
    uint uStack_1c;
    undefined4 local_18;
    uint uStack_14;
    undefined4 local_10;
    uint uStack_c;

    if (((param_9 != (float*)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0))
    {
        param_9[0x27] = param_9[0x28];
        param_9[0x28] = param_9[0x29];
        FUN_80003494((uint)(param_9 + 0x2a), (uint)(param_9 + 0x2e), 0x10);
        FUN_80003494((uint)(param_9 + 0x32), (uint)(param_9 + 0x36), 0x10);
        FUN_80003494((uint)(param_9 + 0x3a), (uint)(param_9 + 0x3e), 0x10);
        if (param_9[0x20] == 0.0)
        {
            fVar4 = param_9[0x28];
            iVar2 = 0;
            uVar5 = *(uint*)((int)fVar4 + 0x1c);
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 1) == 0)) && (uVar5 != 0xffffffff))
            {
                iVar2 = 1;
                local_88[0] = uVar5;
            }
            uVar5 = *(uint*)((int)fVar4 + 0x20);
            iVar3 = iVar2;
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 2) == 0)) && (uVar5 != 0xffffffff))
            {
                iVar3 = iVar2 + 1;
                local_88[iVar2] = uVar5;
            }
            uVar5 = *(uint*)((int)fVar4 + 0x24);
            iVar2 = iVar3;
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 4) == 0)) && (uVar5 != 0xffffffff))
            {
                iVar2 = iVar3 + 1;
                local_88[iVar3] = uVar5;
            }
            uVar5 = *(uint*)((int)fVar4 + 0x28);
            iVar3 = iVar2;
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 8) == 0)) && (uVar5 != 0xffffffff))
            {
                iVar3 = iVar2 + 1;
                local_88[iVar2] = uVar5;
            }
            if (iVar3 == 0)
            {
                uVar5 = 0xffffffff;
            }
            else
            {
                uVar5 = randomGetRange(0, iVar3 - 1);
                uVar5 = local_88[uVar5];
            }
        }
        else
        {
            fVar4 = param_9[0x28];
            iVar2 = 0;
            uVar5 = *(uint*)((int)fVar4 + 0x1c);
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 1) != 0)) && (uVar5 != 0xffffffff))
            {
                iVar2 = 1;
                local_78[0] = uVar5;
            }
            uVar5 = *(uint*)((int)fVar4 + 0x20);
            iVar3 = iVar2;
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 2) != 0)) && (uVar5 != 0xffffffff))
            {
                iVar3 = iVar2 + 1;
                local_78[iVar2] = uVar5;
            }
            uVar5 = *(uint*)((int)fVar4 + 0x24);
            iVar2 = iVar3;
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 4) != 0)) && (uVar5 != 0xffffffff))
            {
                iVar2 = iVar3 + 1;
                local_78[iVar3] = uVar5;
            }
            uVar5 = *(uint*)((int)fVar4 + 0x28);
            iVar3 = iVar2;
            if (((-1 < (int)uVar5) && ((*(byte*)((int)fVar4 + 0x1b) & 8) != 0)) && (uVar5 != 0xffffffff))
            {
                iVar3 = iVar2 + 1;
                local_78[iVar2] = uVar5;
            }
            if (iVar3 == 0)
            {
                uVar5 = 0xffffffff;
            }
            else
            {
                uVar5 = randomGetRange(0, iVar3 - 1);
                uVar5 = local_78[uVar5];
            }
        }
        if (uVar5 == 0xffffffff)
        {
            param_9[0x29] = 0.0;
        }
        else
        {
            if ((int)uVar5 < 0)
            {
                fVar6 = 0.0;
            }
            else
            {
                fVar4 = (float)(DAT_803de0f0 + -1);
                iVar3 = 0;
                while (iVar3 <= (int)fVar4)
                {
                    iVar2 = (int)fVar4 + iVar3 >> 1;
                    fVar6 = (float)(int)romCurves[iVar2];
                    if (*(uint*)((int)fVar6 + 0x14) < uVar5)
                    {
                        iVar3 = iVar2 + 1;
                    }
                    else
                    {
                        if (*(uint*)((int)fVar6 + 0x14) <= uVar5) goto LAB_800df42c;
                        fVar4 = (float)(iVar2 + -1);
                    }
                }
                fVar6 = 0.0;
            }
        LAB_800df42c:
            param_9[0x29] = fVar6;
            if (param_9[0x29] != 0.0)
            {
                if (param_9[0x20] == 0.0)
                {
                    param_9[0x2e] = *(float*)((int)param_9[0x28] + 8);
                    param_9[0x2f] = *(float*)((int)param_9[0x29] + 8);
                    uStack_c = (int)*(char*)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_10 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_14 = (uint) * (byte*)((int)param_9[0x28] + 0x2e);
                    local_18 = 0x43300000;
                    param_9[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_14) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_1c = (int)*(char*)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
                    local_20 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_24 = (uint) * (byte*)((int)param_9[0x29] + 0x2e);
                    local_28 = 0x43300000;
                    param_9[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_24) - DOUBLE_803e12a8) *
                            dVar7);
                    param_9[0x36] = *(float*)((int)param_9[0x28] + 0xc);
                    param_9[0x37] = *(float*)((int)param_9[0x29] + 0xc);
                    uStack_2c = (int)*(char*)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
                    local_30 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_34 = (uint) * (byte*)((int)param_9[0x28] + 0x2e);
                    local_38 = 0x43300000;
                    param_9[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_34) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_3c = (int)*(char*)((int)param_9[0x29] + 0x2d) << 8 ^ 0x80000000;
                    local_40 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_44 = (uint) * (byte*)((int)param_9[0x29] + 0x2e);
                    local_48 = 0x43300000;
                    param_9[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_44) - DOUBLE_803e12a8) *
                            dVar7);
                    param_9[0x3e] = *(float*)((int)param_9[0x28] + 0x10);
                    param_9[0x3f] = *(float*)((int)param_9[0x29] + 0x10);
                    uStack_4c = (int)*(char*)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_50 = 0x43300000;
                    dVar7 = (double)FUN_80294964();
                    uStack_54 = (uint) * (byte*)((int)param_9[0x28] + 0x2e);
                    local_58 = 0x43300000;
                    param_9[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_54) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_5c = (int)*(char*)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
                    local_60 = 0x43300000;
                    dVar8 = (double)FUN_80294964();
                    dVar7 = DOUBLE_803e12a8;
                    uStack_64 = (uint) * (byte*)((int)param_9[0x29] + 0x2e);
                    local_68 = 0x43300000;
                    dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000, uStack_64) -
                        DOUBLE_803e12a8) * dVar8);
                    param_9[0x41] = (float)((double)lbl_803E1290 * dVar8);
                    uVar1 = extraout_r4_00;
                }
                else
                {
                    param_9[0x2e] = *(float*)((int)param_9[0x28] + 8);
                    param_9[0x2f] = *(float*)((int)param_9[0x27] + 8);
                    uStack_64 = (int)*(char*)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_68 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_5c = (uint) * (byte*)((int)param_9[0x28] + 0x2e);
                    local_60 = 0x43300000;
                    param_9[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_5c) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_54 = (int)*(char*)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
                    local_58 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_4c = (uint) * (byte*)((int)param_9[0x27] + 0x2e);
                    local_50 = 0x43300000;
                    param_9[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_4c) - DOUBLE_803e12a8) *
                            dVar7);
                    param_9[0x36] = *(float*)((int)param_9[0x28] + 0xc);
                    param_9[0x37] = *(float*)((int)param_9[0x27] + 0xc);
                    uStack_44 = (int)*(char*)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
                    local_48 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_3c = (uint) * (byte*)((int)param_9[0x28] + 0x2e);
                    local_40 = 0x43300000;
                    param_9[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_3c) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_34 = (int)*(char*)((int)param_9[0x27] + 0x2d) << 8 ^ 0x80000000;
                    local_38 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_2c = (uint) * (byte*)((int)param_9[0x27] + 0x2e);
                    local_30 = 0x43300000;
                    param_9[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_2c) - DOUBLE_803e12a8) *
                            dVar7);
                    param_9[0x3e] = *(float*)((int)param_9[0x28] + 0x10);
                    param_9[0x3f] = *(float*)((int)param_9[0x27] + 0x10);
                    uStack_24 = (int)*(char*)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_28 = 0x43300000;
                    dVar7 = (double)FUN_80294964();
                    uStack_1c = (uint) * (byte*)((int)param_9[0x28] + 0x2e);
                    local_20 = 0x43300000;
                    param_9[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_1c) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_14 = (int)*(char*)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
                    local_18 = 0x43300000;
                    dVar8 = (double)FUN_80294964();
                    dVar7 = DOUBLE_803e12a8;
                    uStack_c = (uint) * (byte*)((int)param_9[0x27] + 0x2e);
                    local_10 = 0x43300000;
                    dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000, uStack_c) -
                        DOUBLE_803e12a8) * dVar8);
                    param_9[0x41] = (float)((double)lbl_803E1290 * dVar8);
                    uVar1 = extraout_r4;
                }
                if (param_9[0x24] != 0.0)
                {
                    FUN_80006a18(dVar8, dVar7, param_3, param_4, param_5, param_6, param_7, param_8, (int)param_9,
                                 uVar1, iVar3, fVar4, fVar6, uVar5, in_r9, in_r10);
                }
                if (param_9[0x20] == 0.0)
                {
                    FUN_80006a10((double)lbl_803E12B4, param_9);
                }
                else
                {
                    FUN_80006a10((double)lbl_803E12B0, param_9);
                }
                return 0;
            }
        }
    }
    return 1;
}

undefined4
FUN_800de998(double param_1, undefined8 param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, float* param_9, int param_10,
             undefined4 param_11, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    return 0;
}

int curves_findNearObj(int obj, int* curveTypes, int typeCount, int action, char bboxMode);

static inline int Objfsa_FindRomCurveById(int curveId)
{
    int lo;
    int hi;
    int mid;
    int curve;
    u32 id;

    if (curveId < 0)
    {
        return 0;
    }

    lo = 0;
    hi = nRomCurves - 1;
    id = (u32)curveId;
    while (lo <= hi)
    {
        mid = (hi + lo) >> 1;
        curve = (int)romCurves[mid];
        if (id > ((ObjfsaRomCurveDef*)curve)->id)
        {
            lo = mid + 1;
        }
        else if (id < ((ObjfsaRomCurveDef*)curve)->id)
        {
            hi = mid - 1;
        }
        else
        {
            return curve;
        }
    }

    return 0;
}

f32 curves_lengthFn24(u32 a, u32 b, f32* posA, f32* posB, f32 t1, f32 t2);

/* Trivial 4b 0-arg blr leaves. */

void UIController_release(void)
{
}

void UIController_initialise(void)
{
}

void dll_12_func0A_nop(void);

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */

/* player_init: memset constructor */

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */
extern f32 lbl_803E05D0;
extern f32 lbl_803E05D4;
extern f32 lbl_803E05D8;

/* player_updateVel */

/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */

static inline f32 RomCurveNode_GetHermiteTangent(void* node, int angleOffset, int useSin)
{
    extern float mathCosf(double x); /* #57 */
    extern float mathSinf(double angle); /* #57 */
    f32 angle;
    f32 trig;

    angle = lbl_803E05D4 * (f32)((s32) * (s8*)((char*)node + angleOffset) << 8) / lbl_803E05D8;
    if (useSin)
    {
        trig = mathCosf(angle);
    }
    else
    {
        trig = mathSinf(angle);
    }
    return lbl_803E05D0 * ((f32)(u32) * (u8*)((char*)node + 0x2e) * trig);
}

int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx);

int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx);

/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */

/* UIController dispatch through the shared GameUI interface. */
extern u8 gameTimerIsRunning(void* p, int a, int b);
extern void hudNumberFn_80014060(void* p);
extern void gameTimerRun(void* p);
void UIController_frameStart(void)
{
    (*gGameUIInterface)->frameStart();
}

void UIController_frameEnd(void)
{
    (*gGameUIInterface)->frameEnd();
}
#pragma scheduling off
#pragma peephole off
void UIController_render(void* p, int a, int b)
{
    if (gameTimerIsRunning(p, a, b) != 0)
    {
        gameTimerRun(p);
    }
    hudNumberFn_80014060(p);
    (*gGameUIInterface)->render(p, a, b);
}

/* player_setState */
void player_setState(void* ctx, void* p, int new_state);

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */

/* segment pragma-stack balance (re-split): */

#include "main/dll/dll_0015_curves.h"
#include "main/game_ui_interface.h"
#include "main/objlib.h"
#include "main/game_object.h"

/* Hcurves keeps the ROM curve definitions sorted by id for binary searches. */

static inline u32 RomCurve_GetId(RomCurveDef* curve);

static inline int RomCurve_IsLinkIdValid(int linkId);

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId);

#pragma fp_contract off
#pragma fp_contract reset

static inline int RomCurve_noUnblockedLinks(RomCurvePlacementDef* curve);

static inline int RomCurve_noBlockedLinks(RomCurvePlacementDef* curve);

/*
 * Retail source-tag string: Hcurves.c: MAX_ROMCURVES exceeded!!
 */

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

/* Forward active hit-segment bounds to ObjHits with the state-derived target mask. */

/* Extended local-point collision setup with a secondary hit type. */

/* Basic local-point collision setup used by path control. */

/* Trivial 4b 0-arg blr leaves. */

/* Pattern wrappers. */

/* getSaveFileStruct: return &saveData (lis/addi). */

/* getLastSavedGameTexts: return (u8*)&gSaveGameData + 0x558. Array form forces lis/addi. */

/* RomCurve_getCurves: *outCount = nRomCurves; return romCurves. */

/* isCheatUnlocked: return registeredDebugOptions & (1 << (idx & 0xff)). */

/* saveFileStruct_unlockCheat: set bit (1 << (idx & 0xff)) in registeredDebugOptions. */

/* curves_findByAction: scan romCurves for matching action curves, return curve id. */

/* RomCurve_segmentIntersectsOriginRayXZ: 2D segment-intersection predicate.
 * Returns 1 if the segment between (x, z) and the origin in the xz-plane
 * crosses the segment between a and b. */
