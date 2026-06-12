#include "main/dll/objfsa_romcurve.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"

extern void OSReport(const char* fmt, ...);

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */
#include "main/dll/curve_walker.h"

#include "main/dll/rom_curve_segment_projection.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a18();
extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit, int obj, int p7,
                              int p8, int p9, int p10);
extern RomCurveDef* RomCurve_findByIdWithIndex(uint curveId, int* outIndex);
extern int mathFn_800dbff0(float* point);
extern RomCurveDef *romCurves[0x514];
extern int nRomCurves;
extern f32 RomCurve_distanceToSegment(f32 x, f32 y, f32 z, RomCurveSegmentProjection* segment);
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern f32 sqrtf(f32 x);
extern uint countLeadingZeros();
extern void voxmaps_worldToGrid(f32 * world, s16 * grid);
extern int voxmaps_traceLine(s16* start, s16* end, void* coordOut, u8* occOut, int skipFirst);

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
extern f32 lbl_803E12BC;
extern f32 lbl_803E12C0;
extern f32 gFloatOne;

extern f32 lbl_803E05F0;
extern f32 lbl_803E0644;
extern int lbl_803DD460;
extern int lbl_803DD464;
extern int lbl_803DD468;
extern char sObjfsaFoundNewWalkGroupPatch[];
extern char sObjfsaIsPointWithinPatchGroupError[];

#define OBJFSA_PATCHGROUP_PATCH_COUNT 4
#define OBJFSA_PATCHGROUP_STRIDE 0x28
#define OBJFSA_ACTIVE_WALKGROUPS_OFFSET 0x4C48
#define OBJFSA_WALKGROUP_COUNT 0xB5

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

typedef struct ObjfsaWalkGroupPatchInfo
{
    u8 walkGroupIndex;
    u8 patchMask;
    u16 patchGroupIds[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroupPatchInfo;

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

/*
 * --INFO--
 *
 * Function: player_setScale
 * EN v1.0 Address: 0x800D8F90
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800D8FE0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803DD440;


#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_800d9090
 * EN v1.0 Address: 0x800D9090
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x800D9108
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_800d9de0
 * EN v1.0 Address: 0x800D9DE0
 * EN v1.0 Size: 1972b
 * EN v1.1 Address: 0x800DA4C8
 * EN v1.1 Size: 1772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800da594
 * EN v1.0 Address: 0x800DA594
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x800DABB4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800da5e8
 * EN v1.0 Address: 0x800DA5E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DAC0C
 * EN v1.1 Size: 1628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_800da5e8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  float* param_9, float param_10, float param_11, float param_12, undefined4 param_13,
                  undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_800da700
 * EN v1.0 Address: 0x800DA700
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800DB36C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800da850
 * EN v1.0 Address: 0x800DA850
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x800DB4B0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da850(uint param_1, undefined* param_2)
{
    *param_2 = (char)(param_1 & 0xffff);
    param_2[1] = (char)((param_1 & 0xffff) >> 8);
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_800db110
 * EN v1.0 Address: 0x800DB110
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x800DBCD8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_800db47c
 * EN v1.0 Address: 0x800DB47C
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x800DBF88
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800db690
 * EN v1.0 Address: 0x800DB690
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x800DC158
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800db820
 * EN v1.0 Address: 0x800DB820
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: 0x800DC27C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_800dd3e4
 * EN v1.0 Address: 0x800DD3E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DD8CC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800dd3e4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9, undefined4 param_10, uint param_11)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_800dd62c
 * EN v1.0 Address: 0x800DD62C
 * EN v1.0 Size: 2048b
 * EN v1.1 Address: 0x800DE41C
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_800ddf84
 * EN v1.0 Address: 0x800DDF84
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DED20
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800ddf84(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* param_9, float param_10, undefined4 param_11, undefined4 param_12,
             undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800ddf8c
 * EN v1.0 Address: 0x800DDF8C
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800DF0DC
 * EN v1.1 Size: 2428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_800de998
 * EN v1.0 Address: 0x800DE998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DFA58
 * EN v1.1 Size: 2400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800de998(double param_1, undefined8 param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, float* param_9, int param_10,
             undefined4 param_11, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: curves_findNearObj
 * EN v1.0 Address: 0x800E0134
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x800E03B8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int curves_findNearObj(int obj, int* curveTypes, int typeCount, int action, char bboxMode);

/*
 * --INFO--
 *
 * Function: FUN_800dece0
 * EN v1.0 Address: 0x800DECE0
 * EN v1.0 Size: 1476b
 * EN v1.1 Address: 0x800E0670
 * EN v1.1 Size: 1572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on


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

/*
 * --INFO--
 *
 * Function: curves_lengthFn24
 * EN v1.0 Address: 0x800E0E18
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x800E109C
 * EN v1.1 Size: 1888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
f32 curves_lengthFn24(u32 a, u32 b, f32* posA, f32* posB, f32 t1, f32 t2);

/*
 * --INFO--
 *
 * Function: curves_getPos
 * EN v1.0 Address: 0x800E1578
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x800E17FC
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: walkGroupFn_800db3e4
 * EN v1.0 Address: 0x800DB3E4
 * EN v1.0 Size: 1268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int walkGroupFn_800db3e4(float* prevPoint, float* nextPoint, uint currentWalkGroupIndex);

/*
 * --INFO--
 *
 * Function: isPointWithinPatchGroup
 * EN v1.0 Address: 0x800DB8D8
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint isPointWithinPatchGroup(float* point, uint patchGroupIndex, int groupId);

/*
 * --INFO--
 *
 * Function: getPatchGroup
 * EN v1.0 Address: 0x800DBA4C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u16 getPatchGroup(float* point, int patchGroupIndex, undefined4 param_3, undefined4 param_4, u8 startPatchIndex);

/*
 * --INFO--
 *
 * Function: isInWalkGroupOrPatch
 * EN v1.0 Address: 0x800DBBA4
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole on
uint isInWalkGroupOrPatch(float* point);

/*
 * --INFO--
 *
 * Function: Objfsa_GetWalkGroupIndexAtPoint
 * EN v1.0 Address: 0x800DBCFC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
int Objfsa_GetWalkGroupIndexAtPoint(float* point, ObjfsaWalkGroupPatchInfo* patchInfo);

/*
 * --INFO--
 *
 * Function: Objfsa_GetPatchGroupIdAtPoint
 * EN v1.0 Address: 0x800DBECC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u16 Objfsa_GetPatchGroupIdAtPoint(float* point);

/*
 * --INFO--
 *
 * Function: mathFn_800dbff0
 * EN v1.0 Address: 0x800DBFF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#define WALKGROUP_TRY_RETURN(idx)                                                  \
    if (Objfsa_IsWalkGroupActive(idx)) {                                           \
        g = &lbl_8039FAE8[idx];                                                    \
        y = point[1];                                                              \
        if (y < (f32)g->maxY && y > (f32)g->minY) {                                \
            z = point[2];                                                          \
            x = point[0];                                                          \
            i = 0;                                                                 \
            j = i;                                                                 \
            for (; i < 4; i++, j += 2) {                                           \
                if (g->planeOffsets[i] +                                           \
                        (x * (f32)((s16 *)g)[j] + z * (f32)((s16 *)g)[j + 1]) >    \
                    0.0f) {                                                        \
                    break;                                                         \
                }                                                                  \
            }                                                                      \
            if (i == 4) {                                                          \
                lbl_803DD464 = (idx);                                              \
                return (idx);                                                      \
            }                                                                      \
        }                                                                          \
    }

int mathFn_800dbff0(float* point);

/*
 * --INFO--
 *
 * Function: RomCurve_findProjectedCurveFromStart
 * EN v1.0 Address: 0x800DFE64
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x800E1A4C
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling on
#pragma peephole on
void player_release(void);


void UIController_release(void);

void UIController_initialise(void);

void dll_12_func0A_nop(void)
{
}

void dll_12_func08_nop(void)
{
}

void dll_12_func07_nop(void)
{
}

void dll_12_func04_nop(void)
{
}

void dll_12_func03_nop(void)
{
}

void dll_12_func05_nop(void)
{
}

void Dummy12_release(void)
{
}

void Dummy12_initialise(void)
{
}

void doNothing_onTrickyFree(void);

void doNothing_onTrickyInit(void);

/* 8b "li r3, N; blr" returners. */
int dll_12_func06_ret_0(void) { return 0x0; }

/* sda21 accessors. */
extern u32 playerOverride;

/* Pattern wrappers. */
extern u32 lbl_803DD458;
void dll_12_func09(void) { lbl_803DD458 = 0x3; }

/* player_init: memset constructor */
extern void* memset(void* dst, int val, u32 n);
extern f32 lbl_803E05C8;
extern f32 lbl_803E05CC;
extern f32 lbl_803E05F4;
extern int Curve_AdvanceAlongPath(float* p, f32 dt);
#pragma scheduling off
#pragma peephole off
void player_init(int unused, void* obj, int a, int b);

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */
extern f32 lbl_803E05D0;
extern f32 lbl_803E05D4;
extern f32 lbl_803E05D8;

int fn_800D9F38(void* a, void* b);

/* player_updateVel */
extern f32 lbl_803E05A4;
extern void fn_800D915C(int pos, int* obj, void* fnTable, f32 fval);



void player_updateVel(char* p, char* obj, int unused);


/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */
extern f32 lbl_803E0610;
extern f32 lbl_803E0614;
extern f32 lbl_803E0618;

void RomCurve_setA4(void* a, void* b);

extern void Curve_BuildHermiteCoeffs(void);
extern void Curve_EvalHermite(void);
extern void curvesMove(float* state);
extern void curvesSetupMoveNetworkCurve(float* state);
extern f32 gFloatZero;
extern f32 gFloatNegOne;
extern void* memcpy(void* dst, const void* src, u32 n);

int RomCurve_setClosed(float* state, int closed);

#define ROMCURVE_ADD_LINK(off, mask, wantSet)                                     \
    neighborId = *(s32 *)(curve + (off));                                         \
    if (neighborId > -1 && (((*(s8 *)(curve + 0x1b) & (mask)) != 0) == (wantSet)) && \
        neighborId != -1) {                                                       \
        candidateIds[candidateCount++] = neighborId;                              \
    }

#define ROMCURVE_REFRESH_CONTROL(secondOff)                                       \
    *(f32 *)(stateBytes + 0xb8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0x8);    \
    *(f32 *)(stateBytes + 0xbc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0x8); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2c) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xc0) = lbl_803E0610 * t;                               \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2c) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xc4) = lbl_803E0610 * t;                               \
    *(f32 *)(stateBytes + 0xd8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0xc);    \
    *(f32 *)(stateBytes + 0xdc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0xc); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2d) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xe0) = lbl_803E0610 * t;                               \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2d) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xe4) = lbl_803E0610 * t;                               \
    *(f32 *)(stateBytes + 0xf8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0x10);   \
    *(f32 *)(stateBytes + 0xfc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0x10); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathCosf(lbl_803E0614 *                                                        \
            (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2c) << 8) / lbl_803E0618); \
    *(f32 *)(stateBytes + 0x100) = lbl_803E0610 * t;                              \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathCosf(lbl_803E0614 *                                                        \
            (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2c) << 8) / \
            lbl_803E0618);                                                        \
    *(f32 *)(stateBytes + 0x104) = lbl_803E0610 * t

u8 RomCurve_goNextPoint(float* state);


#pragma scheduling on
#pragma peephole on
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
int RomCurve_getControlPointId_2B(int curve, int exclude, int pickIdx);


#pragma scheduling off
#pragma peephole off
int RomCurve_func29(float* state, int pickIdx);

int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx);

int RomCurve_getControlPointId_2B(int curve, int exclude, int pickIdx);

extern f32 lbl_803E0648;
extern f32 lbl_803E064C;
extern f32 lbl_803E0650;
extern f32 lbl_803E0654;

int RomCurve_findProjectedCurveFromStart(f32 x, f32 y, f32 z, int curve, float* outPhase);

void curves_getPos(f32 phase, int curve, float* outX, float* outY, float* outZ);


int RomCurve_func2C(float* state, int unused, int startCurveId);

int RomCurve_get(float* state, int obj, int* curveTypes, int curveType, f32 maxDistance);

int RomCurve_func1C(u32 startCurve, int unused1, int unused2, int* previousCurveId);

/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */
#pragma peephole on
void RomCurve_stepClamped(float* state, f32 dt);


extern int curveFn_800da23c(float* state, void* targetCurve);

#pragma peephole off
int curveFn_800da23c(float* state, void* targetCurve);

#pragma peephole on
int fn_800DA980(float* state, void* fromCurve, void* toCurve, void* targetCurve);

extern f32 lbl_803E05F8;

#pragma peephole off
void* Objfsa_FindNearestCurveType24(int pos, int p4_filter, int p5_filter);

void* Objfsa_FindNearestEnabledCurveType24(int pos, int p4_filter, int p5_filter);


extern void mapBlockFn_80059c2c(u8 * outFlags);
extern f32 lbl_803E0600;
extern f32 lbl_803E0604;
extern f32 lbl_803E05FC;

extern f32 lbl_803E0608;
extern f32 lbl_803E060C;
extern char sObjfsaMissingPatchExitPoint0[];
extern char sObjfsaMissingPatchExitPoint1[];

#define OBJFSA_CORNER(BASE, OFF, POSOFF)                                        \
    (f32)((f32)*(s8 *)(OFF) * scale + *(f32 *)((BASE) + (POSOFF)))

#define OBJFSA_SET_PLANE(P, K, XA, ZA)                                          \
    len = sqrtf(dxn * dxn + dzn * dzn);                                         \
    if (len != lbl_803E05F0) {                                                  \
        dxn = dxn / len;                                                        \
        dzn = dzn / len;                                                        \
    }                                                                           \
    (P).planes[K].normalX = (s16)(lbl_803E05FC * dxn);                          \
    (P).planes[K].normalZ = (s16)(lbl_803E05FC * dzn);                          \
    (P).planeOffsets[K] = -((f32)(P).planes[K].normalX * (XA) +                 \
                            (f32)(P).planes[K].normalZ * (ZA))

#define OBJFSA_WG(GRP) ((ObjfsaWalkGroup *)((char *)patchBase + (GRP) * OBJFSA_PATCHGROUP_STRIDE + 0x3000))

#define OBJFSA_EXIT_INSIDE(GRP, XF, ZF)                                         \
    ez = (f32)(ZF);                                                             \
    ex = (f32)(XF);                                                             \
    j2 = 0;                                                                     \
    for (e = 0; e < 4; e++) {                                                   \
        if (lbl_803E05F0 <                                                      \
            OBJFSA_WG(GRP)->planeOffsets[e] +                                   \
                ex * (f32)((s16 *)OBJFSA_WG(GRP))[j2 & 0xff] +                  \
                ez * (f32)((s16 *)OBJFSA_WG(GRP))[(j2 & 0xff) + 1]) {           \
            break;                                                              \
        }                                                                       \
        j2 += 2;                                                                \
    }

#define OBJFSA_NEWPATCH (patchBase[lbl_803DD468])

void walkgroupFindExitPointFn_800dc398(void);

int RomCurve_func1B(double x, double y, double z, int curve, int preferredNeighborId);

int RomCurve_func16(double x, double y, double z);

/* UIController dispatch through the shared GameUI interface. */
extern u8 gameTimerIsRunning(void* p, int a, int b);
extern void hudNumberFn_80014060(void* p);
extern void gameTimerRun(void* p);
#pragma scheduling on
#pragma peephole on
void UIController_frameStart(void);

void UIController_frameEnd(void);
#pragma scheduling off
#pragma peephole off
void UIController_render(void* p, int a, int b);

/* player_setState */
void player_setState(void* ctx, void* p, int new_state);

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */
void walkPath_writeU16LE(u32 v, u8* dst);

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */
#pragma scheduling on
void fn_800D9EE8(float* p);


#pragma scheduling off
int fn_800DB240(int p1, f32* outVec, u16 id);

void fn_800D915C(int p1, int* obj, void* fnTable, f32 fval);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/curves.c [800E1B24-800E5434) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/dll/dll_0015_curves.h"
#include "main/game_ui_interface.h"
#include "main/objlib.h"
#include "main/game_object.h"


extern f32 vec3f_distanceSquared(f32 * posA, f32 * posB);

/* Hcurves keeps the ROM curve definitions sorted by id for binary searches. */
extern f32 gFloatHalf;
extern f32 lbl_803E12B8;
extern f32 lbl_803E065C;
extern f32 lbl_803E0660;
extern f32 lbl_803E0664;



static inline u32 RomCurve_GetId(RomCurveDef* curve);

static inline int RomCurve_IsLinkIdValid(int linkId);

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId);

int RomCurve_segmentIntersectsOriginRayXZ(RomCurveDef* a, RomCurveDef* b, f32 x, f32 unusedY,
                                          f32 z, f32 unusedW);

/*
 * --INFO--
 *
 * Function: RomCurve_projectPointToAdjacentWindow
 * EN v1.0 Address: 0x800E1B24
 * EN v1.0 Size: 1048b
 * EN v1.1 Address: 0x800E1DA8
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 RomCurve_projectPointToAdjacentWindow(f32 x, f32 y, f32 z, u32* curveIds, float* outLateralOffset, float* outVerticalOffset, float* outPhase);


/*
 * --INFO--
 *
 * Function: curves_distFn15
 * EN v1.0 Address: 0x800E1FF4
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E2278
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int curves_distFn15(u32 curveId, f32 x, f32 y, f32 z, f32* outDistance);

/*
 * --INFO--
 *
 * Function: curves_distanceToNearestOfType16
 * EN v1.0 Address: 0x800E2214
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x800E2498
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int curves_distanceToNearestOfType16(f32 x, f32 y, f32 z, int queryAll);

/*
 * --INFO--
 *
 * Function: RomCurve_func13
 * EN v1.0 Address: 0x800E2090
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: 0x800E260C
 * EN v1.1 Size: 1416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#define SQ(v) ((v) * (v))

int RomCurve_func13(uint curveId, int typeFilter, uint maxDist, int* outLink);

/*
 * --INFO--
 *
 * Function: RomCurve_func11
 * EN v1.0 Address: 0x800E2590
 * EN v1.0 Size: 1528b
 * EN v1.1 Address: 0x800E2B94
 * EN v1.1 Size: 1612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma fp_contract off
int RomCurve_func11(RomCurveDef* curve, int typeFilter, int actionFilter, int* outCurveId);
#pragma fp_contract reset

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomLinkedOfTypes
 * EN v1.0 Address: 0x800E2F5C
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x800E31E0
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getRandomLinkedOfTypes(RomCurveDef* curve, int* types, int typeCount, int* previousLinkId);

/*
 * --INFO--
 *
 * Function: curves_distXZ
 * EN v1.0 Address: 0x800E3330
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x800E35B4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 curves_distXZ(f32 x, f32 z, uint curveId);

/*
 * --INFO--
 *
 * Function: curves_distFn0B
 * EN v1.0 Address: 0x800E33E0
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x800E3664
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 curves_distFn0B(int obj, uint curveId);

int curves_isNotPoint(RomCurveDef* curve);

int curves_isPoint(RomCurveDef* curve);

/*
 * --INFO--
 *
 * Function: curves_find
 * EN v1.0 Address: 0x800E34B0
 * EN v1.0 Size: 564b
 * EN v1.1 Address: 0x800E3734
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 curves_find(int type, int action, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ);

/*
 * --INFO--
 *
 * Function: RomCurve_findByIdWithIndex
 * EN v1.0 Address: 0x800E36F8
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800E397C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
RomCurveDef* RomCurve_findByIdWithIndex(uint curveId, int* outIndex);

/*
 * --INFO--
 *
 * Function: RomCurve_func20
 * EN v1.0 Address: 0x800E31DC
 * EN v1.0 Size: 2296b
 * EN v1.1 Address: 0x800E3A00
 * EN v1.1 Size: 2996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#define ROMCURVE_PLACEMENT_ANGLE(v) ((lbl_803E0614 * (f32)((s32)(v) << 8)) / lbl_803E0618)

static inline int RomCurve_noUnblockedLinks(RomCurvePlacementDef* curve);

static inline int RomCurve_noBlockedLinks(RomCurvePlacementDef* curve);

int RomCurve_func20(RomCurvePlacementDef* curve, f32* outX, f32* outY, f32* outZ, s8* outTypes);

/*
 * --INFO--
 *
 * Function: RomCurve_countRandomPoints
 * EN v1.0 Address: 0x800E3AD4
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E45B4
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_countRandomPoints(RomCurveDef* curve);

/*
 * --INFO--
 *
 * Function: RomCurve_func1E
 * EN v1.0 Address: 0x800E3CEC
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x800E4854
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_func1E(uint* curveIds, float* outX, float* outY, float* outZ);

/*
 * --INFO--
 *
 * Function: RomCurve_getAdjacentWindow
 * EN v1.0 Address: 0x800E47C4
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x800E4A48
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void RomCurve_getAdjacentWindow(RomCurveDef* curve, int* outIds);

/*
 * --INFO--
 *
 * Function: RomCurve_getNearestAdjacentLink
 * EN v1.0 Address: 0x800E4A00
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x800E4C84
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getNearestAdjacentLink(f32 x, f32 y, f32 z, RomCurveDef* curve, int excludeLinkId);

/*
 * --INFO--
 *
 * Function: RomCurve_distanceToSegment
 * EN v1.0 Address: 0x800E4BE4
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x800E4E68
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 RomCurve_distanceToSegment(f32 x, f32 y, f32 z, RomCurveSegmentProjection* segment);

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomBlockedLink
 * EN v1.0 Address: 0x800E4D28
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x800E4FAC
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getRandomBlockedLink(RomCurveDef* curve, int excludeLinkId);

/*
 * --INFO--
 *
 * Function: RomCurve_getLinkIds
 * EN v1.0 Address: 0x800E4E64
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getLinkIds(RomCurveDef* curve, int excludeLinkId, int* outIds);

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomUnblockedLink
 * EN v1.0 Address: 0x800E4F00
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x800E5184
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getRandomUnblockedLink(RomCurveDef* curve, int excludeLinkId);

/*
 * --INFO--
 *
 * Function: RomCurve_getById
 * EN v1.0 Address: 0x800E503C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
RomCurveDef* RomCurve_getById(uint curveId);

/*
 * --INFO--
 *
 * Function: RomCurve_find
 * EN v1.0 Address: 0x800E4628
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x800E5330
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_find(int* types, int typeCount, f32 x, f32 y, f32 z, int action);

/*
 * --INFO--
 *
 * Function: curves_remove
 * EN v1.0 Address: 0x800E51EC
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_remove(RomCurveDef* curve);

/*
 * --INFO--
 *
 * Function: curves_addCurveDef
 * EN v1.0 Address: 0x800E52E8
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x800E556C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Retail source-tag string: Hcurves.c: MAX_ROMCURVES exceeded!!
 */
void curves_addCurveDef(RomCurveDef* curve);

/*
 * --INFO--
 *
 * Function: curves_countRandomPoints
 * EN v1.0 Address: 0x800E5434
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x800E56B8
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/*
 * --INFO--
 *
 * Function: fn_800E58FC
 * EN v1.0 Address: 0x800E49C4
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x800E5B80
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: fn_800E5CBC
 * EN v1.0 Address: 0x800E4C64
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800E5F40
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: fn_800E5E38
 * EN v1.0 Address: 0x800E5E38
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: fn_800E5F1C
 * EN v1.0 Address: 0x800E5F1C
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: curves_updateLocalPointCollision
 * EN v1.0 Address: 0x800E4DBC
 * EN v1.0 Size: 912b
 * EN v1.1 Address: 0x800E6410
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: curves_preparePointCollisionFrame
 * EN v1.0 Address: 0x800E514C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x800E6778
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: curves_updateLocalPointTransforms
 * EN v1.0 Address: 0x800E5428
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x800E6A30
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_15_func0A
 * EN v1.0 Address: 0x800E5570
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x800E6BA0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_15_func0B
 * EN v1.0 Address: 0x800E6A90
 * EN v1.0 Size: 168b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: curves_getCurves
 * EN v1.0 Address: 0x800E6B38
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x800E6DBC
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_15_func08
 * EN v1.0 Address: 0x800E58B8
 * EN v1.0 Size: 2184b
 * EN v1.1 Address: 0x800E6F68
 * EN v1.1 Size: 2472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/*
 * --INFO--
 *
 * Function: dll_15_func06
 * EN v1.0 Address: 0x800E61A4
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: 0x800E79A0
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: dll_15_func05
 * EN v1.0 Address: 0x800E7AE8
 * EN v1.0 Size: 412b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Forward active hit-segment bounds to ObjHits with the state-derived target mask. */


/* Extended local-point collision setup with a secondary hit type. */

/* Basic local-point collision setup used by path control. */

/*
 * --INFO--
 *
 * Function: curves_clear
 * EN v1.0 Address: 0x800E7D20
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800E7FA4
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: playerHasKrazoaSpirit
 * EN v1.0 Address: 0x800E6680
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x800E8024
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: saveFileStruct_setCheatActive
 * EN v1.0 Address: 0x800E6734
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800E80C4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct SaveData
{
    u8 pad00[2];
    u8 subtitlesEnabled;
    u8 gameUiSetting;
    u8 cameraSetting;
    u8 pad05;
    u8 widescreenEnabled;
    u8 pad07;
    u8 rumbleEnabled;
    u8 soundMode;
    u8 musicVolume;
    u8 sfxVolume;
    u8 speechVolume;
    u8 pad0D[3];
    u32 registeredDebugOptions;
    u32 enabledDebugOptions;
} SaveData;

extern SaveData saveData;



/* Trivial 4b 0-arg blr leaves. */
void curves_release(void);

void RomCurve_initialise(void);



/*
 * --INFO--
 *
 * Function: loadSaveSettings
 * EN v1.0 Address: 0x800E7F44
 * EN v1.0 Size: 256b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

void loadSaveSettings(void);

/* Pattern wrappers. */
void curves_initialise(void);

void RomCurve_func0D(RomCurveDef** startOut, RomCurveDef** endOut);

/* getSaveFileStruct: return &saveData (lis/addi). */
void* getSaveFileStruct(void);

/* getLastSavedGameTexts: return (u8*)&gSaveGameData + 0x558. Array form forces lis/addi. */




/* RomCurve_getCurves: *outCount = nRomCurves; return romCurves. */
void* RomCurve_getCurves(int* outCount);


/* isCheatUnlocked: return registeredDebugOptions & (1 << (idx & 0xff)). */
int isCheatUnlocked(u8 idx);

/* saveFileStruct_unlockCheat: set bit (1 << (idx & 0xff)) in registeredDebugOptions. */


/* curves_findByAction: scan romCurves for matching action curves, return curve id. */
int curves_findByAction(int act);

/* RomCurve_segmentIntersectsOriginRayXZ: 2D segment-intersection predicate.
 * Returns 1 if the segment between (x, z) and the origin in the xz-plane
 * crosses the segment between a and b. */
int RomCurve_segmentIntersectsOriginRayXZ(RomCurveDef* a, RomCurveDef* b, f32 x, f32 unusedY, f32 z, f32 unusedW);
#pragma scheduling reset
#pragma peephole reset
