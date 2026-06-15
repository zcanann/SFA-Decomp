#include "main/dll/objfsa_romcurve.h"
#include "main/dll/objfsa.h"
#include "main/game_object.h"

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */

#include "main/dll/dll_0015_curves.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a18();
extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
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

extern u32 lbl_803DD458;
extern f32 lbl_803E05D0;
extern f32 lbl_803E05D4;
extern f32 lbl_803E05D8;

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

undefined4
FUN_800d9de0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* state, float param_10, undefined4 param_11, undefined4 param_12,
             undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    undefined4 uVar2;
    undefined4 extraout_r4;
    undefined4 extraout_r4_00;
    double dVar3;
    double dVar4;

    fVar1 = state[0x28];
    if (((fVar1 == 0.0) || (state[0x29] == 0.0)) || (param_10 == 0.0))
    {
        uVar2 = 1;
    }
    else
    {
        if (state[0x20] == 0.0)
        {
            state[0x27] = fVar1;
            state[0x28] = state[0x29];
            state[0x29] = param_10;
            FUN_80003494((uint)(state + 0x2a), (uint)(state + 0x2e), 0x10);
            FUN_80003494((uint)(state + 0x32), (uint)(state + 0x36), 0x10);
            uVar2 = 0x10;
            FUN_80003494((uint)(state + 0x3a), (uint)(state + 0x3e), 0x10);
            state[0x2e] = *(float*)((int)state[0x28] + 8);
            state[0x2f] = *(float*)((int)state[0x29] + 8);
            dVar3 = (double)FUN_80293f90();
            state[0x30] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x28] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            state[0x31] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x29] + 0x2e) * dVar3);
            state[0x36] = *(float*)((int)state[0x28] + 0xc);
            state[0x37] = *(float*)((int)state[0x29] + 0xc);
            dVar3 = (double)FUN_80293f90();
            state[0x38] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x28] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            state[0x39] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x29] + 0x2e) * dVar3);
            state[0x3e] = *(float*)((int)state[0x28] + 0x10);
            state[0x3f] = *(float*)((int)state[0x29] + 0x10);
            dVar3 = (double)FUN_80294964();
            state[0x40] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x28] + 0x2e) * dVar3);
            dVar4 = (double)FUN_80294964();
            dVar3 = DOUBLE_803e1268;
            dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                     (uint) * (byte*)((int)state[0x29] +
                                                                         0x2e)) -
                DOUBLE_803e1268) * dVar4);
            state[0x41] = (float)((double)lbl_803E1250 * dVar4);
            if (state[0x24] != 0.0)
            {
                FUN_80006a18(dVar4, dVar3, param_3, param_4, param_5, param_6, param_7, param_8, (int)state,
                             extraout_r4_00, uVar2, param_12, param_13, param_14, param_15, param_16);
                if (lbl_803E1248 <= *state)
                {
                    *state = lbl_803E124C;
                }
            }
        }
        else
        {
            state[0x27] = fVar1;
            state[0x28] = state[0x29];
            state[0x29] = param_10;
            FUN_80003494((uint)(state + 0x2e), (uint)(state + 0x2a), 0x10);
            FUN_80003494((uint)(state + 0x36), (uint)(state + 0x32), 0x10);
            uVar2 = 0x10;
            FUN_80003494((uint)(state + 0x3e), (uint)(state + 0x3a), 0x10);
            state[0x2a] = *(float*)((int)state[0x29] + 8);
            state[0x2b] = *(float*)((int)state[0x28] + 8);
            dVar3 = (double)FUN_80293f90();
            state[0x2c] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x29] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            state[0x2d] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x28] + 0x2e) * dVar3);
            state[0x32] = *(float*)((int)state[0x29] + 0xc);
            state[0x33] = *(float*)((int)state[0x28] + 0xc);
            dVar3 = (double)FUN_80293f90();
            state[0x34] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x29] + 0x2e) * dVar3);
            dVar3 = (double)FUN_80293f90();
            state[0x35] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x28] + 0x2e) * dVar3);
            state[0x3a] = *(float*)((int)state[0x29] + 0x10);
            state[0x3b] = *(float*)((int)state[0x28] + 0x10);
            dVar3 = (double)FUN_80294964();
            state[0x3c] =
                lbl_803E1250 *
                (float)((double)(float)(u32)*(byte*)((int)state[0x29] + 0x2e) * dVar3);
            dVar4 = (double)FUN_80294964();
            dVar3 = DOUBLE_803e1268;
            dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                     (uint) * (byte*)((int)state[0x28] +
                                                                         0x2e)) -
                DOUBLE_803e1268) * dVar4);
            state[0x3d] = (float)((double)lbl_803E1250 * dVar4);
            if (state[0x24] != 0.0)
            {
                FUN_80006a18(dVar4, dVar3, param_3, param_4, param_5, param_6, param_7, param_8, (int)state,
                             extraout_r4, uVar2, param_12, param_13, param_14, param_15, param_16);
                if (*state <= lbl_803E1270)
                {
                    *state = lbl_803E1274;
                }
            }
        }
        uVar2 = 0;
    }
    return uVar2;
}

void FUN_800da594(double param_1, float* pValue)
{
    if (lbl_803E1270 < *pValue)
    {
        if (lbl_803E1248 <= *pValue)
        {
            *pValue = lbl_803E124C;
        }
    }
    else
    {
        *pValue = lbl_803E1274;
    }
    FUN_80006a10(param_1, pValue);
    return;
}

bool FUN_800da5e8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  float* state, float param_10, float param_11, float param_12, undefined4 param_13,
                  undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

void FUN_800da700(undefined4 param_1, undefined4 param_2, int actFilter)
{
    float dx;
    float dy;
    float dz;
    float* refPos;
    int* pObj;
    uint bitVal;
    int obj;
    int i;
    double distSq;
    double in_f31;
    double bestDistSq;
    double in_ps31_1;
    undefined8 packed;
    int objList[12];
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    packed = FUN_80286838();
    refPos = (float*)((ulonglong)packed >> 0x20);
    pObj = (int*)(**(code**)(*DAT_803dd71c + 0x10))(objList);
    bestDistSq = (double)lbl_803E1278;
    for (i = 0; i < objList[0]; i = i + 1)
    {
        obj = *pObj;
        if ((((((obj != 0) && (*(char*)(obj + 0x19) == '$')) &&
                        (((uint)packed == 0xffffffff || ((uint) * (byte*)(obj + 3) == (uint)packed)))) &&
                    ((actFilter == -1 || (*(char*)(obj + 0x1a) == actFilter)))) &&
                (((int)*(short*)(obj + 0x30) == 0xffffffff ||
                    (bitVal = GameBit_Get((int)*(short*)(obj + 0x30)), bitVal != 0)))) &&
            ((((int)*(short*)(obj + 0x32) == 0xffffffff ||
                    (bitVal = GameBit_Get((int)*(short*)(obj + 0x32)), bitVal == 0)) &&
                (dx = *refPos - ((GameObject *)obj)->anim.rootMotionScale, dy = refPos[1] - ((GameObject *)obj)->anim.localPosX,
                    dz = refPos[2] - ((GameObject *)obj)->anim.localPosY,
                    distSq = (double)(dz * dz + dx * dx + dy * dy), distSq < bestDistSq))))
        {
            bestDistSq = distSq;
        }
        pObj = pObj + 1;
    }
    FUN_80286884();
    return;
}

void FUN_800da850(uint value, undefined* out)
{
    *out = (char)(value & 0xffff);
    out[1] = (char)((value & 0xffff) >> 8);
    return;
}

undefined2
FUN_800db110(float* point, int patchIdx, undefined4 param_3, undefined4 param_4, byte param_5)
{
    byte i;
    uint sectorIdx;
    uint off;

    i = 0;
    do
    {
        if (3 < i)
        {
            return 0;
        }
        if (((&DAT_803a2390)[patchIdx] != '\0') &&
            (sectorIdx = (uint)(byte)(&DAT_803a076c)[patchIdx * 0x28 + (uint)i], sectorIdx != 0))
        {
            if ((point[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_8039d768)[sectorIdx * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)(&DAT_8039d76a)[sectorIdx * 0x18] ^ 0x80000000
                ) - DOUBLE_803e1260) < point[1]))
            {
                param_5 = 0;
                off = 0;
                while ((param_5 < 4 &&
                    (*(float*)(&DAT_8039d748 + sectorIdx * 0x18 + (uint)param_5 * 2 + 8) +
                        *point *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d748)[sectorIdx * 0x18 + (off & 0xff)]
                                                 ^ 0x80000000) - DOUBLE_803e1260) +
                        point[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d748)
                                                 [sectorIdx * 0x18 + (off & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    param_5 = param_5 + 1;
                    off = off + 2;
                }
            }
            if (param_5 == 4)
            {
                return (&DAT_8039d76c)[sectorIdx * 0x18];
            }
        }
        i = i + 1;
    }
    while (true);
}

void FUN_800db47c(float* point, undefined* param_2)
{
    uint bitMask;
    uint sectorIdx;
    byte i;
    uint childIdx;
    uint off;
    byte unaff_r31;

    sectorIdx = FUN_800db820(point);
    if ((param_2 != (undefined*)0x0) && ((sectorIdx & 0xff) != 0))
    {
        *param_2 = (char)sectorIdx;
        param_2[1] = 0;
        bitMask = 1;
        for (i = 0; i < 4; i = i + 1)
        {
            off = (uint)i;
            childIdx = (uint)(byte)(&DAT_803a076c)[(sectorIdx & 0xff) * 0x28 + off];
            if (childIdx == 0)
            {
                *(undefined2*)(param_2 + off * 2 + 2) = 0;
            }
            else
            {
                *(undefined2*)(param_2 + off * 2 + 2) = (&DAT_8039d76c)[childIdx * 0x18];
                if (point[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_8039d768)[childIdx * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260))
                {
                    if ((float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_8039d76a)[childIdx * 0x18] ^ 0x80000000) -
                        DOUBLE_803e1260) < point[1])
                    {
                        off = 0;
                        for (unaff_r31 = 0; unaff_r31 < 4; unaff_r31 = unaff_r31 + 1)
                        {
                            if (lbl_803E1270 <
                                *(float*)(&DAT_8039d748 + childIdx * 0x18 + (uint)unaff_r31 * 2 + 8) +
                                *point *
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039d748)
                                                         [childIdx * 0x18 + (off & 0xff)] ^ 0x80000000)
                                    - DOUBLE_803e1260) +
                                point[2] *
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)(&DAT_8039d748)
                                                         [childIdx * 0x18 + (off & 0xff) + 1] ^
                                                         0x80000000) - DOUBLE_803e1260))
                                break;
                            off = off + 2;
                        }
                    }
                }
                if (unaff_r31 == 4)
                {
                    param_2[1] = param_2[1] | (byte)bitMask;
                }
            }
            bitMask = (bitMask & 0x7f) << 1;
        }
    }
    return;
}

ushort FUN_800db690(float* point)
{
    uint off;
    byte i;
    undefined2* sector;
    int remaining;

    sector = &DAT_8039d748;
    remaining = DAT_803de0e4;
    if (0 < DAT_803de0e4)
    {
        do
        {
            if ((point[1] <
                    (float)((double)CONCAT44(0x43300000, (int)(short)sector[0x10] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)sector[0x11] ^ 0x80000000) -
                    DOUBLE_803e1260) < point[1]))
            {
                i = 0;
                off = 0;
                while ((i < 4 &&
                    (*(float*)(sector + (uint)i * 2 + 8) +
                        *point *
                        (float)((double)CONCAT44(0x43300000, (int)(short)sector[off & 0xff] ^ 0x80000000) -
                            DOUBLE_803e1260) +
                        point[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)sector[(off & 0xff) + 1] ^ 0x80000000) -
                            DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    i = i + 1;
                    off = off + 2;
                }
                if (i == 4)
                {
                    return sector[0x12];
                }
            }
            sector = sector + 0x18;
            remaining = remaining + -1;
        }
        while (remaining != 0);
    }
    return 0;
}

int FUN_800db820(float* point)
{
    short next;
    short cur;
    uint off;
    int idx;
    byte i;

    cur = (short)DAT_803de0e0;
    if (DAT_803de0e0 == 0xb4)
    {
        next = 0;
    }
    else
    {
        next = cur + 1;
    }
    do
    {
        idx = (int)cur;
        if (idx == next)
        {
            if ((&DAT_803a2390)[idx] != '\0')
            {
                if ((point[1] <
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0768)[idx * 0x14] ^ 0x80000000) -
                            DOUBLE_803e1260)) &&
                    ((float)((double)CONCAT44(0x43300000,
                                              (int)(short)(&DAT_803a076a)[idx * 0x14] ^ 0x80000000) -
                        DOUBLE_803e1260) < point[1]))
                {
                    i = 0;
                    off = 0;
                    while ((i < 4 &&
                        (*(float*)(&DAT_803a0748 + idx * 0x14 + (uint)i * 2 + 8) +
                            *point *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)(&DAT_803a0748)
                                                     [idx * 0x14 + (off & 0xff)] ^ 0x80000000)
                                - DOUBLE_803e1260) +
                            point[2] *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)(short)(&DAT_803a0748)
                                                     [idx * 0x14 + (off & 0xff) + 1] ^
                                                     0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                    {
                        i = i + 1;
                        off = off + 2;
                    }
                    if (i == 4)
                    {
                        DAT_803de0e0 = (int)cur;
                        return (int)cur;
                    }
                }
            }
            return 0;
        }
        idx = (int)cur;
        if ((&DAT_803a2390)[idx] != '\0')
        {
            if ((point[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_803a0768)[idx * 0x14] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)(&DAT_803a076a)[idx * 0x14] ^ 0x80000000
                ) - DOUBLE_803e1260) < point[1]))
            {
                i = 0;
                off = 0;
                while ((i < 4 &&
                    (*(float*)(&DAT_803a0748 + idx * 0x14 + (uint)i * 2 + 8) +
                        *point *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)[idx * 0x14 + (off & 0xff)]
                                                 ^ 0x80000000) - DOUBLE_803e1260) +
                        point[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)
                                                 [idx * 0x14 + (off & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    i = i + 1;
                    off = off + 2;
                }
                if (i == 4)
                {
                    DAT_803de0e0 = (int)cur;
                    return (int)cur;
                }
            }
        }
        idx = (int)next;
        if ((&DAT_803a2390)[idx] != '\0')
        {
            if ((point[1] <
                    (float)((double)CONCAT44(0x43300000,
                                             (int)(short)(&DAT_803a0768)[idx * 0x14] ^ 0x80000000) -
                        DOUBLE_803e1260)) &&
                ((float)((double)CONCAT44(0x43300000, (int)(short)(&DAT_803a076a)[idx * 0x14] ^ 0x80000000
                ) - DOUBLE_803e1260) < point[1]))
            {
                i = 0;
                off = 0;
                while ((i < 4 &&
                    (*(float*)(&DAT_803a0748 + idx * 0x14 + (uint)i * 2 + 8) +
                        *point *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)[idx * 0x14 + (off & 0xff)]
                                                 ^ 0x80000000) - DOUBLE_803e1260) +
                        point[2] *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)(short)(&DAT_803a0748)
                                                 [idx * 0x14 + (off & 0xff) + 1] ^
                                                 0x80000000) - DOUBLE_803e1260) <= lbl_803E1270)))
                {
                    i = i + 1;
                    off = off + 2;
                }
                if (i == 4)
                {
                    DAT_803de0e0 = (int)next;
                    return (int)next;
                }
            }
        }
        cur = cur + -1;
        if (cur == -1)
        {
            cur = 0xb4;
        }
        next = next + 1;
        if (next == 0xb5)
        {
            next = 0;
        }
    }
    while (true);
}

undefined4
FUN_800dd3e4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* state, undefined4 param_10, uint param_11)
{
    return 0;
}

undefined4
FUN_800dd62c(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* state, uint param_10, undefined4 param_11, int param_12, int param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    uint uVar1;
    undefined4 extraout_r4;
    undefined4 extraout_r4_00;
    undefined4 uVar2;
    float fVar3;
    double dVar4;
    double dVar5;

    if (((state != (float*)0x0) && (state[0x28] != 0.0)) && (state[0x29] != 0.0))
    {
        state[0x27] = state[0x28];
        state[0x28] = state[0x29];
        FUN_80003494((uint)(state + 0x2a), (uint)(state + 0x2e), 0x10);
        FUN_80003494((uint)(state + 0x32), (uint)(state + 0x36), 0x10);
        FUN_80003494((uint)(state + 0x3a), (uint)(state + 0x3e), 0x10);
        if (state[0x20] == 0.0)
        {
            uVar1 = FUN_800dd50c((int)state[0x28], -1, param_10);
        }
        else
        {
            uVar1 = FUN_800dd3ec((int)state[0x28], -1, param_10);
        }
        if (uVar1 == 0xffffffff)
        {
            state[0x29] = 0.0;
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
            state[0x29] = fVar3;
            if (state[0x29] != 0.0)
            {
                if (state[0x20] == 0.0)
                {
                    state[0x2e] = *(float*)((int)state[0x28] + 8);
                    state[0x2f] = *(float*)((int)state[0x29] + 8);
                    dVar4 = (double)FUN_80293f90();
                    state[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    state[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x29] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    state[0x36] = *(float*)((int)state[0x28] + 0xc);
                    state[0x37] = *(float*)((int)state[0x29] + 0xc);
                    dVar4 = (double)FUN_80293f90();
                    state[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    state[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x29] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    state[0x3e] = *(float*)((int)state[0x28] + 0x10);
                    state[0x3f] = *(float*)((int)state[0x29] + 0x10);
                    dVar4 = (double)FUN_80294964();
                    state[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar5 = (double)FUN_80294964();
                    dVar4 = DOUBLE_803e12a8;
                    dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                             (uint) * (byte*)((int)state[0x29
                                                                             ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
                    state[0x41] = (float)((double)lbl_803E1290 * dVar5);
                    uVar2 = extraout_r4_00;
                }
                else
                {
                    state[0x2e] = *(float*)((int)state[0x28] + 8);
                    state[0x2f] = *(float*)((int)state[0x27] + 8);
                    dVar4 = (double)FUN_80293f90();
                    state[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    state[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x27] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    state[0x36] = *(float*)((int)state[0x28] + 0xc);
                    state[0x37] = *(float*)((int)state[0x27] + 0xc);
                    dVar4 = (double)FUN_80293f90();
                    state[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar4 = (double)FUN_80293f90();
                    state[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x27] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    state[0x3e] = *(float*)((int)state[0x28] + 0x10);
                    state[0x3f] = *(float*)((int)state[0x27] + 0x10);
                    dVar4 = (double)FUN_80294964();
                    state[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint) * (byte*)((int)state[0x28] + 0x2e))
                            - DOUBLE_803e12a8) * dVar4);
                    dVar5 = (double)FUN_80294964();
                    dVar4 = DOUBLE_803e12a8;
                    dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                             (uint) * (byte*)((int)state[0x27
                                                                             ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
                    state[0x41] = (float)((double)lbl_803E1290 * dVar5);
                    uVar2 = extraout_r4;
                }
                if (state[0x24] != 0.0)
                {
                    FUN_80006a18(dVar5, dVar4, param_3, param_4, param_5, param_6, param_7, param_8, (int)state,
                                 uVar2, param_10, param_12, param_13, fVar3, param_15, param_16);
                }
                if (state[0x20] == 0.0)
                {
                    FUN_80006a10((double)lbl_803E12B4, state);
                }
                else
                {
                    FUN_80006a10((double)lbl_803E12B0, state);
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
             float* state, float param_10, undefined4 param_11, undefined4 param_12,
             undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

undefined4
FUN_800ddf8c(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             float* state)
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

    if (((state != (float*)0x0) && (state[0x28] != 0.0)) && (state[0x29] != 0.0))
    {
        state[0x27] = state[0x28];
        state[0x28] = state[0x29];
        FUN_80003494((uint)(state + 0x2a), (uint)(state + 0x2e), 0x10);
        FUN_80003494((uint)(state + 0x32), (uint)(state + 0x36), 0x10);
        FUN_80003494((uint)(state + 0x3a), (uint)(state + 0x3e), 0x10);
        if (state[0x20] == 0.0)
        {
            fVar4 = state[0x28];
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
            fVar4 = state[0x28];
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
            state[0x29] = 0.0;
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
            state[0x29] = fVar6;
            if (state[0x29] != 0.0)
            {
                if (state[0x20] == 0.0)
                {
                    state[0x2e] = *(float*)((int)state[0x28] + 8);
                    state[0x2f] = *(float*)((int)state[0x29] + 8);
                    uStack_c = (int)*(char*)((int)state[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_10 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_14 = (uint) * (byte*)((int)state[0x28] + 0x2e);
                    local_18 = 0x43300000;
                    state[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_14) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_1c = (int)*(char*)((int)state[0x29] + 0x2c) << 8 ^ 0x80000000;
                    local_20 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_24 = (uint) * (byte*)((int)state[0x29] + 0x2e);
                    local_28 = 0x43300000;
                    state[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_24) - DOUBLE_803e12a8) *
                            dVar7);
                    state[0x36] = *(float*)((int)state[0x28] + 0xc);
                    state[0x37] = *(float*)((int)state[0x29] + 0xc);
                    uStack_2c = (int)*(char*)((int)state[0x28] + 0x2d) << 8 ^ 0x80000000;
                    local_30 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_34 = (uint) * (byte*)((int)state[0x28] + 0x2e);
                    local_38 = 0x43300000;
                    state[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_34) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_3c = (int)*(char*)((int)state[0x29] + 0x2d) << 8 ^ 0x80000000;
                    local_40 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_44 = (uint) * (byte*)((int)state[0x29] + 0x2e);
                    local_48 = 0x43300000;
                    state[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_44) - DOUBLE_803e12a8) *
                            dVar7);
                    state[0x3e] = *(float*)((int)state[0x28] + 0x10);
                    state[0x3f] = *(float*)((int)state[0x29] + 0x10);
                    uStack_4c = (int)*(char*)((int)state[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_50 = 0x43300000;
                    dVar7 = (double)FUN_80294964();
                    uStack_54 = (uint) * (byte*)((int)state[0x28] + 0x2e);
                    local_58 = 0x43300000;
                    state[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_54) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_5c = (int)*(char*)((int)state[0x29] + 0x2c) << 8 ^ 0x80000000;
                    local_60 = 0x43300000;
                    dVar8 = (double)FUN_80294964();
                    dVar7 = DOUBLE_803e12a8;
                    uStack_64 = (uint) * (byte*)((int)state[0x29] + 0x2e);
                    local_68 = 0x43300000;
                    dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000, uStack_64) -
                        DOUBLE_803e12a8) * dVar8);
                    state[0x41] = (float)((double)lbl_803E1290 * dVar8);
                    uVar1 = extraout_r4_00;
                }
                else
                {
                    state[0x2e] = *(float*)((int)state[0x28] + 8);
                    state[0x2f] = *(float*)((int)state[0x27] + 8);
                    uStack_64 = (int)*(char*)((int)state[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_68 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_5c = (uint) * (byte*)((int)state[0x28] + 0x2e);
                    local_60 = 0x43300000;
                    state[0x30] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_5c) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_54 = (int)*(char*)((int)state[0x27] + 0x2c) << 8 ^ 0x80000000;
                    local_58 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_4c = (uint) * (byte*)((int)state[0x27] + 0x2e);
                    local_50 = 0x43300000;
                    state[0x31] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_4c) - DOUBLE_803e12a8) *
                            dVar7);
                    state[0x36] = *(float*)((int)state[0x28] + 0xc);
                    state[0x37] = *(float*)((int)state[0x27] + 0xc);
                    uStack_44 = (int)*(char*)((int)state[0x28] + 0x2d) << 8 ^ 0x80000000;
                    local_48 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_3c = (uint) * (byte*)((int)state[0x28] + 0x2e);
                    local_40 = 0x43300000;
                    state[0x38] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_3c) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_34 = (int)*(char*)((int)state[0x27] + 0x2d) << 8 ^ 0x80000000;
                    local_38 = 0x43300000;
                    dVar7 = (double)FUN_80293f90();
                    uStack_2c = (uint) * (byte*)((int)state[0x27] + 0x2e);
                    local_30 = 0x43300000;
                    state[0x39] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_2c) - DOUBLE_803e12a8) *
                            dVar7);
                    state[0x3e] = *(float*)((int)state[0x28] + 0x10);
                    state[0x3f] = *(float*)((int)state[0x27] + 0x10);
                    uStack_24 = (int)*(char*)((int)state[0x28] + 0x2c) << 8 ^ 0x80000000;
                    local_28 = 0x43300000;
                    dVar7 = (double)FUN_80294964();
                    uStack_1c = (uint) * (byte*)((int)state[0x28] + 0x2e);
                    local_20 = 0x43300000;
                    state[0x40] =
                        lbl_803E1290 *
                        (float)((double)(float)((double)CONCAT44(0x43300000, uStack_1c) - DOUBLE_803e12a8) *
                            dVar7);
                    uStack_14 = (int)*(char*)((int)state[0x27] + 0x2c) << 8 ^ 0x80000000;
                    local_18 = 0x43300000;
                    dVar8 = (double)FUN_80294964();
                    dVar7 = DOUBLE_803e12a8;
                    uStack_c = (uint) * (byte*)((int)state[0x27] + 0x2e);
                    local_10 = 0x43300000;
                    dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000, uStack_c) -
                        DOUBLE_803e12a8) * dVar8);
                    state[0x41] = (float)((double)lbl_803E1290 * dVar8);
                    uVar1 = extraout_r4;
                }
                if (state[0x24] != 0.0)
                {
                    FUN_80006a18(dVar8, dVar7, param_3, param_4, param_5, param_6, param_7, param_8, (int)state,
                                 uVar1, iVar3, fVar4, fVar6, uVar5, in_r9, in_r10);
                }
                if (state[0x20] == 0.0)
                {
                    FUN_80006a10((double)lbl_803E12B4, state);
                }
                else
                {
                    FUN_80006a10((double)lbl_803E12B0, state);
                }
                return 0;
            }
        }
    }
    return 1;
}

undefined4
FUN_800de998(double param_1, undefined8 param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, float* state, int param_10,
             undefined4 param_11, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    return 0;
}


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

int dll_12_func06_ret_0(void) { return 0x0; }

void dll_12_func09(void) { lbl_803DD458 = 0x3; }

void player_init(int unused, void* obj, int a, int b);

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


/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */

/* UIController dispatch through the shared GameUI interface. */

/* player_setState */

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */

/* segment pragma-stack balance (re-split): */

static inline u32 RomCurve_GetId(RomCurveDef* curve);

static inline int RomCurve_IsLinkIdValid(int linkId);

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId);

static inline int RomCurve_noUnblockedLinks(RomCurvePlacementDef* curve);

static inline int RomCurve_noBlockedLinks(RomCurvePlacementDef* curve);

/*
 * Retail source-tag string: Hcurves.c: MAX_ROMCURVES exceeded!!
 */

/* RomCurve_segmentIntersectsOriginRayXZ: 2D segment-intersection predicate.
 * Returns 1 if the segment between (x, z) and the origin in the xz-plane
 * crosses the segment between a and b. */
