/*
 * dll_80138b60 - Tricky companion helpers.
 *
 * Blend-channel weight animation (Tricky_updateBlendChannelWeight) and the
 * impress fade (fn_80138D7C / trickyImpress), queued-path particle emission
 * (Tricky_emitQueuedPathParticles), baddie target search
 * (trickyFindNearestUsableBaddie) and queued-command target selection
 * (trickySelectQueuedCommandTarget), plus small state accessors.
 */

#include "main/dll/partfx_interface.h"
#include "main/vecmath.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/dll_0019_dll19func0.h"

/* The one partfx effect emitted along Tricky's queued impress path. */
#define TRICKY_PATH_PARTFX 0x533

#define TRICKY_BADDIE_TARGET_OBJGROUP 49 /* baddie object group scanned by trickyFindNearestUsableBaddie */
/* creatures excluded from Tricky's baddie targeting (retail OBJECTS.bin names). */
#define TRICKY_SEQID_WHIRLPOOL    2129 /* "Whirlpool" (DLL 0xC9) */
#define TRICKY_SEQID_VAMBAT       1022 /* "Vambat" (DLL 0xC9) */
#define TRICKY_SEQID_WB           1239 /* "WB" (DLL 0xC9) */
#define TRICKY_SEQID_SC_BABYLIGHT 636  /* "SC_babyligh" (DLL 0x1B5) */
#define TRICKY_SEQID_PINPON       593  /* "PinPon" (DLL 0xC9) */

#define TUMBLEWEED_BLEND_FLAGS_OFFSET    0x82e
#define TUMBLEWEED_BLEND_WEIGHT_OFFSET   0x830
#define TUMBLEWEED_BLEND_VELOCITY_OFFSET 0x834

typedef struct TrickyImpressState
{
    u8 pad0[0x14 - 0x0];
    f32 unk14;
    u8 pad18[0x24 - 0x18];
    GameObject* stayPoint;
    u8 pad28[0x54 - 0x28];
    u32 flags54;
    u8 pad58[0x408 - 0x58];
    f32 renderPosX;
    f32 renderPosY;
    f32 renderPosZ;
    s16 unk414;
    u8 pad416[0x7A8 - 0x416];
    s32 childObj0; /* 0x7A8: attached child object handle (slot 0) */
    u8 pad7AC[0x7B0 - 0x7AC];
    s32 childObj1; /* 0x7B0: attached child object handle (slot 1) */
    u8 pad7B4[0x7B8 - 0x7B4];
    s32 childObj2;   /* 0x7B8: attached child object handle (slot 2) */
    u8 childSlotMap; /* 0x7BC: packed 2-bit slot index per impress child (childObj0/1/2 via >>6/>>4/>>2 & 3) */
    u8 pad7BD[0x808 - 0x7BD];
    f32 unk808;
    u8 pad80C[0x810 - 0x80C];
} TrickyImpressState;

typedef struct
{
    u8 pending : 1;
    u8 active : 1;
    u8 rest : 6;
} TumbleweedBlendFlags;

extern const f32 lbl_803E23E8;
extern const f32 lbl_803E2418;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23E4;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;
extern f32 lbl_803E2408;
extern f32 lbl_803E240C;

/* Weighted blend-channel animator. On state[0x82e] bit 0x80,
 * primes channel 1 (weight 0, target weight ratio at +0x830) and latches
 * the active flag. While bit 0x40 is set, ramps state[0x830] toward
 * data[0] / data[1] with acceleration lbl_803E23E4 and damping
 * lbl_803E23F0, clamps to [0, lbl_803E23E8], and pushes the result to the
 * model's blend channel 1 as `lbl_803E23F8 * weight - lbl_803E23E8`. */
void Tricky_updateBlendChannelWeight(int obj, u8* state)
{
    ObjModel* model;
    f32 target;
    Obj_GetActiveModel((GameObject*)obj);
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 7) & 1) != 0)
    {
        model = Obj_GetActiveModel((GameObject*)obj);
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, lbl_803E23DC, 0x21);
        *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E0;
        ObjModel_SetBlendChannelWeight(model, 0, lbl_803E23DC);
        ((TumbleweedBlendFlags*)(state + TUMBLEWEED_BLEND_FLAGS_OFFSET))->pending = 0;
        ((TumbleweedBlendFlags*)(state + TUMBLEWEED_BLEND_FLAGS_OFFSET))->active = 1;
    }
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 6) & 1) != 0)
    {
        u8* data = *(u8**)(state + 0);
        target = (f32)(u32)data[0] / (f32)(u32)data[1];
        if (target > *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET))
        {
            *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                lbl_803E23E4 * timeDelta + *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET);
            *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * timeDelta +
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET);
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) > lbl_803E23E8)
            {
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E8;
            }
            else if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) > target)
            {
                if (*(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) < lbl_803E23EC)
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                    *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = target;
                }
                else
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                        *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * lbl_803E23F0;
                }
            }
        }
        else if (target < *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET))
        {
            *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) - lbl_803E23E4 * timeDelta;
            *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * timeDelta +
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET);
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < *(f32*)&lbl_803E23DC)
            {
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                    lbl_803E23DC;
            }
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < target)
            {
                if (*(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) > lbl_803E23F4)
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                    *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = target;
                }
                else
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                        *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * lbl_803E23F0;
                }
            }
        }
        ObjModel_SetBlendChannelWeight(Obj_GetActiveModel((GameObject*)obj), 1,
                                       lbl_803E23F8 * *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) - lbl_803E23E8);
    }
}

void fn_80138D7C(int obj, int state)
{
    u8 ratio = (u8)((s32) * (u8*)(*(int*)(state + 0) + 2) / 10);

    if (((TrickyState*)state)->modelVariant != ratio)
    {
        f32 t;
        if (mainGetBit(1005) == 0)
        {
            mainSetBits(1005, 1);
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
            ((TrickyState*)state)->stateFlags |= 0x4000;
            *(f32*)(state + 0x828) = *(f32*)(state + 0x828) + lbl_803E2408;
        }
        *(f32*)(state + 0x828) = *(f32*)(state + 0x828) - timeDelta;
        t = *(f32*)(state + 0x828);
        if (!(t > lbl_803E2408))
        {
            if (t > lbl_803E23DC)
            {
                f32 alpha;
                if (t > lbl_803E23E0)
                {
                    alpha = lbl_803E23E8 - (t - lbl_803E23E0) / lbl_803E23E0;
                }
                else
                {
                    Obj_GetActiveModel((GameObject*)obj)->textureRefs->unk08 = ratio;
                    alpha = *(f32*)(state + 0x828) / lbl_803E23E0;
                }
                Obj_SetModelColorOverrideRecursive((GameObject*)obj, 255, 255, 255, lbl_803E240C * alpha, 1);
            }
            else
            {
                ((TrickyState*)state)->modelVariant = ratio;
                Obj_SetModelColorOverrideRecursive((GameObject*)obj, 0, 0, 0, 0, 0);
            }
        }
    }
}

/* Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */
void trickyImpress(GameObject* obj)
{
    TrickyImpressState* b = ((GameObject*)obj)->extra;
    b->flags54 |= 0x80000000;
    b->unk808 = lbl_803E2408;
}
/* GameBit-gated bit toggle on obj->_b8->_54: requires mainGetBit(GAMEBIT_Tricky_Usable); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
int trickyFn_80138f14(GameObject* obj)
{
    TrickyImpressState* b = obj->extra;
    if ((u32)mainGetBit(GAMEBIT_Tricky_Usable) != 0u)
    {
        b->flags54 |= 0x10000LL;
        if ((b->flags54 & 0x10) != 0u)
        {
            return 1;
        }
    }
    return 0;
}

PPCWGPipe GXWGFifo : (0xCC008000);

f32 fn_80138F78(GameObject* obj)
{
    return ((TrickyImpressState*)obj->extra)->unk14;
}

GameObject* trickyGetStayPoint(GameObject* obj)
{
    return ((TrickyImpressState*)obj->extra)->stayPoint;
}
int fn_80138F90(GameObject* obj)
{
    return ((TrickyImpressState*)obj->extra)->unk414;
}
void* trickyGetQueuedPathParticlePos(GameObject* obj)
{
    return &((TrickyImpressState*)obj->extra)->renderPosX;
}

GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes)
{
    int* objs;
    int* tmpList;
    GameObject* closest;
    int i;
    f32 bestDistSq;
    int count;

    bestDistSq = maxRadius;
    closest = 0;
    tmpList = (int*)ObjGroup_GetObjects(3, &count);
    bestDistSq = bestDistSq * bestDistSq;
    i = 0;
    objs = tmpList;

    for (; i < count; objs++, i++)
    {
        int* data;
        f32 obj_extra;
        int v1, v2;
        s32 g1, g2;

        if (dll_19_func1B((GameObject*)(*objs)) != 0)
        {
            obj_extra = (*gBaddieControlInterface)->getHealthFraction((GameObject*)*objs);
        }
        else
        {
            obj_extra = enemy_getHealthFraction((GameObject*)*objs);
        }

        data = (int*)((GameObject*)*objs)->anim.placementData;
        g1 = *(s16*)((char*)data + 0x18);
        if (g1 == -1)
        {
            v1 = 0;
        }
        else
        {
            v1 = mainGetBit(g1);
        }
        g2 = *(s16*)((char*)data + 0x1a);
        if (g2 == -1)
        {
            v2 = 1;
        }
        else
        {
            v2 = mainGetBit(g2);
        }

        if (ObjGroup_ContainsObject(*objs, TRICKY_BADDIE_TARGET_OBJGROUP) == 0 && obj_extra > lbl_803E23DC && v1 == 0 &&
            v2 != 0)
        {
            if (((GameObject*)*objs)->anim.seqId != TRICKY_SEQID_WHIRLPOOL)
            {
                if ((*gMapEventInterface)->shouldNotSaveTime(*(int*)((char*)data + 0x14)) != 0)
                {
                    if (allowSpecialTypes == 0)
                    {
                        s16 m = ((GameObject*)*objs)->anim.seqId;
                        if (m == TRICKY_SEQID_VAMBAT || m == TRICKY_SEQID_WB || m == TRICKY_SEQID_SC_BABYLIGHT ||
                            m == TRICKY_SEQID_PINPON)
                            continue;
                    }
                    {
                        f32 dist = vec3f_distanceSquared(&origin->anim.worldPosX, &((GameObject*)*objs)->anim.worldPosX);
                        if (dist < bestDistSq)
                        {
                            bestDistSq = dist;
                            closest = (GameObject*)*objs;
                        }
                    }
                }
            }
        }
    }
    return closest;
}

void Tricky_emitQueuedPathParticles(u8* a, u8* b)
{
    struct
    {
        s16 hx, hy, hz;
        f32 fk;
        f32 dx, dy, dz;
    } stk;
    u8 i = 0x14;
    u32 flags = ((TrickyImpressState*)b)->flags54;
    if ((flags & 0x1800) == 0)
        return;
    stk.dx = ((TrickyImpressState*)b)->renderPosX - ((GameObject*)a)->anim.worldPosX;
    stk.dy = ((TrickyImpressState*)b)->renderPosY - ((GameObject*)a)->anim.worldPosY;
    stk.dz = ((TrickyImpressState*)b)->renderPosZ - ((GameObject*)a)->anim.worldPosZ;
    stk.fk = lbl_803E23E8;
    stk.hx = ((GameObject*)a)->anim.rotX;
    stk.hy = ((GameObject*)a)->anim.rotY;
    stk.hz = ((GameObject*)a)->anim.rotZ;
    if ((flags & 0x800) == 0)
    {
        while (i-- != 0)
        {
            (*gPartfxInterface)->spawnObject(a, TRICKY_PATH_PARTFX, &stk, 2, -1, NULL);
        }
        ((TrickyImpressState*)b)->flags54 = ((TrickyImpressState*)b)->flags54 & ~0x1000LL;
    }
}
int trickySelectQueuedCommandTarget(u8* state, int commandType)
{
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    u8* entry;
    int i;
    u8* bestPriorityTarget;
    u8* bestFallbackTarget;

    bestPriorityDist = lbl_803E2418;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (i = 0, entry = state; i < ((TrickyState*)state)->commandCount; i++)
    {
        if (*(s8*)(entry + 0x74d) == commandType)
        {
            f32 dist = getXZDistance(&((GameObject*)((TrickyState*)state)->playerObj)->anim.worldPosX,
                                     &((GameObject*)*(u8**)(entry + 0x748))->anim.worldPosX);

            if (*(s8*)(entry + 0x74c) == 1)
            {
                if (dist < bestPriorityDist)
                {
                    bestPriorityDist = dist;
                    bestPriorityTarget = *(u8**)(entry + 0x748);
                }
            }
            else if (dist < bestFallbackDist)
            {
                bestFallbackDist = dist;
                bestFallbackTarget = *(u8**)(entry + 0x748);
            }
        }
        entry += 8;
    }

    if (bestPriorityTarget != NULL)
    {
        ((TrickyState*)state)->followObj = bestPriorityTarget;
    }
    else
    {
        if (bestFallbackTarget == NULL)
        {
            return 0;
        }
        ((TrickyState*)state)->followObj = bestFallbackTarget;
    }

    {
        u8* targetPos = (u8*)&((GameObject*)((TrickyState*)state)->followObj)->anim.worldPosX;
        if (((TrickyState*)state)->targetPosPtr != targetPos)
        {
            ((TrickyState*)state)->targetPosPtr = targetPos;
            *(s32*)&((TrickyState*)state)->stateFlags &= ~(u64)0x400;
            ((TrickyState*)state)->linkedWalkGroup = 0;
        }
    }

    state[0xa] = 0;
    return 1;
}
