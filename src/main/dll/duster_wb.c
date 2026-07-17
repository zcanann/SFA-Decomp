/*
 * duster_wb - the whirlpool/water-baddie and mutated-EBA behaviours that share
 * the duster family's BaddieState control record:
 *   - whirlpool/water creature (wbInit / fn_8015625C / fn_8015652C /
 *     wbUpdateWhileFrozen): path-following (RomCurveWalker) flyer/swimmer with
 *     buoyancy clamping and periodic decoy sfx.
 *   - mutated EBA (mutatedEbaInit / fn_80156B0C / fn_80156C34 / fn_80156950 /
 *     mutatedEbaUpdateWhileFrozen): move-table sequenced attacker
 *     (gDusterEbaMoveTable entries, 0xC bytes each).
 */
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/obj_placement.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/objfsa.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"

typedef struct DusterState
{
    u8 pad00[0x2F8];
    u16 moveEventFired; /* 0x2F8 nonzero = current move fired its progress event this frame */
    u8 pad2FA[0x324 - 0x2FA];
    f32 phaseTimer; /* 0x324 */
    f32 decoyTimer; /* 0x328 */
} DusterState;

#define DUSTER_HIT_VOLUME_SLOT 10

#pragma dont_inline on

extern int lbl_803DBCD8[2];
extern u8 gDusterEbaMoveTable[];
extern void fn_8014CD1C(int obj, int state, int moveId, f32 a, f32 b, int c);
extern const f32 lbl_803E2A98;
extern const f32 lbl_803E2AA8;
extern const f32 lbl_803E2AAC;
extern const f32 lbl_803E2AB0;
extern const f32 lbl_803E2AB4;
extern const f32 lbl_803E2AB8;
extern const f32 lbl_803E2ABC;
extern const f32 lbl_803E2AC0;
extern const f32 lbl_803E2AC4;
extern const f32 lbl_803E2AC8;
extern const f32 lbl_803E2ACC;
extern const f32 lbl_803E2AD0;
extern const f32 lbl_803E2AD4;
extern const f32 lbl_803E2AD8;
extern const f32 lbl_803E2ADC;
extern f32 lbl_803E2AE0;
extern const f32 lbl_803E2AE4;
extern const f32 lbl_803E2AE8;
extern const f32 lbl_803E2AEC;
extern const f32 lbl_803E2AF0;
extern const f32 lbl_803E2AF4;
extern const f32 lbl_803E2AF8;
extern const f32 lbl_803E2AFC;
extern const f32 lbl_803E2B00;
extern const f32 lbl_803E2B04;
extern const f32 lbl_803E2B08;
extern const f32 lbl_803E2B0C;
extern const f32 lbl_803E2B10;
extern const f32 lbl_803E2B14;

void wbUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_wingflap_260);
            ((BaddieState*)state)->hitCounter = 0;
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x20;
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        }
    }
    return;
}

void fn_8015625C(u32 obj, int state)
{
    u32 randVal;
    GameObject* tracked;
    f32 moveSpeed;
    ObjHitsPriorityState* hitState;

    if (((DusterState*)state)->decoyTimer > lbl_803E2AA8)
    {
        ((DusterState*)state)->decoyTimer = lbl_803E2AAC;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DUSTER_HIT_VOLUME_SLOT, 1, 0);
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mn_heart1_c_261);
    }
    ((DusterState*)state)->decoyTimer = ((DusterState*)state)->decoyTimer - timeDelta;
    if (((DusterState*)state)->decoyTimer <= lbl_803E2A98)
    {
        if ((((BaddieState*)state)->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_eba_pollenspin);
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2A98, *(u8*)(state + 0x323));
    }
    if (((DusterState*)state)->phaseTimer > lbl_803E2A98)
    {
        ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
        if (((DusterState*)state)->phaseTimer <= lbl_803E2A98)
        {
            ((DusterState*)state)->phaseTimer = lbl_803E2AB0;
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        }
    }
    else if ((((BaddieState*)state)->controlFlags & 0x400) != 0)
    {
        ((DusterState*)state)->phaseTimer = lbl_803E2AB0;
    }
    if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = lbl_803E2AB4;
    }
    else
    {
        tracked = (GameObject*)((BaddieState*)state)->trackedObj;
        moveSpeed = sidekickToy_accelerateTowardTargetXZ(
            (GameObject*)(obj), tracked->anim.worldPosX, lbl_803E2AB8 + tracked->anim.worldPosY,
            tracked->anim.worldPosZ, lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4, ((BaddieState*)state)->unk304);
    }
    if (((moveSpeed > lbl_803E2A98) && (((GameObject*)obj)->anim.velocityY < lbl_803E2AC8)) ||
        ((((BaddieState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
    if ((((BaddieState*)state)->seqEntryIndex != 0) && (moveSpeed > lbl_803E2A98))
    {
        ((BaddieState*)state)->unk308 = lbl_803E2ACC;
        if (((BaddieState*)state)->hitCounter != 0)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2AD0;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E2AD4)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD4;
        }
        else if (((GameObject*)obj)->anim.velocityY > lbl_803E2AD8)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD8;
        }
    }
    else
    {
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((BaddieState*)state)->unk308 > lbl_803E2ADC)
        {
            ((BaddieState*)state)->unk308 = -(lbl_803E2AE0 * timeDelta - ((BaddieState*)state)->unk308);
        }
    }
    fn_8014CD1C(obj, state, 0x2d, lbl_803E2A98, *(f32*)&lbl_803E2A98, 0);
}

void fn_8015652C(u32 obj, int state)
{
    u32 randVal;
    RomCurveWalker* route;
    ObjPlacement* placement;
    f32 moveSpeed;
    ObjHitsPriorityState* hitState;

    route = *(RomCurveWalker**)state;
    placement = ((GameObject*)obj)->anim.placement;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DUSTER_HIT_VOLUME_SLOT, 1, 0);
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mn_heart1_c_261);
    }
    ((DusterState*)state)->decoyTimer = ((DusterState*)state)->decoyTimer - timeDelta;
    if (((DusterState*)state)->decoyTimer <= lbl_803E2A98)
    {
        if ((((BaddieState*)state)->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_eba_pollenspin);
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2A98, *(u8*)(state + 0x323));
    }
    if (((DusterState*)state)->phaseTimer > lbl_803E2A98)
    {
        ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
        if (((DusterState*)state)->phaseTimer <= lbl_803E2A98)
        {
            ((DusterState*)state)->phaseTimer = lbl_803E2A98;
        }
    }
    else
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (((Curve_AdvanceAlongPath(route, ((BaddieState*)state)->pathStep) != 0 || route->atSegmentEnd != 0) &&
             (*gRomCurveInterface)->goNextPoint(route) != 0) &&
            (*gRomCurveInterface)
                    ->initCurve(*(RomCurveWalker**)state, (void*)obj, lbl_803E2AE4, (int*)&lbl_803DBCD8, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags =
                ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
        {
            moveSpeed = lbl_803E2ABC;
        }
        else
        {
            moveSpeed = sidekickToy_accelerateTowardTargetXZ((GameObject*)(obj), route->posX, route->posY, route->posZ,
                                                             lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4,
                                                             ((BaddieState*)state)->unk304);
        }
    }
    else if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = lbl_803E2ABC;
    }
    else
    {
        moveSpeed = sidekickToy_accelerateTowardTargetXZ((GameObject*)(obj), placement->posX, placement->posY,
                                                         placement->posZ, lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4,
                                                         ((BaddieState*)state)->unk304);
    }
    if (((moveSpeed > lbl_803E2A98) && (((GameObject*)obj)->anim.velocityY < lbl_803E2AC8)) ||
        ((((BaddieState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
    if ((((BaddieState*)state)->seqEntryIndex != 0) && (moveSpeed > lbl_803E2A98))
    {
        ((BaddieState*)state)->unk308 = lbl_803E2ACC;
        if (((BaddieState*)state)->hitCounter != 0)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2AD0;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E2AD4)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD4;
        }
        else if (((GameObject*)obj)->anim.velocityY > lbl_803E2AD8)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD8;
        }
    }
    else
    {
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((BaddieState*)state)->unk308 > lbl_803E2ADC)
        {
            ((BaddieState*)state)->unk308 = -(lbl_803E2AE0 * timeDelta - ((BaddieState*)state)->unk308);
        }
    }
    fn_8014CD1C(obj, state, 0x2d, lbl_803E2A98, *(f32*)&lbl_803E2A98, 0);
}

void wbInit(u32 unused, int state)
{
    float fa;
    u32 ua;

    ((BaddieState*)state)->speedScale = lbl_803E2AE8;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0x2002b029;
    ((BaddieState*)state)->unk308 = lbl_803E2ACC;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2AEC;
    ((BaddieState*)state)->unk304 = lbl_803E2AF0;
    ((BaddieState*)state)->unk320 = 0;
    fa = lbl_803E2AF4;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2AF4;
    ((BaddieState*)state)->unk321 = 1;
    ((BaddieState*)state)->unk318 = fa;
    ((BaddieState*)state)->unk322 = 2;
    ((BaddieState*)state)->unk31C = fa;
    ua = randomGetRange(0x78, 0x1e0);
    ((DusterState*)state)->decoyTimer = (float)(int)ua;
    return;
}

void fn_80156950(u32 obj, int state)
{
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 5:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_bite);
        }
        break;
    case 6:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_bite);
        }
        break;
    case 7:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2AF8)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_bite);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
            }
        }
        break;
    case 8:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2AFC)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
            }
            else if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2B00)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_call1);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
            }
        }
        break;
    }
    return;
}

void mutatedEbaUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    int move;

    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            if ((((move = ((GameObject*)obj)->anim.currentMove) == 0) || (move == 1)) || (move == 3) || (move == 4))
            {
                Sfx_PlayFromObject(obj, SFXTRIG_mv_ladderslide16_250);
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
            }
            else
            {
                Baddie_SetMove(obj, state, 4, lbl_803E2B04, 0, 0);
                ((BaddieState*)state)->seqEntryIndex = 0;
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_call);
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
            }
        }
    }
    return;
}

void fn_80156B0C(u32 obj, int state)
{
    int tblOff;

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    if (((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0) &&
        (((BaddieState*)state)->seqEntryIndex <= 1))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ((BaddieState*)state)->seqEntryIndex += 1;
        if (10 < ((BaddieState*)state)->seqEntryIndex)
        {
            ((BaddieState*)state)->seqEntryIndex = 3;
        }
        if (*(u16*)(state + 0x2a0) < 4)
        {
            tblOff = (u32)((BaddieState*)state)->seqEntryIndex * 0xc;
            Baddie_SetMove(obj, state, gDusterEbaMoveTable[tblOff + 8], *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
        }
        else
        {
            tblOff = (u32)((BaddieState*)state)->seqEntryIndex * 0xc;
            Baddie_SetMove(obj, state, gDusterEbaMoveTable[tblOff + 9], *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
        }
    }
    fn_80156950(obj, state);
    return;
}

void fn_80156C34(u32 obj, int state)
{
    int tblOff;
    u32 phase;

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        phase = ((BaddieState*)state)->seqEntryIndex;
        if (phase == 0)
        {
            ((BaddieState*)state)->seqEntryIndex += 1;
        }
        else if (phase >= 2)
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
        tblOff = (u32)((BaddieState*)state)->seqEntryIndex * 0xc;
        Baddie_SetMove(obj, state, gDusterEbaMoveTable[tblOff + 8], *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
    }
    fn_80156950(obj, state);
    return;
}

void mutatedEbaInit(u32 unused, int state)
{
    float fa;

    ((BaddieState*)state)->speedScale = lbl_803E2B08;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0x46001;
    ((BaddieState*)state)->unk308 = lbl_803E2B0C;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2B10;
    ((BaddieState*)state)->unk304 = lbl_803E2B14;
    ((BaddieState*)state)->unk320 = 0;
    fa = lbl_803E2B04;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2B04;
    ((BaddieState*)state)->unk321 = 4;
    ((BaddieState*)state)->unk318 = fa;
    ((BaddieState*)state)->unk322 = 3;
    ((BaddieState*)state)->unk31C = fa;
    ((BaddieState*)state)->seqEntryIndex = 1;
    ((BaddieState*)state)->hitCounter = 0xa;
    return;
}
