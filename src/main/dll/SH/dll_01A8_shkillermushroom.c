/*
 * shkillermushroom (DLL 0x1A8) - the killer mushroom enemy rooted in the
 * ground in ThornTail Hollow. It stays dormant until the player runs close,
 * then emerges and inflates a spherical damage field; striking it pops it.
 *
 * EnemyMushroomState.stateId killer path (live-verified in Dolphin, watching
 * one mushroom's stateId byte through a full cycle):
 *   0  dormant - hidden/idle; wakes to 3 when the player is within detectRange
 *                AND moving fast enough (player animSpeedA, via fn_8029610C,
 *                >= gKillerMushroomTriggerAnimSpeed) - a slow walk sneaks past
 *   3  emerge  - growl (baddie_haga_talk3) + emerge anim; -> 4 when anim done
 *   4  attack  - hitRadius inflates (gKillerMushroomChaseRadiusRate, capped at
 *                gKillerMushroomMaxHitRadius) and records a contact hit on the
 *                player; -> 5 after gKillerMushroomChaseDuration frames
 *   5  deflate - cools down for the placement regrow delay; -> 0
 *   9  popped  - struck while active; spawns the burst fx then resets to 0
 * States 1/2/6/0xa belong to the shared edible-mushroom grow/despawn/respawn
 * path, not the killer cycle. The per-state animation move and advance rate
 * come from the gKillerMushroomStateAnimMoves / gKillerMushroomStateAnimRates
 * tables.
 */
#include "main/dll/ediblemushroom.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"

#define SHKILLERMUSHROOM_OBJGROUP 3
extern void ObjGroup_RemoveObject(u32 obj, int group);

#define SHKILLERMUSHROOM_OBJFLAG_PARENT_SLACK 0x1000

/* EnemyMushroomState::stateFlags bits (killer-mushroom local) */
#define MUSHROOM_STATEFLAG_HIT_PLAYER 0x1 /* player already hit this attack cycle */
#define MUSHROOM_STATEFLAG_ANIM_DONE  0x2 /* current move finished this frame */
#define MUSHROOM_STATEFLAG_ACTIVE     0x4 /* hittable this frame (set at update top) */


extern f32 gKillerMushroomRiseStepEpsilon;
extern const f32 lbl_803E52FC;
extern f32 gKillerMushroomRiseDurationBase;
extern f32 gKillerMushroomHeightTargetJitter;

#pragma dont_inline on
extern void ObjPath_GetPointWorldPosition(void* obj, int idx, void* out0, void* out1, void* out2, int flag);
extern f32 lbl_803E5310;
extern f32 gKillerMushroomSpawnYOffset;
extern void Sfx_KeepAliveLoopedObjectSound(int* obj, int id);
extern int objIsFrozen(int* obj);
extern int EmissionController_IsLingering(u8 * player);
extern int fn_80296448(u8 * player);
extern f32 fn_8029610C(u8 * player);
extern void objFn_8002b67c(int* obj);
extern void Obj_StartModelFadeIn(int* obj, int frames);
extern void Obj_ResetModelColorState(int* obj);
extern int Sfx_PlayFromObject(int* obj, int id);

s16 gKillerMushroomStateAnimMoves[12] = {0, 0, 4, 1, 2, 3, 5, 6, 6, 6, 0, 0};
f32 gKillerMushroomStateAnimRates[11] = {
    0.0f, 0.0f, 0.008f, 0.025f, 0.018f, 0.015f, 0.006f, 0.008f, 0.005f, 0.005f, 0.005f,
};
extern f32 gKillerMushroomHitEffectScale;
extern f32 gKillerMushroomInflateRadiusRate;
extern f32 gKillerMushroomMaxHitRadius;
extern f32 gKillerMushroomChaseRadiusRate;
extern f32 gKillerMushroomChaseDuration;
extern f32 gKillerMushroomRiseStepDecay;
extern f32 lbl_803E532C;
extern f32 lbl_803E5330;
extern f32 gKillerMushroomPopFxInterval;
extern f32 gKillerMushroomDetectRangeScale;
extern f32 gKillerMushroomTriggerAnimSpeed;
extern f32 gKillerMushroomPopAnimProgressDiv;

void enemymushroom_resetToSpawn(EnemyMushroomObject* obj, EnemyMushroomState* state, int enableTimer)
{
    EnemyMushroomMapData* mapData;
    u32 randomValue;
    f32 fr;

    mapData = obj->mapData;
    obj->rotZ = randomGetRange(-0x5dc, 0x5dc);
    obj->rotY = randomGetRange(-0x5dc, 0x5dc);
    obj->rotX = randomGetRange(-0x5dc, 0x5dc);
    obj->alpha = 0xff;
    obj->flags = (s16)(obj->flags & ~OBJANIM_FLAG_HIDDEN);
    obj->posX = mapData->posX;
    obj->posY = mapData->posY;
    obj->posZ = mapData->posZ;
    if (enableTimer != 0)
    {
        obj->scale = gKillerMushroomRiseStepEpsilon;
        state->timer = lbl_803E52FC;
        randomValue = randomGetRange(0, 100);
        fr = (f32)(s32)
        randomValue;
        fr = gKillerMushroomRiseDurationBase + fr;
        state->riseDuration = fr;
        randomValue = randomGetRange(-100, 100);
        fr = (f32)(s32)
        randomValue;
        fr = gKillerMushroomHeightTargetJitter * fr + state->baseScale;
        state->heightTarget = fr;
        state->riseStep = state->heightTarget / state->riseDuration;
    }
    ObjHits_EnableObject((int)obj);
    ObjHits_RefreshObjectState((int)obj);
}
#pragma dont_inline reset

int enemymushroom_getExtraSize(void)
{
    return 0x3c;
}

int enemymushroom_getObjectTypeId(EnemyMushroomObject* obj)
{
    return (*(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1f) << 0xb) | 0x400;
}

void enemymushroom_free(EnemyMushroomObject* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
    ObjGroup_RemoveObject((int)obj, SHKILLERMUSHROOM_OBJGROUP);
}

void enemymushroom_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    extern void objRenderFn_8003b8f4(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
    void* state = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5310);
        ObjPath_GetPointWorldPosition(obj, 0, (char*)state + 0x20, (char*)state + 0x24, (char*)state + 0x28, 0);
    }
}

void enemymushroom_hitDetect(void)
{
}

typedef struct EnemymushroomPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    u16 regrowDelay; /* 0x18: frames before a deflated mushroom regrows */
    u8 pad1A[0x1C - 0x1A];
    s16 popGameBit; /* 0x1C: game bit set when popped (-1 = none) */
    u8 detectRange; /* 0x1E: proximity-detection range scale */
    u8 pad1F[0x20 - 0x1F];
} EnemymushroomPlacement;

void enemymushroom_release(void)
{
}

void enemymushroom_initialise(void)
{
}

/* Constructor: seeds the state block, clamps the regrow period, offsets the
 * spawn height, flags the model, optionally resets to spawn, and registers
 * in object group 3. */
void enemymushroom_init(EnemyMushroomObject* obj, EnemyMushroomMapData* arg, int flag)
{
    extern void ObjGroup_AddObject(int* obj, int group);
    EnemyMushroomState* state = obj->state;
    f32 z = lbl_803E52FC;

    state->timer = z;
    state->hitRadius = z;
    state->baseScale = obj->scale;
    state->respawnFrameLimit = arg->respawnFrameLimit;
    if (state->respawnFrameLimit < 0x708)
    {
        state->respawnFrameLimit = 0x708;
    }
    obj->posY = arg->posY - gKillerMushroomSpawnYOffset;
    if (obj->modelState != NULL)
    {
        obj->modelState->flags |= 0x810;
    }
    if (flag == 0)
    {
        enemymushroom_resetToSpawn(obj, state, 0);
    }
    ObjGroup_AddObject((int*)obj, SHKILLERMUSHROOM_OBJGROUP);
}

typedef struct
{
    f32 particleParams[3];
    f32 x, y, z;
} MushHitInfo;

/* Per-frame state machine: dormant -> inflate -> chase -> deflate cycle,
 * hit reaction, pop and respawn. */
#pragma opt_common_subs off
void enemymushroom_update(int* obj)
{
    extern f32 Vec_distance(f32* a, f32* b);
    char* state;
    u8* player;
    int* src;
    MushHitInfo hv;
    int hitObject;
    int hitSphereIndex;
    u32 hitVolume;
    int hitType;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    src = *(int**)&((GameObject*)obj)->anim.placementData;
    ObjHits_ClearHitVolumes((int)obj);
    ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    ((EnemyMushroomState*)state)->stateFlags |= MUSHROOM_STATEFLAG_ACTIVE;

    if (objIsFrozen(obj))
    {
        hitType = ObjHits_GetPriorityHitWithPosition((int)obj, &hitObject, &hitSphereIndex, &hitVolume,
                                                     &hv.x, &hv.y, &hv.z);
        if (hitType != 0 && hitType != 0x10)
        {
            hv.x += playerMapOffsetX;
            hv.z += playerMapOffsetZ;
            objLightFn_8009a1dc(obj, gKillerMushroomHitEffectScale, &hv, 1, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
            Obj_ResetModelColorState(obj);
        }
        return;
    }

    if (((GameObject*)player)->objectFlags & SHKILLERMUSHROOM_OBJFLAG_PARENT_SLACK)
    {
        return;
    }

    switch (((EnemyMushroomState*)state)->stateId)
    {
    case 6:
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_diallp_c);
        ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_ACTIVE);
        ((EnemyMushroomState*)state)->hitRadius = gKillerMushroomInflateRadiusRate * timeDelta + ((EnemyMushroomState*)state)->hitRadius;
        if (((EnemyMushroomState*)state)->hitRadius > *(f32*)&gKillerMushroomMaxHitRadius)
        {
            ((EnemyMushroomState*)state)->hitRadius = gKillerMushroomMaxHitRadius;
        }
        if (!(((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_HIT_PLAYER))
        {
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <= ((
                    EnemyMushroomState*)state)->hitRadius &&
                !EmissionController_IsLingering(player) && !fn_80296448(player) &&
                !(((GameObject*)player)->objectFlags & SHKILLERMUSHROOM_OBJFLAG_PARENT_SLACK))
            {
                ObjHits_RecordObjectHit((int)player, (int)obj, 0x16, 1, 0);
                ((EnemyMushroomState*)state)->stateFlags |= MUSHROOM_STATEFLAG_HIT_PLAYER;
            }
        }
        if (((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_ANIM_DONE)
        {
            ((EnemyMushroomState*)state)->timer = lbl_803E52FC;
            ((EnemyMushroomState*)state)->stateId = 2;
        }
        hv.x = ((EnemyMushroomState*)state)->hitEffectX;
        hv.y = ((EnemyMushroomState*)state)->hitEffectY;
        hv.z = ((EnemyMushroomState*)state)->hitEffectZ;
        {
            u8 k = 1;
            int base = 0x200000;
            while (k != 0)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x3eb, &hv, base + 1,
                                                 -1, NULL);
                k--;
            }
        }
        break;
    case 2:
        ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_ACTIVE);
        if (((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_ANIM_DONE)
        {
            int t = ((GameObject*)obj)->anim.alpha - framesThisStep * 4;
            if (t < 0)
            {
                t = 0;
            }
            ((GameObject*)obj)->anim.alpha = t;
            ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->timer + timeDelta;
            if (((EnemyMushroomState*)state)->timer > (f32)((EnemyMushroomState*)state)->respawnFrameLimit)
            {
                enemymushroom_resetToSpawn((EnemyMushroomObject*)obj, (EnemyMushroomState*)state, 1);
                ((EnemyMushroomState*)state)->stateId = 1;
            }
        }
        break;
    case 3:
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9c);
        if (((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_ANIM_DONE)
        {
            ((EnemyMushroomState*)state)->stateId = 4;
        }
        break;
    case 4:
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        ((EnemyMushroomState*)state)->hitRadius = gKillerMushroomChaseRadiusRate * timeDelta + ((EnemyMushroomState*)state)->hitRadius;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_diallp_c);
        if (!(((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_HIT_PLAYER))
        {
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <= ((
                    EnemyMushroomState*)state)->hitRadius &&
                !EmissionController_IsLingering(player) && !fn_80296448(player) &&
                !(((GameObject*)player)->objectFlags & SHKILLERMUSHROOM_OBJFLAG_PARENT_SLACK))
            {
                ObjHits_RecordObjectHit((int)player, (int)obj, 0x16, 1, 0);
                ((EnemyMushroomState*)state)->stateFlags |= MUSHROOM_STATEFLAG_HIT_PLAYER;
            }
        }
        if (((EnemyMushroomState*)state)->hitRadius > *(f32*)&gKillerMushroomMaxHitRadius)
        {
            ((EnemyMushroomState*)state)->hitRadius = gKillerMushroomMaxHitRadius;
        }
        ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->timer + timeDelta;
        if (((EnemyMushroomState*)state)->timer > gKillerMushroomChaseDuration)
        {
            ((EnemyMushroomState*)state)->timer = lbl_803E52FC;
            ((EnemyMushroomState*)state)->stateId = 5;
        }
        hv.x = ((EnemyMushroomState*)state)->hitEffectX;
        hv.y = ((EnemyMushroomState*)state)->hitEffectY;
        hv.z = ((EnemyMushroomState*)state)->hitEffectZ;
        {
            u8 k = 1;
            int base = 0x200000;
            while (k != 0)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x3eb, &hv, base + 1,
                                                 -1, NULL);
                k--;
            }
        }
        break;
    case 5:
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->timer + timeDelta;
        if (((EnemyMushroomState*)state)->timer > (f32)((EnemymushroomPlacement*)src)->regrowDelay)
        {
            if (((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_ANIM_DONE)
            {
                ((EnemyMushroomState*)state)->stateId = 0;
                ((EnemyMushroomState*)state)->hitRadius = lbl_803E52FC;
                ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_HIT_PLAYER);
            }
        }
        break;
    case 1:
        ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_ACTIVE);
        if (((GameObject*)obj)->anim.rootMotionScale > ((EnemyMushroomState*)state)->heightTarget)
        {
            ((EnemyMushroomState*)state)->riseStep = ((EnemyMushroomState*)state)->riseStep / gKillerMushroomRiseStepDecay;
        }
        if (((EnemyMushroomState*)state)->riseStep < gKillerMushroomRiseStepEpsilon)
        {
            ((EnemyMushroomState*)state)->riseStep = lbl_803E52FC;
        }
        ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->timer + timeDelta;
        ((GameObject*)obj)->anim.rootMotionScale = ((EnemyMushroomState*)state)->riseStep * timeDelta + ((GameObject*)
            obj)->anim.rootMotionScale;
        if (((EnemyMushroomState*)state)->timer > ((EnemyMushroomState*)state)->riseDuration)
        {
            ((EnemyMushroomState*)state)->stateId = 0;
        }
        break;
    case 9:
        if (((EnemyMushroomState*)state)->timer <= lbl_803E52FC)
        {
            ((EnemyMushroomState*)state)->timer = (f32)(int)
            randomGetRange(0xf0, 0x12c);
        }
        if (((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_ANIM_DONE)
        {
            ((EnemyMushroomState*)state)->timer = lbl_803E52FC;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_cagelp_c);
        {
            f32 nv = ((EnemyMushroomState*)state)->timer - timeDelta;
            ((EnemyMushroomState*)state)->timer = nv;
            if (nv <= lbl_803E52FC)
            {
                (*gExpgfxInterface)->freeSource((u32)obj);
                ((EnemyMushroomState*)state)->stateId = 0;
                objFn_8002b67c(obj);
            }
            else
            {
                f32 nw = ((EnemyMushroomState*)state)->effectTimer - timeDelta;
                ((EnemyMushroomState*)state)->effectTimer = nw;
                if (nw <= lbl_803E52FC)
                {
                    hv.x = lbl_803E532C;
                    hv.y = lbl_803E5330;
                    (*gPartfxInterface)->spawnObject(obj, 0x51d, &hv, 2, -1,
                                                     NULL);
                    ((EnemyMushroomState*)state)->effectTimer = gKillerMushroomPopFxInterval;
                }
                ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(
                    ((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
            }
        }
        break;
    case 0xa:
        ObjHits_DisableObject((u32)obj);
        ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->timer + timeDelta;
        if (((EnemyMushroomState*)state)->timer > (f32)((EnemyMushroomState*)state)->respawnFrameLimit)
        {
            enemymushroom_resetToSpawn((EnemyMushroomObject*)obj, (EnemyMushroomState*)state, 1);
            ((EnemyMushroomState*)state)->stateId = 1;
            objFn_8002b67c(obj);
        }
        break;
    default:
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
            if ((u16)(int)
                sqrtf(dx * dx + dy * dy + dz * dz) <
                    (u16)(int)(gKillerMushroomDetectRangeScale * (f32)((EnemymushroomPlacement*)src)->detectRange)
            )
            {
                if (fn_8029610C(player) >= gKillerMushroomTriggerAnimSpeed)
                {
                    ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_HIT_PLAYER);
                    ((EnemyMushroomState*)state)->stateId = 3;
                    ((EnemyMushroomState*)state)->timer = lbl_803E52FC;
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_haga_talk3);
                }
            }
        }
        break;
    }

    hitType = ObjHits_GetPriorityHitWithPosition((int)obj, &hitObject, &hitSphereIndex, &hitVolume,
                                                 &hv.x, &hv.y, &hv.z);
    hv.x += playerMapOffsetX;
    hv.z += playerMapOffsetZ;
    if (hitType != 0)
    {
        if (((EnemyMushroomState*)state)->stateFlags & MUSHROOM_STATEFLAG_ACTIVE)
        {
            if (hitType == 0x10)
            {
                Obj_StartModelFadeIn(obj, 0x12c);
            }
            else
            {
                if (((EnemyMushroomState*)state)->stateId != 9)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_mv_ladderslide16);
                }
                ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_HIT_PLAYER);
                if (((EnemymushroomPlacement*)src)->popGameBit != -1)
                {
                    GameBit_Set(((EnemymushroomPlacement*)src)->popGameBit, 1);
                }
                ((EnemyMushroomState*)state)->stateId = 9;
                ((EnemyMushroomState*)state)->timer = lbl_803E52FC;
                ((GameObject*)obj)->anim.currentMoveProgress = (f32)(int)
                randomGetRange(0, 0x28) / gKillerMushroomPopAnimProgressDiv;
            }
            objLightFn_8009a1dc(obj, gKillerMushroomHitEffectScale, &hv, 1, 0);
        }
    }

    if (((GameObject*)obj)->anim.currentMove != gKillerMushroomStateAnimMoves[((EnemyMushroomState*)state)->stateId])
    {
        ObjAnim_SetCurrentMove((int)obj, gKillerMushroomStateAnimMoves[((EnemyMushroomState*)state)->stateId], lbl_803E52FC, 0);
    }
    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, gKillerMushroomStateAnimRates[((EnemyMushroomState*)state)->stateId], timeDelta,
        NULL) != 0)
    {
        ((EnemyMushroomState*)state)->stateFlags |= MUSHROOM_STATEFLAG_ANIM_DONE;
    }
    else
    {
        ((EnemyMushroomState*)state)->stateFlags = (u8)(((EnemyMushroomState*)state)->stateFlags & ~MUSHROOM_STATEFLAG_ANIM_DONE);
    }
}
#pragma opt_common_subs reset

