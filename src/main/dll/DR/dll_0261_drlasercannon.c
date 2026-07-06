#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define DRLASERCANNON_OBJFLAG_PARENT_SLACK 0x1000
#define DRLASERCANNON_OBJFLAG_FREED 0x40

#define DR_LASERCANNON_EXTRA_SIZE 0x1ac

#define DR_LASERCANNON_GROUP_ID 0x3
#define DR_LASERCANNON_FIREPIPE_GROUP_ID 0x4a

#define DR_LASERCANNON_PITCH_FLIP_TYPE 0x417
#define DR_LASERCANNON_BEAM_OBJECT_TYPE 0x429
#define DR_LASERCANNON_FIREPIPE_OBJECT_TYPE 0x1b5

#define DR_LASERCANNON_SETUP_SIZE 0x20
#define DR_LASERCANNON_INITIAL_HEALTH 4
#define DR_LASERCANNON_HIDDEN_FLAG 0x4000
#define DR_LASERCANNON_TRICKY_COOLDOWN 0x258
#define DR_LASERCANNON_OPTIONAL_GAMEBIT 0xe90

#define DR_LASERCANNON_SETUP_INITIAL_YAW 0x18
#define DR_LASERCANNON_SETUP_RELOAD_FRAMES 0x19
#define DR_LASERCANNON_SETUP_TARGET_RANGE 0x1a
#define DR_LASERCANNON_SETUP_BEAM_SPEED 0x1c
#define DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT 0x1e
#define DR_LASERCANNON_SETUP_WARNING_OFF_GAMEBIT 0x20

#define DR_LASERCANNON_STATE_BEAM_OBJECT 0x00
#define DR_LASERCANNON_STATE_LAST_HIT_OBJECT 0x0c
#define DR_LASERCANNON_STATE_MUZZLE_X 0x10
#define DR_LASERCANNON_STATE_CURVE_FOLLOW 0x1c
#define DR_LASERCANNON_STATE_CURVE_END_X 0x84
#define DR_LASERCANNON_STATE_ANIM_STEP_SCALE 0x124
#define DR_LASERCANNON_STATE_TRICKY_COOLDOWN 0x128
#define DR_LASERCANNON_STATE_RELOAD_TIMER 0x12c
#define DR_LASERCANNON_STATE_AIM 0x130
#define DR_LASERCANNON_STATE_WARNING_OBJECT 0x190
#define DR_LASERCANNON_STATE_FIREPIPE_OBJECT 0x194
#define DR_LASERCANNON_STATE_ACTIVE_FRAMES 0x198
#define DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE 0x19c
#define DR_LASERCANNON_STATE_BOB_OFFSET 0x1a0
#define DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT 0x1a4
#define DR_LASERCANNON_STATE_HEALTH 0x1a6
#define DR_LASERCANNON_STATE_HAS_FIREPIPE 0x1a7
#define DR_LASERCANNON_STATE_FLAGS 0x1a8
#define DR_LASERCANNON_STATE_BOB_PHASE 0x1aa

#define DR_LASERCANNON_AIM_YAW 0x14
#define DR_LASERCANNON_AIM_PITCH 0x44

#define DR_LASERCANNON_WARNING_ACTIVE_MODE 4
#define DR_LASERCANNON_WARNING_HIDE_MODE 5
#define DR_LASERCANNON_WARNING_HIT_MODE 6

typedef struct DrLaserCannonSetup
{
    u8 pad00[DR_LASERCANNON_SETUP_INITIAL_YAW];
    s8 initialYaw;
    s8 reloadFrames;
    s16 targetRange;
    s16 beamSpeed;
    s16 destroyedGameBit;
    s16 warningOffGameBit;
} DrLaserCannonSetup;

typedef struct DrLaserCannonBeamSetup
{
    s16 objectType;
    u8 field02;
    u8 pad03;
    u8 field04;
    u8 field05;
    u8 field06;
    u8 field07;
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
} DrLaserCannonBeamSetup;

typedef struct DrLaserCannonAim
{
    u8 pad00[DR_LASERCANNON_AIM_YAW];
    s16 yaw;
    u8 pad16[DR_LASERCANNON_AIM_PITCH - 0x16];
    s16 pitch;
} DrLaserCannonAim;

typedef struct DrLaserCannonState
{
    int beamObject;
    u8 pad04[DR_LASERCANNON_STATE_LAST_HIT_OBJECT - 0x04];
    int lastHitObject;
    f32 muzzleX;
    f32 muzzleY;
    f32 muzzleZ;
    u8 curveFollow[DR_LASERCANNON_STATE_CURVE_END_X - 0x1C];
    f32 curveEndX;
    f32 curveEndY;
    f32 curveEndZ;
    u8 pad90[DR_LASERCANNON_STATE_ANIM_STEP_SCALE - 0x90];
    f32 animStepScale;
    int trickyCooldown;
    f32 reloadTimer;
    DrLaserCannonAim aim;
    u8 pad176[DR_LASERCANNON_STATE_WARNING_OBJECT - 0x176];
    int warningObject;
    int firepipeObject;
    int activeFrames;
    int hitExcludeType;
    f32 bobOffset;
    s16 optionalGameBit;
    s8 health;
    u8 hasFirepipe;
    BitFlags8 flags;
    u8 pad1A9;
    u16 bobPhase;
} DrLaserCannonState;

STATIC_ASSERT(offsetof(DrLaserCannonSetup, initialYaw) == DR_LASERCANNON_SETUP_INITIAL_YAW);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, reloadFrames) == DR_LASERCANNON_SETUP_RELOAD_FRAMES);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, targetRange) == DR_LASERCANNON_SETUP_TARGET_RANGE);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, beamSpeed) == DR_LASERCANNON_SETUP_BEAM_SPEED);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, destroyedGameBit) == DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, warningOffGameBit) == DR_LASERCANNON_SETUP_WARNING_OFF_GAMEBIT);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, objectType) == 0x0);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field02) == 0x2);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field04) == 0x4);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field05) == 0x5);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field06) == 0x6);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field07) == 0x7);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnX) == 0x8);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnY) == 0xc);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnZ) == 0x10);
STATIC_ASSERT(offsetof(DrLaserCannonAim, yaw) == DR_LASERCANNON_AIM_YAW);
STATIC_ASSERT(offsetof(DrLaserCannonAim, pitch) == DR_LASERCANNON_AIM_PITCH);
STATIC_ASSERT(offsetof(DrLaserCannonState, beamObject) == DR_LASERCANNON_STATE_BEAM_OBJECT);
STATIC_ASSERT(offsetof(DrLaserCannonState, lastHitObject) == DR_LASERCANNON_STATE_LAST_HIT_OBJECT);
STATIC_ASSERT(offsetof(DrLaserCannonState, muzzleX) == DR_LASERCANNON_STATE_MUZZLE_X);
STATIC_ASSERT(offsetof(DrLaserCannonState, curveFollow) == DR_LASERCANNON_STATE_CURVE_FOLLOW);
STATIC_ASSERT(offsetof(DrLaserCannonState, curveEndX) == DR_LASERCANNON_STATE_CURVE_END_X);
STATIC_ASSERT(offsetof(DrLaserCannonState, animStepScale) == DR_LASERCANNON_STATE_ANIM_STEP_SCALE);
STATIC_ASSERT(offsetof(DrLaserCannonState, trickyCooldown) == DR_LASERCANNON_STATE_TRICKY_COOLDOWN);
STATIC_ASSERT(offsetof(DrLaserCannonState, reloadTimer) == DR_LASERCANNON_STATE_RELOAD_TIMER);
STATIC_ASSERT(offsetof(DrLaserCannonState, aim) == DR_LASERCANNON_STATE_AIM);
STATIC_ASSERT(offsetof(DrLaserCannonState, warningObject) == DR_LASERCANNON_STATE_WARNING_OBJECT);
STATIC_ASSERT(offsetof(DrLaserCannonState, firepipeObject) == DR_LASERCANNON_STATE_FIREPIPE_OBJECT);
STATIC_ASSERT(offsetof(DrLaserCannonState, activeFrames) == DR_LASERCANNON_STATE_ACTIVE_FRAMES);
STATIC_ASSERT(offsetof(DrLaserCannonState, hitExcludeType) == DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE);
STATIC_ASSERT(offsetof(DrLaserCannonState, bobOffset) == DR_LASERCANNON_STATE_BOB_OFFSET);
STATIC_ASSERT(offsetof(DrLaserCannonState, optionalGameBit) == DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT);
STATIC_ASSERT(offsetof(DrLaserCannonState, health) == DR_LASERCANNON_STATE_HEALTH);
STATIC_ASSERT(offsetof(DrLaserCannonState, hasFirepipe) == DR_LASERCANNON_STATE_HAS_FIREPIPE);
STATIC_ASSERT(offsetof(DrLaserCannonState, flags) == DR_LASERCANNON_STATE_FLAGS);
STATIC_ASSERT(offsetof(DrLaserCannonState, bobPhase) == DR_LASERCANNON_STATE_BOB_PHASE);
STATIC_ASSERT(sizeof(DrLaserCannonState) == DR_LASERCANNON_EXTRA_SIZE);

int drlasercannon_getExtraSize(void) { return DR_LASERCANNON_EXTRA_SIZE; }

int drlasercannon_getObjectTypeId(void) { return 0x0; }

void drlasercannon_initialise(void)
{
}

void drlasercannon_release(void)
{
}

int drlasercannon_aimAtTarget(GameObject* self, GameObject* target, DrLaserCannonAim* out, int maxRate,
                              f32* eyePos)
{
    extern int getAngle(float y, float x);
    s16 negClampS;
    s16* vec;
    f32 d[3];
    f32* dp;
    f32 horiz;
    int yaw;
    int pitch;
    int negClamp;
    int clamp;
    int delta;
    s16 wrapDelta;

    /* Fetch the barrel's secondary rotation vector (pitch channel) from the model. */
    vec = (s16*)objModelGetVecFn_800395d8((int)self, 0xb);
    if (vec == NULL)
    {
        return 0;
    }
    /* No target: ease both yaw and pitch back toward rest by halving each frame. */
    if (target == NULL)
    {
        self->anim.rotX = (s16)(self->anim.rotX >> 1);
        *vec = (s16)(*vec >> 1);
        return 0;
    }
    /* Vector from the cannon's eye position to the target. */
    dp = d;
    if (target != NULL) dp = d;
    dp[0] = target->anim.localPosX - eyePos[0];
    dp[1] = target->anim.localPosY - eyePos[1];
    dp[2] = target->anim.localPosZ - eyePos[2];
    horiz = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
    /* Desired yaw from the ground-plane heading, pitch from height over horizontal range. */
    yaw = getAngle(dp[0], dp[2]);
    pitch = (s16)getAngle(dp[1], horiz);
    if (self->anim.seqId == DR_LASERCANNON_PITCH_FLIP_TYPE)
    {
        pitch = (s16) - pitch;
    }
    /* Below the full-speed threshold, clamp the requested aim to a scaled per-frame angle. */
    if (maxRate < 0x168)
    {
        clamp = (s16)(gLaserCannonAngleRateScale * maxRate);
        negClamp = -clamp;
        negClampS = negClamp;
        out->yaw = yaw;
        if (out->yaw > clamp)
        {
            out->yaw = clamp;
        }
        if (out->yaw < negClamp)
        {
            out->yaw = negClampS;
        }
        out->pitch = pitch;
        if (out->pitch > clamp)
        {
            out->pitch = clamp;
        }
        if (out->pitch < negClamp)
        {
            out->pitch = negClampS;
        }
    }
    else
    {
        out->yaw = yaw;
        out->pitch = pitch;
    }
    /* Shortest signed angular delta from current yaw to target, wrapped into [-0x8000, 0x8000]. */
    wrapDelta = out->yaw - (u16)self->anim.rotX;
    if (wrapDelta > 0x8000)
    {
        wrapDelta = wrapDelta - 0xFFFF;
    }
    if (wrapDelta < -0x8000)
    {
        wrapDelta = wrapDelta + 0xFFFF;
    }
    /* Limit the step to the max aim rate, then interpolate current yaw toward the target. */
    wrapDelta = (wrapDelta < -gLaserCannonMaxAimStep)
                    ? -gLaserCannonMaxAimStep
                    : (s16)((wrapDelta > gLaserCannonMaxAimStep) ? gLaserCannonMaxAimStep : wrapDelta);
    self->anim.rotX = (s16)((f32)self->anim.rotX + interpolate((f32)wrapDelta, lbl_803E68E4, timeDelta));
    /* Same wrap-and-step interpolation applied to the pitch channel. */
    if (vec != NULL)
    {
        wrapDelta = out->pitch - (u16) * vec;
        if (wrapDelta > 0x8000)
        {
            wrapDelta = wrapDelta - 0xFFFF;
        }
        if (wrapDelta < -0x8000)
        {
            wrapDelta = wrapDelta + 0xFFFF;
        }
        wrapDelta = (wrapDelta < -gLaserCannonMaxAimStep)
                        ? -gLaserCannonMaxAimStep
                        : (s16)((wrapDelta > gLaserCannonMaxAimStep) ? gLaserCannonMaxAimStep : wrapDelta);
        *vec = (s16)((f32) * vec + interpolate((f32)wrapDelta, lbl_803E68E4, timeDelta));
    }
    /* Report whether yaw is still far (> 0x100) from the target, i.e. not yet on-aim. */
    delta = self->anim.rotX - out->yaw;
    if (delta < 0)
    {
        delta = -delta;
    }
    return delta > 0x100;
}

void drlasercannon_free(int obj)
{
    DrLaserCannonState* state = ((GameObject*)obj)->extra;
    if ((void*)state->firepipeObject != NULL)
    {
        firepipe_clearLinkedUpdateFlag(state->firepipeObject);
        ObjLink_DetachChild(obj, state->firepipeObject);
    }
    if ((void*)state->warningObject != NULL)
    {
        Obj_FreeObject(state->warningObject);
    }
    ObjGroup_RemoveObject(obj, DR_LASERCANNON_GROUP_ID);
}

void drlasercannon_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    DrLaserCannonState* state = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E68E8);
        ObjPath_GetPointWorldPosition((int)obj, 0, &state->muzzleX, &state->muzzleY, &state->muzzleZ, 0);
        state->muzzleY = state->muzzleY - lbl_803E68EC;
    }
}

#pragma dont_inline on
int drlasercannon_getTrackedTarget(int obj, int* arg)
{
    int* tricky = getTrickyObject();
    void* player;
    void* r;
    int t;
    if (tricky != 0 && arg != 0 &&
        (u8)(*(int (**)(int*))((char*)*(void**)*(void**)((char*)tricky + 0x68) + 0x40))(tricky))
    {
        t = *arg - framesThisStep;
        *arg = t;
        if (t < 0)
        {
            (*(void (**)(int*, int, int))((char*)*(void**)*(void**)((char*)tricky + 0x68) + 0x34))(tricky, 0, 0);
            *arg = DR_LASERCANNON_TRICKY_COOLDOWN;
        }
        return (int)tricky;
    }
    player = Obj_GetPlayerObject();
    if (player != 0)
    {
        r = (void*)fn_802972A8();
        if (r != 0 && (((GameObject*)r)->objectFlags & DRLASERCANNON_OBJFLAG_PARENT_SLACK) == 0)
        {
            return (int)r;
        }
        if ((((GameObject*)player)->objectFlags & DRLASERCANNON_OBJFLAG_PARENT_SLACK) == 0)
        {
            return (int)player;
        }
    }
    return 0;
}
#pragma dont_inline reset

void drlasercannon_init(int obj, char* arg)
{
    DrLaserCannonState* state = ((GameObject*)obj)->extra;
    DrLaserCannonSetup* setup = (DrLaserCannonSetup*)arg;
    f32 fz;
    state->health = DR_LASERCANNON_INITIAL_HEALTH;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(setup->destroyedGameBit) != 0)
    {
        ((GameObject*)obj)->anim.flags |= DR_LASERCANNON_HIDDEN_FLAG;
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, DR_LASERCANNON_GROUP_ID);
    state->beamObject = 0;
    state->flags.b3 = 0;
    ((GameObject*)obj)->anim.rotX = (s16)(setup->initialYaw << 8);
    state->trickyCooldown = DR_LASERCANNON_TRICKY_COOLDOWN;
    state->animStepScale = lbl_803E6920;
    if (GameBit_Get(setup->destroyedGameBit) != 0)
    {
        state->flags.b0 = 1;
        state->flags.b4 = 1;
    }
    else
    {
        state->flags.b4 = 0;
    }
    state->flags.b5 = 0;
    fz = lbl_803E690C;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    if (GameBit_Get(setup->destroyedGameBit) == 0)
    {
        state->warningObject = fn_801702D4(obj, lbl_803E6938);
        if ((void*)state->warningObject != NULL)
        {
            staffFn_80170380(state->warningObject, DR_LASERCANNON_WARNING_ACTIVE_MODE);
        }
        state->flags.b6 = 1;
    }
    else
    {
        state->flags.b6 = 0;
        state->warningObject = 0;
    }
    storeZeroToFloatParam(&state->reloadTimer);
    s16toFloat(&state->reloadTimer, (s16)(setup->reloadFrames * 4 + 1));
    state->hasFirepipe = 0;
    state->flags.b7 = 1;
    state->hitExcludeType = DR_LASERCANNON_BEAM_OBJECT_TYPE;
    if (((GameObject*)obj)->anim.mapEventSlot == 2)
    {
        state->optionalGameBit = DR_LASERCANNON_OPTIONAL_GAMEBIT;
    }
    else
    {
        state->optionalGameBit = -1;
    }
}

void drlasercannon_hitDetect(int obj)
{
    DrLaserCannonState* state = ((GameObject*)obj)->extra;
    DrLaserCannonSetup* setup = (DrLaserCannonSetup*)((GameObject*)obj)->anim.placementData;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    u32 hitVolume;
    int hitObject;
    int hit;
    int* tricky;
    if (state->flags.b0 || state->flags.b3)
    {
        return;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, 0, &hitVolume, &hitPosX,
                                             &hitPosY, &hitPosZ);
    if (state->flags.b6 != 0)
    {
        if (hit != 0 && ((GameObject *)hitObject)->anim.seqId != state->hitExcludeType &&
            (void *)state->warningObject != NULL)
        {
            staffFn_80170380(state->warningObject, DR_LASERCANNON_WARNING_HIT_MODE);
        }
    }
    else if (((u32)(hit - 0xe) <= 1 || hit == 5) &&
             (void *)state->lastHitObject != (void *)hitObject &&
             ((GameObject *)hitObject)->anim.seqId != state->hitExcludeType)
    {
        state->lastHitObject = hitObject;
        state->health -= hitVolume;
        Obj_SpawnHitLightAndFade(obj, &hitPosX, lbl_803E68F0);
        fn_8009A8C8(obj, lbl_803E68F4);
        Sfx_PlayFromObject(obj, SFXTRIG_ar_awghitobj16);
        if (state->health <= 0)
        {
            tricky = getTrickyObject();
            Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11_4b6);
            spawnExplosion(obj, lbl_803E68F8, 0, 1, 1, 1, 0, 1, 0);
            state->flags.b0 = 1;
            GameBit_Set(setup->destroyedGameBit, 1);
            if (tricky != 0)
            {
                (*(void (**)(int*, int, int))((char*)*(void**)*(void**)((char*)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
            ((GameObject*)obj)->anim.flags |= DR_LASERCANNON_HIDDEN_FLAG;
        }
    }
    if (hit == 0)
    {
        state->lastHitObject = 0;
    }
    else
    {
        state->lastHitObject = hitObject;
    }
}

void drlasercannon_update(int obj)
{
    int target;
    DrLaserCannonState* state = ((GameObject*)obj)->extra;
    DrLaserCannonSetup* setup = (DrLaserCannonSetup*)((GameObject*)obj)->anim.placementData;
    int player = (int)Obj_GetPlayerObject();
    int spawned;
    int hit;
    f32 dist;
    f32 nearDist;
    int spawnFlag;
    f32 hitPos[3];
    f32 outv[6];
    f32 inv[6];
    ((GameObject*)obj)->anim.localPosY -= state->bobOffset;
    if (state->flags.b7 != 0)
    {
        nearDist = lbl_803E68F8;
        if ((state->firepipeObject = ObjGroup_FindNearestObject(DR_LASERCANNON_FIREPIPE_GROUP_ID, obj, &nearDist)) !=
            0u)
        {
            state->hasFirepipe = 1;
            ObjLink_AttachChild(obj, state->firepipeObject, 0);
            firepipe_setLinkedUpdateFlag(state->firepipeObject);
        }
        state->flags.b7 = 0;
    }
    if (state->flags.b4 == 0)
    {
        if (GameBit_Get(setup->destroyedGameBit) != 0)
        {
            state->flags.b4 = 1;
            state->flags.b0 = 1;
            ((GameObject*)obj)->anim.flags |= DR_LASERCANNON_HIDDEN_FLAG;
        }
    }
    if (state->flags.b0 != 0)
    {
        return;
    }
    if ((void*)state->warningObject != NULL)
    {
        ((GameObject*)state->warningObject)->anim.localPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)state->warningObject)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E68FC;
        ((GameObject*)state->warningObject)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ;
    }
    if (state->flags.b6 != 0)
    {
        if (GameBit_Get(setup->warningOffGameBit) != 0)
        {
            state->flags.b6 = 0;
            if ((void*)state->warningObject != NULL)
            {
                staffFn_80170380(state->warningObject, DR_LASERCANNON_WARNING_HIDE_MODE);
            }
        }
    }
    else
    {
        objfx_spawnFrameTimedHitPulse(obj, lbl_803E6900, 1, (u8)(5 - state->health), lbl_803E6904);
        if ((void*)state->warningObject != NULL)
        {
            staffFn_80170380(state->warningObject, DR_LASERCANNON_WARNING_HIDE_MODE);
        }
        state->activeFrames += 1;
        if (state->health == 0)
        {
            return;
        }
    }
    target = drlasercannon_getTrackedTarget(obj, &state->trickyCooldown);
    if ((void*)target != NULL &&
        (state->optionalGameBit == -1 || GameBit_Get(state->optionalGameBit) == 0))
    {
        hit = 1;
        dist = Vec_xzDistance(&((GameObject*)target)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
        if (dist < setup->targetRange)
        {
            hit = drlasercannon_aimAtTarget((GameObject*)obj, (GameObject*)target, &state->aim, 0x168,
                                            &state->muzzleX);
            if (hit != 0)
            {
                Sfx_PlayFromObject(obj, SFXfoot_dirt_run_3);
            }
        }
        else
        {
            s16* v;
            ((GameObject*)obj)->anim.rotX += lbl_803DC2AC;
            v = (s16*)objModelGetVecFn_800395d8(obj, 0xb);
            v[0] = (s16)(v[0] >> 1);
        }
        if (hit == 0 && dist < setup->targetRange)
        {
            if ((void*)target == (void*)player)
            {
                fn_802966CC(player);
            }
            switch (state->hasFirepipe)
            {
            case 0:
                state->hitExcludeType = DR_LASERCANNON_BEAM_OBJECT_TYPE;
                if (timerCountDown(&state->reloadTimer) != 0)
                {
                    if (Obj_PredictInterceptPoint(target,
                                    setup->beamSpeed / lbl_803E6908, &state->muzzleX, hitPos) != 0)
                    {
                        spawned = *(int*)&((GameObject*)obj)->extra;
                        if (Obj_IsLoadingLocked() == 0)
                        {
                            spawned = 0;
                        }
                        else
                        {
                            int o =
                                Obj_AllocObjectSetup(DR_LASERCANNON_SETUP_SIZE, DR_LASERCANNON_BEAM_OBJECT_TYPE);
                            ((DrLaserCannonBeamSetup*)o)->objectType = DR_LASERCANNON_BEAM_OBJECT_TYPE;
                            ((DrLaserCannonBeamSetup*)o)->field02 = 8;
                            ((DrLaserCannonBeamSetup*)o)->field04 = 1;
                            ((DrLaserCannonBeamSetup*)o)->field06 = 0xff;
                            ((DrLaserCannonBeamSetup*)o)->field05 = 1;
                            ((DrLaserCannonBeamSetup*)o)->field07 = 0xff;
                            ((DrLaserCannonBeamSetup*)o)->spawnX = ((DrLaserCannonState*)spawned)->muzzleX;
                            ((DrLaserCannonBeamSetup*)o)->spawnY = ((DrLaserCannonState*)spawned)->muzzleY;
                            ((DrLaserCannonBeamSetup*)o)->spawnZ = ((DrLaserCannonState*)spawned)->muzzleZ;
                            spawned = Obj_SetupObject(o, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
                        }
                        if ((void*)spawned != NULL)
                        {
                            outv[3] = state->muzzleX;
                            outv[4] = state->muzzleY;
                            outv[5] = state->muzzleZ;
                            inv[3] = hitPos[0];
                            inv[4] = hitPos[1];
                            inv[5] = hitPos[2];
                            (*(void (**)(int, f32*, f32*, f32))(*(int*)(*(int*)&((GameObject*)spawned)->anim.dll) +
                                0x24))(
                                spawned, outv, inv, setup->beamSpeed / lbl_803E6908);
                            state->beamObject = spawned;
                            ObjAnim_SetCurrentMove(obj, 1, lbl_803E690C, 0);
                            state->animStepScale = lbl_803E6910;
                            Sfx_PlayFromObject(obj, SFXfoot_dirt_run_1);
                            Sfx_PlayFromObject(obj, SFXfoot_dirt_run_2);
                        }
                    }
                    s16toFloat(&state->reloadTimer, (s16)(setup->reloadFrames << 2));
                }
                break;
            case 1:
                state->hitExcludeType = DR_LASERCANNON_FIREPIPE_OBJECT_TYPE;
                firepipe_setLinkedUpdateFlag(state->firepipeObject);
                break;
            }
        }
        else if ((void*)state->firepipeObject != NULL)
        {
            firepipe_clearLinkedUpdateFlag(state->firepipeObject);
        }
    }
    spawned = state->firepipeObject;
    if ((void*)spawned != NULL)
    {
        if ((((GameObject*)spawned)->objectFlags & DRLASERCANNON_OBJFLAG_FREED) != 0)
        {
            state->firepipeObject = 0;
        }
        else
        {
            s16* v = (s16*)objModelGetVecFn_800395d8(obj, 0xb);
            *(s16*)spawned = (s16)((f32) * (s16*)obj + lbl_803DDD68);
            ((GameObject*)spawned)->anim.rotY = v[0];
        }
    }
    if (state->flags.b5 != 0)
    {
        Obj_UpdateRomCurveFollowVelocity(obj, (f32*)state->curveFollow,
                                         lbl_803E6914 * lbl_803DC2A8, lbl_803E6918, lbl_803E6908, 1);
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }
    else
    {
        spawnFlag = 1;
        if ((*gRomCurveInterface)->initCurve(state->curveFollow, (void*)obj, lbl_803E691C, &spawnFlag, 0) == 0)
        {
            state->flags.b5 = 1;
            ((GameObject*)obj)->anim.localPosX = state->curveEndX;
            ((GameObject*)obj)->anim.localPosZ = state->curveEndZ;
            ((GameObject*)obj)->anim.localPosY = state->curveEndY;
        }
    }
    {
        int tricky = (int)getTrickyObject();
        if ((void*)tricky != NULL)
        {
            (*(void (**)(int, int, int, int))(*(int*)(*(int*)((char*)tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    hit = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animStepScale, timeDelta, 0);
    if (((GameObject*)obj)->anim.currentMove == 1 && hit != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E690C, 0);
        state->animStepScale = lbl_803E6920;
    }
    *(u16*)&state->bobPhase = (lbl_803E6924 * timeDelta + (f32)(u32)state->bobPhase);
    state->bobOffset =
        lbl_803E68EC * mathSinf(lbl_803E6928 * (f32)(u32)state->bobPhase / lbl_803E692C);
    ((GameObject*)obj)->anim.localPosY += state->bobOffset;
}
