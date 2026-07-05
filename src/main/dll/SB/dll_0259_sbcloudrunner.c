/*
 * SB_Cloudrunner (DLL 0x259) - the rideable Cloudrunner Krystal flies in the
 * ShipBattle prologue (SB = the retail "ShipBattle" map). She rides it to
 * chase General Scales' galleon and shoot out its guns/propellers, and at
 * the end of the level it catches her after Scales throws her overboard and
 * carries her on to Krazoa Palace. The player mounts the bird, holds A to
 * fire a forward burst (WCPushBlock_SpawnFromPath), steers with the analog
 * stick (padGetStickX/Y feed the yaw/pitch integrators in the steer update,
 * SB_CloudRunner_UpdateSteer), and the laser targets nearby objects
 * (SB_CloudRunner_HandlePriorityHit). The ride leans/banks via
 * WCPushBlock_UpdateRideTilt / WCPushBlock_UpdateCloudAction.
 *
 * The Cloudrunner was retooled from the WC ("warlock") push-block ride,
 * so the shared steering/burst helpers retain their WCPushBlock_* names.
 *
 * SB_CloudRunner_UpdateSteer (the analog-steer update) integrates the stick input into
 * the bird's body rotation and advances the flap animation; the two-op
 * "(d - 0x10000) + 1" forms below are the shortest-arc angle wrap-clamps.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/WC/dll_0259_sbcloudrunner.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/texture.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"

#define SBCLOUDRUNNER_OBJGROUP 0xa

typedef struct SBCloudRunnerState
{
    u8 pad0[0x10 - 0x0];
    s32 targetObj;          /* 0x10: laser-locked target (object type 0x8E) */
    s32 resource;           /* 0x14: acquired resource handle */
    void *texture0;         /* 0x18 */
    void *texture1;         /* 0x1C */
    u8 pad20[0x2C - 0x20];
    s16 rotXAccum;          /* 0x2C: roll accumulator, biased into anim.rotX */
    s16 rotZ;              /* 0x2E: integrated body roll */
    u8 pad30[0x4C - 0x30];
    f32 spawnPosX;          /* 0x4C */
    f32 spawnPosY;          /* 0x50 */
    f32 spawnPosZ;          /* 0x54 */
    f32 tiltY;              /* 0x58: banking integrator (Y) */
    f32 tiltZ;              /* 0x5C: banking integrator (Z) */
    f32 steerSmoothed;      /* 0x60: smoothed FX heading */
    s8 burstCooldown;       /* 0x64: frames until next A-burst allowed */
    s8 rideSubState;        /* 0x65: 0=ride, 1=tilt, 2/3=dismount */
    u8 pad66[0x6C - 0x66];
    s16 rideFrames;         /* 0x6C: frames in current rideSubState */
    s8 done;               /* 0x6E: ride finished, hide object */
    u8 pad6F[0x70 - 0x6F];
    s32 stickX;             /* 0x70 */
    s32 stickY;             /* 0x74 */
    f32 steerX;             /* 0x78 */
    f32 steerZ;             /* 0x7C */
    u8 aButtonHeld : 1;     /* 0x80 & 1: A held last frame */
    u8 pad80 : 7;
} SBCloudRunnerState;

STATIC_ASSERT(offsetof(SBCloudRunnerState, targetObj) == 0x10);
STATIC_ASSERT(offsetof(SBCloudRunnerState, resource) == 0x14);
STATIC_ASSERT(offsetof(SBCloudRunnerState, texture0) == 0x18);
STATIC_ASSERT(offsetof(SBCloudRunnerState, texture1) == 0x1C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rotXAccum) == 0x2C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rotZ) == 0x2E);
STATIC_ASSERT(offsetof(SBCloudRunnerState, spawnPosX) == 0x4C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, tiltY) == 0x58);
STATIC_ASSERT(offsetof(SBCloudRunnerState, steerSmoothed) == 0x60);
STATIC_ASSERT(offsetof(SBCloudRunnerState, burstCooldown) == 0x64);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rideSubState) == 0x65);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rideFrames) == 0x6C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, done) == 0x6E);
STATIC_ASSERT(offsetof(SBCloudRunnerState, stickX) == 0x70);
STATIC_ASSERT(offsetof(SBCloudRunnerState, steerX) == 0x78);
STATIC_ASSERT(sizeof(SBCloudRunnerState) == 0x84);

/* object type ids (anim.seqId at obj+0x46) */
#define SBCLOUDRUNNER_OBJ_TYPE 0x43      /* SB_CloudRunner_getObjectTypeId */
#define CLOUDRUNNER_TARGET_TYPE 0x8E     /* laser-lockable target */
#define HIT_TYPE_INVULNERABLE 281        /* hit objects of this type ignore the laser */
#define HIT_TYPE_BURST 154               /* hit type that triggers the partfx burst */

/* rideSubState (state->rideSubState, obj's switch dispatch) */
enum
{
    RIDE_SUBSTATE_STEER = 0,
    RIDE_SUBSTATE_TILT = 1,
    RIDE_SUBSTATE_DISMOUNT_A = 2,
    RIDE_SUBSTATE_DISMOUNT_B = 3
};

#define A_BUTTON_MASK 0x100              /* getButtonsHeld bit for the A button */
#define A_BURST_COOLDOWN_FRAMES 40       /* frames between A-bursts */
#define A_BURST_READY_THRESHOLD 20       /* cooldown below which a press queues a burst */
#define BURST_COOLDOWN_INIT 100          /* burstCooldown set at init */

/* anim move ids passed to ObjAnim_SetCurrentMove */
#define CLOUDRUNNER_MOVE_FLAP 5
#define CLOUDRUNNER_MOVE_GLIDE 256

/* effect ids spawned through gPartfxInterface on a laser hit */
#define PARTFX_HIT_FLASH 168
#define PARTFX_HIT_DEBRIS 169
#define PARTFX_HIT_DEBRIS_COUNT 10
#define PARTFX_SPAWN_FLAGS 0x200001

#define GAMEBIT_CLOUDRUNNER_HIT_SFX 3870 /* gates the extra hit SFX */
#define SFX_CLOUDRUNNER_HIT 1169
#define SFX_CLOUDRUNNER_FLAP 294

#define COLORFADE_RUMBLE_PRESET 4000     /* anim.rotY written on a fade hit */

extern void *ObjGroup_GetObjects();
extern void ObjGroup_RemoveObject();
extern void ObjGroup_AddObject();

extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern void WCPushBlock_SpawnFromPath(s16 *path, u8 *state);

extern void objRenderFn_8003b8f4(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E5C70;
extern void objSetMtxFn_800412d4(u32 x);


extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5C98;
extern f32 lbl_803E5CA8;
extern f32 lbl_803E5CAC;
extern f32 lbl_803E5CB0;
extern f32 lbl_803E5CB4;

extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);

extern const f32 lbl_803E5CB8;
extern f32 lbl_803E5C74;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void Obj_BuildInverseWorldTransformMatrix(int obj, f32 *mtx);
extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern int Obj_GetPlayerObject(void);
extern void SB_CloudRunner_onSeqFree(void);
extern void objHitDetectFn_80062e84(int player, int hitObj, int p3);
extern void fn_80295918(int obj, int sel, f32 fval);

extern u8 padGetStickX(int port);
extern u8 padGetStickY(int port);
extern const f32 lbl_803E5CBC;
extern const f32 lbl_803E5CC0;
extern void WCPushBlock_UpdateRideTilt(int obj, int state);
extern void WCPushBlock_UpdateCloudAction(int obj, int state);

void fn_801EED7C(void)
{
}

void fn_801EEDA8(void)
{
}

void fn_801EEDD4(void)
{
}

void SB_CloudRunner_hitDetect(void)
{
}

void SB_CloudRunner_release(void)
{
}

void SB_CloudRunner_initialise(void)
{
}


int fn_801EEDAC(void) { return 0x0; }
int fn_801EEDD8(void) { return 0x2; }
int fn_801EEDFC(void) { return 0x0; }
int fn_801EEE04(void) { return 0x0; }
int fn_801EEE2C(void) { return 0x0; }
int fn_801EEE34(void) { return 0x0; }
int SB_CloudRunner_getExtraSize(void) { return 0x84; }
int SB_CloudRunner_getObjectTypeId(void) { return SBCLOUDRUNNER_OBJ_TYPE; }

f32 fn_801EEDB4(int unused, f32 *p)
{
    f32 v = lbl_803E5C70;
    *p = v;
    return v;
}

void fn_801EEDE0(GameObject *src, f32 *out_x, f32 *out_y, f32 *out_z)
{
    *out_x = src->anim.localPosX;
    *out_y = src->anim.localPosY;
    *out_z = src->anim.localPosZ;
}

/* Forward to the laser-locked target's DLL vtable (slot 0x24). */
void shipBattleFn_801eed24(void *obj)
{
    void *target = *(void **)&((SBCloudRunnerState *)((GameObject *)obj)->extra)->targetObj;
    void *vt = *((GameObject *)target)->anim.dll;
    void (*fn)(void *) = *(void (**)(void *))((char *)vt + 0x24);
    fn(target);
}

void fn_801EED5C(int *obj, f32 *x, f32 *y, f32 *z)
{
    SBCloudRunnerState *state = ((GameObject *)obj)->extra;
    *x = state->spawnPosX;
    *y = state->spawnPosY;
    *z = state->spawnPosZ;
}

void fn_801EED80(void *obj)
{
    objSetMtxFn_800412d4(ObjPath_GetPointModelMtx((int)obj, 3));
}

void fn_801EEDC0(int p1, f32 *out, int *outInt)
{
    *out = lbl_803E5C70;
    *outInt = 0;
}

void fn_801EEE0C(int *obj, f32 *x, f32 *y, f32 *z)
{
    f32 *p = ((GameObject *)obj)->extra;
    *x = p[0];
    *y = p[1];
    *z = p[2];
}

/* Analog-stick steering update for the cloudrunner ride (target 0x801EE668;
 * Ghidra split this body as FUN_801eeafc). Integrates stick X/Y into the
 * bird's yaw/pitch/roll, clamps to the steer limits, advances the
 * flap/glide animation, and fires the forward burst on a fresh A press. */

/* Overlay for the A-held bit at state+0x80. Load-bearing: accessing it
 * through this separate typed pointer (not SBCloudRunnerState.aButtonHeld)
 * is what reproduces the retail codegen (md5-verified). */
typedef struct
{
    u8 held : 1;
} WCButtonFlag;

typedef struct
{
    u8 pad[0x1b];
    s8 sfxFlag;
} WCAnimEvents;

void SB_CloudRunner_UpdateSteer(s16 *obj, u8 *state)
{
    WCAnimEvents events;
    int doSpawn;
    int yawTarget;
    int pitchTarget;
    int d;
    int v;
    f32 spd;

    yawTarget = (-((SBCloudRunnerState *)state)->stickY * 6000) / 70;
    pitchTarget = (-((SBCloudRunnerState *)state)->stickX * 12000) / 70;

    {
        f32 t = (f32)(((SBCloudRunnerState *)state)->stickX << 3) / lbl_803E5C98;
        ((SBCloudRunnerState *)state)->rotXAccum = -(t * timeDelta - (f32)((SBCloudRunnerState *)state)->rotXAccum);
    }
    ((SBCloudRunnerState *)state)->rotXAccum -= (((SBCloudRunnerState *)state)->rotXAccum * framesThisStep) >> 5;

    d = yawTarget - (u16)((GameObject *)obj)->anim.rotY;
    if (d > 0x8000)
    {
        d = (d - 0x10000) + 1;
    }
    if (d < -0x8000)
    {
        d = (d + 0x10000) - 1;
    }
    ((GameObject *)obj)->anim.rotY = lbl_803E5CA8 * ((f32)d * timeDelta) + (f32) * (s16 *)(int)(obj + 1);

    d = pitchTarget - (u16) * (s16 *)(state + 0x2e);
    if (d > 0x8000)
    {
        d = (d - 0x10000) + 1;
    }
    if (d < -0x8000)
    {
        d = (d + 0x10000) - 1;
    }
    ((SBCloudRunnerState *)state)->rotZ = lbl_803E5CA8 * ((f32)d * timeDelta) + (f32) * (s16 *)(int)(state + 0x2e);

    v = ((GameObject *)obj)->anim.rotY;
    v = (v < -8000) ? -8000 : ((v > 8000) ? 8000 : v);
    ((GameObject *)obj)->anim.rotY = v;

    v = ((SBCloudRunnerState *)state)->rotZ;
    v = (v < -13000) ? -13000 : ((v > 13000) ? 13000 : v);
    ((SBCloudRunnerState *)state)->rotZ = v;

    ((GameObject *)obj)->anim.rotX = ((SBCloudRunnerState *)state)->rotXAccum + 0x4000;
    ((GameObject *)obj)->anim.rotZ = ((SBCloudRunnerState *)state)->rotZ;

    events.sfxFlag = 0;
    spd = lbl_803E5CB0 * (f32)((GameObject *)obj)->anim.rotY + lbl_803E5CAC;
    if (spd > lbl_803E5CB4)
    {
        if (((GameObject *)obj)->anim.currentMove != CLOUDRUNNER_MOVE_FLAP)
        {
            ObjAnim_SetCurrentMove((int)obj, CLOUDRUNNER_MOVE_FLAP, lbl_803E5C70, 0);
        }
    }
    else
    {
        spd = lbl_803E5CAC;
        if (((GameObject *)obj)->anim.currentMove != CLOUDRUNNER_MOVE_GLIDE)
        {
            ObjAnim_SetCurrentMove((int)obj, CLOUDRUNNER_MOVE_GLIDE, lbl_803E5C70, 0);
        }
    }
    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)((int)obj, spd, timeDelta, (ObjAnimEventList *)&events);

    ((GameObject *)obj)->anim.localPosX = ((SBCloudRunnerState *)state)->spawnPosX;
    ((GameObject *)obj)->anim.localPosY = ((SBCloudRunnerState *)state)->spawnPosY;
    ((GameObject *)obj)->anim.localPosZ = ((SBCloudRunnerState *)state)->spawnPosZ;

    if (events.sfxFlag)
    {
        Sfx_PlayFromObject(0, SFX_CLOUDRUNNER_FLAP);
    }

    doSpawn = 0;
    if (((WCButtonFlag *)(state + 0x80))->held)
    {
        if ((getButtonsHeld(0) & A_BUTTON_MASK) == 0)
        {
            ((WCButtonFlag *)(state + 0x80))->held = 0;
        }
        else if (((SBCloudRunnerState *)state)->burstCooldown == 0)
        {
            doSpawn = 1;
            ((SBCloudRunnerState *)state)->burstCooldown = A_BURST_COOLDOWN_FRAMES;
        }
    }
    else
    {
        if ((getButtonsHeld(0) & A_BUTTON_MASK) != 0)
        {
            ((WCButtonFlag *)(state + 0x80))->held = 1;
            if (((SBCloudRunnerState *)state)->burstCooldown < A_BURST_READY_THRESHOLD)
            {
                doSpawn = 1;
                ((SBCloudRunnerState *)state)->burstCooldown = A_BURST_COOLDOWN_FRAMES;
            }
        }
    }
    if (doSpawn)
    {
        WCPushBlock_SpawnFromPath(obj, state);
    }
}

/* SB_CloudRunner_HandlePriorityHit: when the laser hits an object whose
 * type isn't HIT_TYPE_INVULNERABLE and isn't currently in fade state,
 * fade it red, rumble, play SFX, gate further damage on a GameBit, then
 * if the hit type is HIT_TYPE_BURST emit 3 hit-flash partfx followed by a
 * 10-shot debris burst. */

struct WCPartfxArgs
{
    s16 v[3];
    s16 _pad;
    f32 scale;
};

void SB_CloudRunner_HandlePriorityHit(int obj, u8 *state)
{
    int hitObj;
    f32 pos[3];
    struct WCPartfxArgs args;
    int i;

    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, 0, &pos[0], &pos[1], &pos[2]) != 0)
    {
        if (objGetFlagsE5_2(obj) == 0)
        {
            if (((GameObject *)hitObj)->anim.seqId != HIT_TYPE_INVULNERABLE)
            {
                Obj_SetModelColorFadeRecursive(obj, 175, 200, 0, 0, 1);
                doRumble(lbl_803E5CB8);
                Sfx_PlayFromObject(0, SFXtr_bcrek2_c);
                if (GameBit_Get(GAMEBIT_CLOUDRUNNER_HIT_SFX) != 0)
                {
                    Sfx_PlayFromObject(obj, SFX_CLOUDRUNNER_HIT);
                }
                ((GameObject *)obj)->anim.rotY = COLORFADE_RUMBLE_PRESET;
                ((SBCloudRunnerState *)state)->rideSubState = RIDE_SUBSTATE_TILT;
                args.scale = lbl_803E5C74;
                args.v[0] = 0;
                args.v[1] = 0;
                args.v[2] = 0;
                if (((GameObject *)hitObj)->anim.seqId == HIT_TYPE_BURST)
                {
                    (*gPartfxInterface)->spawnObject((void *)obj, PARTFX_HIT_FLASH, &args,
                                                     PARTFX_SPAWN_FLAGS, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void *)obj, PARTFX_HIT_FLASH, &args,
                                                     PARTFX_SPAWN_FLAGS, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void *)obj, PARTFX_HIT_FLASH, &args,
                                                     PARTFX_SPAWN_FLAGS, -1, NULL);
                    for (i = 0; i < PARTFX_HIT_DEBRIS_COUNT; i++)
                    {
                        (*gPartfxInterface)->spawnObject((void *)obj, PARTFX_HIT_DEBRIS,
                                                         &args, PARTFX_SPAWN_FLAGS, -1,
                                                         NULL);
                    }
                }
            }
        }
    }
}

void SB_CloudRunner_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    f32 *state = obj->extra;
    f32 mtx[16];
    if (visible == -1)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E5C74);
        ObjPath_GetPointWorldPosition((int)obj, 3, state, state + 1, state + 2, 0);
        if (obj->anim.parent != NULL)
        {
            *state = *state - playerMapOffsetX;
            state[2] = state[2] - playerMapOffsetZ;
            Obj_BuildInverseWorldTransformMatrix(*(int *)&obj->anim.parent, mtx);
            PSMTXMultVec(mtx, state, state);
        }
    }
    else if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E5C74);
        ObjPath_GetPointWorldPosition((int)obj, 3, state, state + 1, state + 2, 0);
        if (obj->anim.parent != NULL)
        {
            *state = *state - playerMapOffsetX;
            state[2] = state[2] - playerMapOffsetZ;
            Obj_BuildInverseWorldTransformMatrix(*(int *)&obj->anim.parent, mtx);
            PSMTXMultVec(mtx, state, state);
        }
    }
    else
    {
        *state = obj->anim.localPosX;
        state[1] = obj->anim.localPosY;
        state[2] = obj->anim.localPosZ;
    }
}

int SB_CloudRunner_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    SBCloudRunnerState *state = ((GameObject *)obj)->extra;
    int player = Obj_GetPlayerObject();
    int i;
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)SB_CloudRunner_onSeqFree;
    state->spawnPosX = ((GameObject *)obj)->anim.localPosX;
    state->spawnPosY = ((GameObject *)obj)->anim.localPosY;
    state->spawnPosZ = ((GameObject *)obj)->anim.localPosZ;
    state->rotXAccum = (s16)(((GameObject *)obj)->anim.rotX - 0x4000);
    state->rotZ = ((GameObject *)obj)->anim.rotZ;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            objHitDetectFn_80062e84(player, state->targetObj, 0);
            fn_80295918(player, 5, lbl_803E5C70);
            state->done = 1;
        }
    }
    animUpdate->sequenceEventActive = 0;
    ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    return 0;
}

void SB_CloudRunner_free(GameObject *obj)
{
    SBCloudRunnerState *state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (state->texture0 != NULL)
    {
        textureFree(state->texture0);
        state->texture0 = NULL;
    }
    if (state->texture1 != NULL)
    {
        textureFree(state->texture1);
        state->texture1 = NULL;
    }
    Resource_Release(*(void **)&state->resource);
    state->resource = 0;
    ObjGroup_RemoveObject(obj, SBCLOUDRUNNER_OBJGROUP);
}

void SB_CloudRunner_init(GameObject *obj)
{
    SBCloudRunnerState *state = obj->extra;
    obj->animEventCallback = SB_CloudRunner_SeqFn;
    state->spawnPosX = obj->anim.localPosX;
    state->spawnPosY = obj->anim.localPosY;
    state->spawnPosZ = obj->anim.localPosZ;
    state->burstCooldown = BURST_COOLDOWN_INIT;
    obj->anim.rotX = 0x4000;
    state->texture0 = textureLoadAsset(342);
    state->texture1 = textureLoadAsset(3085);
    *(void **)&state->resource = Resource_Acquire(121, 1);
    ObjHits_SetTargetMask((int)obj, 1);
    ObjGroup_AddObject(obj, SBCLOUDRUNNER_OBJGROUP);
}

void SB_CloudRunner_update(GameObject *obj)
{
    SBCloudRunnerState *state = obj->extra;
    int prevSubState;

    if (state->done != 0 || obj->anim.mapEventSlot == 0xb)
    {
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        return;
    }
    setAButtonIcon(6);
    state->stickX = (int)(s8)padGetStickX(0);
    state->stickY = (int)(s8)padGetStickY(0);
    if (*(void **)&state->targetObj == NULL)
    {
        int count;
        int *objs = ObjGroup_GetObjects(3, &count);
        int i;
        for (i = 0; i < count; i++)
        {
            int o = objs[i];
            if (((GameObject *)o)->anim.seqId == CLOUDRUNNER_TARGET_TYPE)
            {
                state->targetObj = o;
                i = count;
            }
        }
    }
    obj->unkF4 = 0;
    prevSubState = state->rideSubState;
    state->burstCooldown = (s8)(state->burstCooldown - framesThisStep);
    if (state->burstCooldown < 0)
    {
        state->burstCooldown = 0;
    }
    switch (state->rideSubState)
    {
    case RIDE_SUBSTATE_STEER:
        ((void (*)(int, int))SB_CloudRunner_UpdateSteer)((int)obj, (int)state);
        ((void (*)(int, int))SB_CloudRunner_HandlePriorityHit)((int)obj, (int)state);
        break;
    case RIDE_SUBSTATE_TILT:
        WCPushBlock_UpdateRideTilt((int)obj, (int)state);
        break;
    case RIDE_SUBSTATE_DISMOUNT_A:
    case RIDE_SUBSTATE_DISMOUNT_B:
        obj->unkF4 = 1;
        break;
    }
    state->tiltZ = state->tiltZ + (f32)(int)obj->anim.rotZ * timeDelta / lbl_803E5CBC;
    state->tiltY = state->tiltY + (f32)(int)obj->anim.rotY * timeDelta / lbl_803E5CBC;
    state->tiltZ -= timeDelta * (state->tiltZ * lbl_803E5CC0);
    state->tiltY -= timeDelta * (state->tiltY * lbl_803E5CC0);
    obj->anim.rotY -= (s16)(lbl_803E5CB8 * state->tiltY);
    obj->anim.localPosY = lbl_803E5CB8 * state->tiltY + state->spawnPosY;
    obj->anim.localPosZ = lbl_803E5CB8 * state->tiltZ + state->spawnPosZ;
    state->rideFrames += framesThisStep;
    if (state->rideSubState != prevSubState)
    {
        state->rideFrames = 0;
    }
    ((void (*)(int, int))WCPushBlock_UpdateCloudAction)((int)obj, (int)state);
}
