#include "dlls/objects/601_SB_Cloudrun.h"

/*
 * SB_Cloudrun (DLL 0x259) - the rideable Cloudrunner Krystal flies in the
 * ShipBattle prologue (SB = the retail "ShipBattle" map). She rides it to
 * chase General Scales' galleon and shoot out its guns/propellers, and at
 * the end of the level it catches her after Scales throws her overboard and
 * carries her on to Krazoa Palace. The player mounts the bird, holds A to
 * fire a forward burst (SB_CloudRunner_SpawnFromPath), steers with the analog
 * stick (padGetStickX/Y feed the yaw/pitch integrators in the steer update,
 * SB_CloudRunner_UpdateSteer), and the laser targets nearby objects
 * (SB_CloudRunner_HandlePriorityHit). The ride leans/banks via
 * SB_CloudRunner_UpdateRideTilt / SB_CloudRunner_UpdateCloudAction.
 *
 * SB_CloudRunner_UpdateSteer (the analog-steer update) integrates the stick input into
 * the bird's body rotation and advances the flap animation; the two-op
 * "(d - 0x10000) + 1" forms below are the shortest-arc angle wrap-clamps.
 */

#include "main/audio/sfx_play_api.h"
#include "main/obj_path.h"
#include "sys/objects.h"
#include "dolphin/mtx.h"
#include "main/dll/cloudaction_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/dll/partfx_interface.h"
#include "main/shader_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/player_api.h"
#include "main/track_dolphin_api.h"
#include "main/objtype.h"
#include "main/objprint_render_api.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/texture.h"
#include "main/dll/tricky_api.h"
#include "main/pad.h"
#include "dolphin/pad.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"
#include "main/objseq.h"

void SB_CloudRunner_onSeqFree(GameObject* obj) {
    SBCloudRunnerState* state = obj->extra;
    state->spawnPosX = obj->anim.localPosX;
    state->spawnPosY = obj->anim.localPosY;
    state->spawnPosZ = obj->anim.localPosZ;
    state->rotXAccum = (s16)(obj->anim.rotX - 0x4000);
    state->rotZ = obj->anim.rotZ;
}

#define SB_CLOUDRUNNER_SPAWN_OBJECT_ID  0x119
#define SB_CLOUDRUNNER_SPAWN_SETUP_SIZE 0x18
#define SB_CLOUDRUNNER_SPAWN_PATH_POINT 4
#define SB_CLOUDRUNNER_SPAWN_SFX        0x127
#define SB_CLOUDRUNNER_SPAWN_IDLE_TIMER 0x5a

#define SB_CLOUDRUNNER_INPUT_SCALE       70
#define SB_CLOUDRUNNER_PITCH_INPUT_SCALE 0x1770
#define SB_CLOUDRUNNER_ROLL_INPUT_SCALE  0x2ee0
#define SB_CLOUDRUNNER_ANGLE_DAMP_SHIFT  5
#define SB_CLOUDRUNNER_MAX_PITCH         0x1f40
#define SB_CLOUDRUNNER_MAX_ROLL          0x32c8
#define SB_CLOUDRUNNER_RIDE_MOVE_ID      0xf

void SB_CloudRunner_SpawnFromPath(GameObject* path, u8* unusedState) {
    SBCloudRunnerBurstSetup* setup;
    GameObject* block;
    f32 outVec[3];
    MatrixTransform rotation;

    if ((u8)Obj_CanSetupObject() == 0) {
        return;
    }

    Sfx_PlayFromObject(0, SB_CLOUDRUNNER_SPAWN_SFX);

    rotation.x = 0.0f;
    rotation.y = 0.0f;
    rotation.z = 0.0f;
    rotation.scale = 1.0f;
    rotation.rotX = path->anim.rotX;
    rotation.rotY = path->anim.rotY;
    rotation.rotZ = path->anim.rotZ;
    outVec[0] = 0.0f;
    outVec[1] = 38.0f;
    outVec[2] = -80.0f;
    vecRotateZXY(&rotation.rotX, outVec);

    setup =
        (SBCloudRunnerBurstSetup*)Obj_AllocObjectSetup(SB_CLOUDRUNNER_SPAWN_SETUP_SIZE, SB_CLOUDRUNNER_SPAWN_OBJECT_ID);
    setup->linkA = 0xff;
    setup->linkB = 0xff;
    setup->placementMode = 2;
    setup->group = 1;
    ObjPath_GetPointWorldPosition(path, SB_CLOUDRUNNER_SPAWN_PATH_POINT, &setup->x, &setup->y, &setup->z, 0);

    block = (GameObject*)objSetupObject((ObjPlacement*)setup, 5, -1, -1, NULL);
    if (block == NULL) {
        return;
    }

    rotation.x = 0.0f;
    rotation.y = 0.0f;
    rotation.z = 0.0f;
    rotation.scale = 1.0f;
    rotation.rotX = path->anim.rotX;
    rotation.rotY = path->anim.rotY;
    rotation.rotZ = 0;
    outVec[0] = 0.0f;
    outVec[1] = 0.0f;
    outVec[2] = -16.0f;
    vecRotateZXY(&rotation.rotX, outVec);

    block->anim.velocityX = outVec[0];
    block->anim.velocityY = outVec[1];
    block->anim.velocityZ = outVec[2];
    block->userData1 = SB_CLOUDRUNNER_SPAWN_IDLE_TIMER;
    block->userData2 = (int)path;
    block->anim.rotZ = 0;
    block->anim.rotY = 0;
    block->anim.rotX = 0;
}

void SB_CloudRunner_UpdateCloudAction(GameObject* obj, SBCloudRunnerRideState* state) {
    f32 angle;
    f32 rotorCos;
    f32 rotorSin;
    f32 targetLift;
    f32 baseLift;
    f32 moveX;
    f32 moveZ;
    f32 liftStep;
    f32 liftSmoothing;

    (void)obj;

    (*gCloudActionInterface)->func10Nop(state->rotorAngle);

    angle = (3.1415927f * state->rotorAngle) / 32768.0f;
    rotorCos = mathCosf(angle);
    angle = (3.1415927f * state->rotorAngle) / 32768.0f;
    rotorSin = mathSinf(angle);

    if (state->targetObj != NULL) {
        targetLift = state->rotZAccum / 1000.0f;
    } else {
        targetLift = 0.0f;
    }
    liftStep = (targetLift - state->liftAmount) * timeDelta;
    liftSmoothing = 0.0625f;
    state->liftAmount += liftStep * liftSmoothing;

    baseLift = 12.0f;
    moveX = baseLift * rotorSin;
    moveZ = baseLift * -rotorCos;
    moveX += rotorCos * -state->liftAmount;
    moveZ += rotorSin * -state->liftAmount;

    state->bankAmount = state->liftAmount;
    state->liftBase = baseLift;

    moveZ = moveZ * timeDelta;
    moveX = moveX * timeDelta;
    moveZ = moveZ / 3.0f;
    moveX = moveX / 3.0f;
    (*gCloudActionInterface)->func12Nop(moveZ, moveX);
}

void SB_CloudRunner_UpdateRideTilt(GameObject* obj, SBCloudRunnerRideState* state) {
    int targetPitch;
    int targetRoll;
    int pitchDelta;
    int rollDelta;
    int pitch;
    int roll;

    targetPitch = (-state->stickY * SB_CLOUDRUNNER_PITCH_INPUT_SCALE) / SB_CLOUDRUNNER_INPUT_SCALE;
    targetRoll = (-state->stickX * SB_CLOUDRUNNER_ROLL_INPUT_SCALE) / SB_CLOUDRUNNER_INPUT_SCALE;

    {
        f32 t = (f32)(state->stickX << 3) / 3.0f;
        state->cloudYawDrift = (s16)(-(t * timeDelta - state->cloudYawDrift));
    }
    state->cloudYawDrift =
        (s16)(state->cloudYawDrift - ((state->cloudYawDrift * framesThisStep) >> SB_CLOUDRUNNER_ANGLE_DAMP_SHIFT));

    pitchDelta = targetPitch - (u16)obj->anim.rotY;
    if (pitchDelta > 0x8000) {
        pitchDelta = (pitchDelta - 0x10000) + 1;
    }
    if (pitchDelta < -0x8000) {
        pitchDelta = (pitchDelta + 0x10000) - 1;
    }

    obj->anim.rotY = (s16)(0.05f * ((f32)pitchDelta * timeDelta) + (f32) * (s16*)(int)&obj->anim.rotY);

    rollDelta = targetRoll - (u16)state->rotZAccum;
    if (rollDelta > 0x8000) {
        rollDelta = (rollDelta - 0x10000) + 1;
    }
    if (rollDelta < -0x8000) {
        rollDelta = (rollDelta + 0x10000) - 1;
    }

    state->rotZAccum = (s16)(0.05f * ((f32)rollDelta * timeDelta) + (f32) * (s16*)(int)&state->rotZAccum);

    pitch = obj->anim.rotY;
    if (pitch < -SB_CLOUDRUNNER_MAX_PITCH) {
        pitch = -SB_CLOUDRUNNER_MAX_PITCH;
    } else if (pitch > SB_CLOUDRUNNER_MAX_PITCH) {
        pitch = SB_CLOUDRUNNER_MAX_PITCH;
    }
    obj->anim.rotY = pitch;

    roll = state->rotZAccum;
    if (roll < -SB_CLOUDRUNNER_MAX_ROLL) {
        roll = -SB_CLOUDRUNNER_MAX_ROLL;
    } else if (roll > SB_CLOUDRUNNER_MAX_ROLL) {
        roll = SB_CLOUDRUNNER_MAX_ROLL;
    }
    state->rotZAccum = roll;

    obj->anim.rotX = (s16)(state->cloudYawDrift + 0x4000);
    obj->anim.rotZ = state->rotZAccum;

    if (obj->anim.currentMove != SB_CLOUDRUNNER_RIDE_MOVE_ID) {
        ObjAnim_SetCurrentMove(obj, SB_CLOUDRUNNER_RIDE_MOVE_ID, 0.0f, 0);
    }

    if (ObjAnim_AdvanceCurrentMove(obj, 0.015f, timeDelta, NULL) != 0) {
        state->rideState = 0;
    }

    obj->userData1 = 1;
}

#define SBCLOUDRUNNER_OBJGROUP 0xa

/* object type ids (anim.romDefNo at obj+0x46) */
#define SBCLOUDRUNNER_OBJ_TYPE  0x43 /* SB_CloudRunner_getObjectTypeId */
#define CLOUDRUNNER_TARGET_TYPE 0x8E /* laser-lockable target */
#define HIT_TYPE_INVULNERABLE   281  /* hit objects of this type ignore the laser */
#define HIT_TYPE_BURST          154  /* hit type that triggers the partfx burst */

/* rideSubState (state->rideSubState, obj's switch dispatch) */
enum {
    RIDE_SUBSTATE_STEER = 0,
    RIDE_SUBSTATE_TILT = 1,
    RIDE_SUBSTATE_DISMOUNT_A = 2,
    RIDE_SUBSTATE_DISMOUNT_B = 3
};

#define A_BURST_COOLDOWN_FRAMES 40  /* frames between A-bursts */
#define A_BURST_READY_THRESHOLD 20  /* cooldown below which a press queues a burst */
#define BURST_COOLDOWN_INIT     100 /* burstCooldown set at init */

/* anim move ids passed to ObjAnim_SetCurrentMove */
#define CLOUDRUNNER_MOVE_FLAP  5
#define CLOUDRUNNER_MOVE_GLIDE 256

/* effect ids spawned through gPartfxInterface on a laser hit */
#define PARTFX_HIT_FLASH        168
#define PARTFX_HIT_DEBRIS       169
#define PARTFX_HIT_DEBRIS_COUNT 10
#define PARTFX_SPAWN_FLAGS      0x200001

#define GAMEBIT_CLOUDRUNNER_HIT_SFX 3870 /* gates the extra hit SFX */
#define SFX_CLOUDRUNNER_HIT         1169
#define SFX_CLOUDRUNNER_FLAP        294

#define COLORFADE_RUMBLE_PRESET 4000 /* anim.rotY written on a fade hit */

/* Analog-stick steering update for the cloudrunner ride. Integrates stick X/Y into the
 * bird's yaw/pitch/roll, clamps to the steer limits, advances the
 * flap/glide animation, and fires the forward burst on a fresh A press. */

void SB_CloudRunner_UpdateSteer(GameObject* obj, SBCloudRunnerState* state) {
    WCAnimEvents events;
    int doSpawn;
    int yawTarget;
    int pitchTarget;
    int angleDelta;
    int clampedRot;
    f32 spd;

    yawTarget = (-state->stickY * 6000) / 70;
    pitchTarget = (-state->stickX * 12000) / 70;

    {
        f32 t = (f32)(state->stickX << 3) / 3.0f;
        state->rotXAccum = -(t * timeDelta - (f32)state->rotXAccum);
    }
    state->rotXAccum -= (state->rotXAccum * framesThisStep) >> 5;

    angleDelta = yawTarget - (u16)obj->anim.rotY;
    if (angleDelta > 0x8000) {
        angleDelta = (angleDelta - 0x10000) + 1;
    }
    if (angleDelta < -0x8000) {
        angleDelta = (angleDelta + 0x10000) - 1;
    }
    obj->anim.rotY = 0.05f * ((f32)angleDelta * timeDelta) + (f32) * ((s16*)obj + 1);

    angleDelta = pitchTarget - (u16)state->rotZ;
    if (angleDelta > 0x8000) {
        angleDelta = (angleDelta - 0x10000) + 1;
    }
    if (angleDelta < -0x8000) {
        angleDelta = (angleDelta + 0x10000) - 1;
    }
    state->rotZ = 0.05f * ((f32)angleDelta * timeDelta) + (f32) * (s16*)((u8*)state + 0x2e);

    clampedRot = obj->anim.rotY;
    clampedRot = (clampedRot < -8000) ? -8000 : ((clampedRot > 8000) ? 8000 : clampedRot);
    obj->anim.rotY = clampedRot;

    clampedRot = state->rotZ;
    clampedRot = (clampedRot < -13000) ? -13000 : ((clampedRot > 13000) ? 13000 : clampedRot);
    state->rotZ = clampedRot;

    obj->anim.rotX = state->rotXAccum + 0x4000;
    obj->anim.rotZ = state->rotZ;

    events.sfxFlag = 0;
    spd = 3.0517578e-6f * (f32)obj->anim.rotY + 0.015f;
    if (spd > 0.013f) {
        if (obj->anim.currentMove != CLOUDRUNNER_MOVE_FLAP) {
            ObjAnim_SetCurrentMove(obj, CLOUDRUNNER_MOVE_FLAP, 0.0f, 0);
        }
    } else {
        spd = 0.015f;
        if (obj->anim.currentMove != CLOUDRUNNER_MOVE_GLIDE) {
            ObjAnim_SetCurrentMove(obj, CLOUDRUNNER_MOVE_GLIDE, 0.0f, 0);
        }
    }
    ObjAnim_AdvanceCurrentMove(obj, spd, timeDelta, (ObjAnimEventList*)&events);

    obj->anim.localPosX = state->spawnPosX;
    obj->anim.localPosY = state->spawnPosY;
    obj->anim.localPosZ = state->spawnPosZ;

    if (events.sfxFlag) {
        Sfx_PlayFromObject(0, SFX_CLOUDRUNNER_FLAP);
    }

    doSpawn = 0;
    if (state->aButtonHeld) {
        if ((getButtonsHeld(0) & PAD_BUTTON_A) == 0) {
            state->aButtonHeld = 0;
        } else if (state->burstCooldown == 0) {
            doSpawn = 1;
            state->burstCooldown = A_BURST_COOLDOWN_FRAMES;
        }
    } else {
        if ((getButtonsHeld(0) & PAD_BUTTON_A) != 0) {
            state->aButtonHeld = 1;
            if (state->burstCooldown < A_BURST_READY_THRESHOLD) {
                doSpawn = 1;
                state->burstCooldown = A_BURST_COOLDOWN_FRAMES;
            }
        }
    }
    if (doSpawn) {
        SB_CloudRunner_SpawnFromPath(obj, (u8*)state);
    }
}

int SB_CloudRunner_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    SBCloudRunnerState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    int i;
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)SB_CloudRunner_onSeqFree;
    state->spawnPosX = obj->anim.localPosX;
    state->spawnPosY = obj->anim.localPosY;
    state->spawnPosZ = obj->anim.localPosZ;
    state->rotXAccum = (s16)(obj->anim.rotX - 0x4000);
    state->rotZ = obj->anim.rotZ;
    for (i = 0; i < animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == 1) {
            Obj_SetParent(player, state->targetObj, 0);
            playerSetStateValue(player, 5, 0.0f);
            state->done = 1;
        }
    }
    animUpdate->movementState = 0;
    obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    return 0;
}

/* SB_CloudRunner_HandlePriorityHit: when the laser hits an object whose
 * type isn't HIT_TYPE_INVULNERABLE and isn't currently in fade state,
 * fade it red, rumble, play SFX, gate further damage on a GameBit, then
 * if the hit type is HIT_TYPE_BURST emit 3 hit-flash partfx followed by a
 * 10-shot debris burst. */

void SB_CloudRunner_HandlePriorityHit(GameObject* obj, SBCloudRunnerState* state) {
    GameObject* hitObj;
    f32 pos[3];
    struct WCPartfxArgs args;
    int i;

    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, 0, &pos[0], &pos[1], &pos[2]) != 0) {
        if (objGetFlagsE5_2((u8*)obj) == 0) {
            if (hitObj->anim.romDefNo != HIT_TYPE_INVULNERABLE) {
                Obj_SetModelColorFadeRecursive(obj, 175, 200, 0, 0, 1);
                doRumble(10.0f);
                Sfx_PlayFromObject(0, SFXTRIG_dn_gscsc1_c);
                if (mainGetBit(GAMEBIT_CLOUDRUNNER_HIT_SFX) != 0) {
                    Sfx_PlayFromObject(obj, SFX_CLOUDRUNNER_HIT);
                }
                (obj)->anim.rotY = COLORFADE_RUMBLE_PRESET;
                state->rideSubState = RIDE_SUBSTATE_TILT;
                args.scale = 1.0f;
                args.v[0] = 0;
                args.v[1] = 0;
                args.v[2] = 0;
                if (hitObj->anim.romDefNo == HIT_TYPE_BURST) {
                    (*gPartfxInterface)->spawnObject((void*)obj, PARTFX_HIT_FLASH, &args, PARTFX_SPAWN_FLAGS, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, PARTFX_HIT_FLASH, &args, PARTFX_SPAWN_FLAGS, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, PARTFX_HIT_FLASH, &args, PARTFX_SPAWN_FLAGS, -1, NULL);
                    for (i = 0; i < PARTFX_HIT_DEBRIS_COUNT; i++) {
                        (*gPartfxInterface)
                            ->spawnObject((void*)obj, PARTFX_HIT_DEBRIS, &args, PARTFX_SPAWN_FLAGS, -1, NULL);
                    }
                }
            }
        }
    }
}

/* Forward to the laser-locked target's DLL vtable (slot 0x24). */
int SB_CloudRunner_getTargetMode(GameObject* obj) {
    GameObject* target = ((SBCloudRunnerState*)obj->extra)->targetObj;
    void* vt = *target->anim.dll;
    int (*fn)(GameObject*) = *(int (**)(GameObject*))((char*)vt + 0x24);
    return fn(target);
}

void SB_CloudRunner_getSpawnPos(GameObject* obj, f32* x, f32* y, f32* z) {
    SBCloudRunnerState* state = obj->extra;
    *x = state->spawnPosX;
    *y = state->spawnPosY;
    *z = state->spawnPosZ;
}

void SB_CloudRunner_func23(void) {
}

void SB_CloudRunner_handleRiderScale(void* obj) {
    objSetCurrentMatrix((MtxPtr)ObjPath_GetPointModelMtx(obj, 3));
}

void SB_CloudRunner_func21(void) {
}

int SB_CloudRunner_getRacePosition(void) {
    return 0x0;
}

f32 SB_CloudRunner_func19(int unused, f32* p) {
    f32 v = 0.0f;
    *p = v;
    return v;
}

void SB_CloudRunner_getPlayerAnim(int obj, f32* out, int* outInt) {
    *out = 0.0f;
    *outInt = 0;
}

void SB_CloudRunner_setMountState(void) {
}

int SB_CloudRunner_getMountState(void) {
    return 0x2;
}

void SB_CloudRunner_getCameraPosition(GameObject* src, f32* out_x, f32* out_y, f32* out_z) {
    *out_x = src->anim.localPosX;
    *out_y = src->anim.localPosY;
    *out_z = src->anim.localPosZ;
}

int SB_CloudRunner_getDismountSide(void) {
    return 0x0;
}

int SB_CloudRunner_canDismount(void) {
    return 0x0;
}

void SB_CloudRunner_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z) {
    SBCloudRunnerState* state = obj->extra;
    *x = state->riderPosition[0];
    *y = state->riderPosition[1];
    *z = state->riderPosition[2];
}

int SB_CloudRunner_getMountSide(void) {
    return 0x0;
}

int SB_CloudRunner_canMount(void) {
    return 0x0;
}

int SB_CloudRunner_getExtraSize(void) {
    return sizeof(SBCloudRunnerState);
}

int SB_CloudRunner_getObjectTypeId(void) {
    return SBCLOUDRUNNER_OBJ_TYPE;
}

void SB_CloudRunner_free(GameObject* obj) {
    SBCloudRunnerState* state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (state->texture0 != NULL) {
        textureFree((Texture*)(state->texture0));
        state->texture0 = NULL;
    }
    if (state->texture1 != NULL) {
        textureFree((Texture*)(state->texture1));
        state->texture1 = NULL;
    }
    Resource_Release(state->resource);
    state->resource = NULL;
    objFreeObjectType(obj, SBCLOUDRUNNER_OBJGROUP);
}

void SB_CloudRunner_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    SBCloudRunnerState* state = obj->extra;
    f32 mtx[16];
    if (visible == -1) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 3, &state->riderPosition[0], &state->riderPosition[1],
                                      &state->riderPosition[2], 0);
        if (obj->anim.parent != NULL) {
            state->riderPosition[0] = state->riderPosition[0] - playerMapOffsetX;
            state->riderPosition[2] = state->riderPosition[2] - playerMapOffsetZ;
            Obj_BuildInverseWorldTransformMatrix(obj->anim.parent, mtx);
            PSMTXMultVec((MtxPtr)mtx, (Vec*)state->riderPosition, (Vec*)state->riderPosition);
        }
    } else if (visible != 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 3, &state->riderPosition[0], &state->riderPosition[1],
                                      &state->riderPosition[2], 0);
        if (obj->anim.parent != NULL) {
            state->riderPosition[0] = state->riderPosition[0] - playerMapOffsetX;
            state->riderPosition[2] = state->riderPosition[2] - playerMapOffsetZ;
            Obj_BuildInverseWorldTransformMatrix(obj->anim.parent, mtx);
            PSMTXMultVec((MtxPtr)mtx, (Vec*)state->riderPosition, (Vec*)state->riderPosition);
        }
    } else {
        state->riderPosition[0] = obj->anim.localPosX;
        state->riderPosition[1] = obj->anim.localPosY;
        state->riderPosition[2] = obj->anim.localPosZ;
    }
}

void SB_CloudRunner_hitDetect(void) {
}

void SB_CloudRunner_update(GameObject* obj) {
    SBCloudRunnerState* state = obj->extra;
    int prevSubState;
    f32 tiltDamping;

    if (state->done != 0 || obj->anim.mapEventSlot == 0xb) {
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        return;
    }
    setAButtonIcon(6);
    state->stickX = padGetStickX(0);
    state->stickY = padGetStickY(0);
    if (state->targetObj == NULL) {
        int count;
        GameObject** objs = objGetAllOfType(3, &count);
        int i;
        for (i = 0; i < count; i++) {
            GameObject* o = objs[i];
            if (o->anim.romDefNo == CLOUDRUNNER_TARGET_TYPE) {
                state->targetObj = o;
                i = count;
            }
        }
    }
    obj->userData1 = 0;
    prevSubState = state->rideSubState;
    state->burstCooldown = (s8)(state->burstCooldown - framesThisStep);
    if (state->burstCooldown < 0) {
        state->burstCooldown = 0;
    }
    switch (state->rideSubState) {
    case RIDE_SUBSTATE_STEER:
        SB_CloudRunner_UpdateSteer(obj, state);
        SB_CloudRunner_HandlePriorityHit(obj, state);
        break;
    case RIDE_SUBSTATE_TILT:
        SB_CloudRunner_UpdateRideTilt(obj, (SBCloudRunnerRideState*)state);
        break;
    case RIDE_SUBSTATE_DISMOUNT_A:
    case RIDE_SUBSTATE_DISMOUNT_B:
        obj->userData1 = 1;
        break;
    }
    state->tiltZ = state->tiltZ + (f32)(int)obj->anim.rotZ * timeDelta / 6370.0f;
    state->tiltY = state->tiltY + (f32)(int)obj->anim.rotY * timeDelta / 6370.0f;
    tiltDamping = 0.1f;
    state->tiltZ -= timeDelta * (state->tiltZ * tiltDamping);
    state->tiltY -= timeDelta * (state->tiltY * tiltDamping);
    obj->anim.rotY -= (s16)(10.0f * state->tiltY);
    obj->anim.localPosY = 10.0f * state->tiltY + state->spawnPosY;
    obj->anim.localPosZ = 10.0f * state->tiltZ + state->spawnPosZ;
    state->rideFrames += framesThisStep;
    if (state->rideSubState != prevSubState) {
        state->rideFrames = 0;
    }
    SB_CloudRunner_UpdateCloudAction(obj, (SBCloudRunnerRideState*)state);
}

void SB_CloudRunner_init(GameObject* obj) {
    SBCloudRunnerState* state = obj->extra;
    obj->animEventCallback = SB_CloudRunner_SeqFn;
    state->spawnPosX = obj->anim.localPosX;
    state->spawnPosY = obj->anim.localPosY;
    state->spawnPosZ = obj->anim.localPosZ;
    state->burstCooldown = BURST_COOLDOWN_INIT;
    obj->anim.rotX = 0x4000;
    state->texture0 = textureLoadAsset(342);
    state->texture1 = textureLoadAsset(3085);
    state->resource = Resource_Acquire(121, 1);
    ObjHits_SetTargetMask(obj, 1);
    objAddObjectType(obj, SBCLOUDRUNNER_OBJGROUP);
}

void SB_CloudRunner_release(void) {
}

void SB_CloudRunner_initialise(void) {
}

ObjectDescriptor24 gSB_CloudRunnerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SB_CloudRunner_initialise,
    (ObjectDescriptorCallback)SB_CloudRunner_release,
    0,
    (ObjectDescriptorCallback)SB_CloudRunner_init,
    (ObjectDescriptorCallback)SB_CloudRunner_update,
    (ObjectDescriptorCallback)SB_CloudRunner_hitDetect,
    (ObjectDescriptorCallback)SB_CloudRunner_render,
    (ObjectDescriptorCallback)SB_CloudRunner_free,
    (ObjectDescriptorCallback)SB_CloudRunner_getObjectTypeId,
    SB_CloudRunner_getExtraSize,
    (ObjectDescriptorCallback)SB_CloudRunner_canMount,
    (ObjectDescriptorCallback)SB_CloudRunner_getMountSide,
    (ObjectDescriptorCallback)SB_CloudRunner_getRiderPosition,
    (ObjectDescriptorCallback)SB_CloudRunner_canDismount,
    (ObjectDescriptorCallback)SB_CloudRunner_getDismountSide,
    (ObjectDescriptorCallback)SB_CloudRunner_getCameraPosition,
    (ObjectDescriptorCallback)SB_CloudRunner_getMountState,
    (ObjectDescriptorCallback)SB_CloudRunner_setMountState,
    (ObjectDescriptorCallback)SB_CloudRunner_getPlayerAnim,
    (ObjectDescriptorCallback)SB_CloudRunner_func19,
    (ObjectDescriptorCallback)SB_CloudRunner_getRacePosition,
    (ObjectDescriptorCallback)SB_CloudRunner_func21,
    (ObjectDescriptorCallback)SB_CloudRunner_handleRiderScale,
    (ObjectDescriptorCallback)SB_CloudRunner_func23,
};
