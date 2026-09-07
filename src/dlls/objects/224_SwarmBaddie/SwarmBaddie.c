/*
 * SwarmBaddie object (DLL slot 224).
 *
 * Follows a ROM curve, chases nearby players, and drives its looping sound
 * and particle effects from its hit-volume envelope.
 */
#include "dlls/objects/224_SwarmBaddie.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/curve.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "string.h"
#include "sys/objects.h"

#define SWARMBADDIE_HIT_VOLUME_SLOT 10

#define SWARMBADDIE_OBJECT_GROUP 3
#define SWARMBADDIE_PARTFX       0x336

#define SWARMBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define SWARMBADDIE_FLAG_CHASE_PLAYER    0x02
#define SWARMBADDIE_FLAG_CHASE_LOCKOUT   0x04
#define SWARMBADDIE_FLAG_CHASE_MASK      0x06

#define SWARMBADDIE_DEG_TO_ANGLE    182.0f
#define SWARMBADDIE_PI              3.1415927f
#define SWARMBADDIE_S16_ANGLE_SCALE 32768.0f

int gSwarmBaddieCurveInitData[2] = {2, 3};
int gSwarmBaddieLastCurvePoint;

ObjectDescriptor gSwarmBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SwarmBaddie_initialise,
    (ObjectDescriptorCallback)SwarmBaddie_release,
    0,
    (ObjectDescriptorCallback)SwarmBaddie_init,
    (ObjectDescriptorCallback)SwarmBaddie_update,
    (ObjectDescriptorCallback)SwarmBaddie_hitDetect,
    (ObjectDescriptorCallback)SwarmBaddie_render,
    (ObjectDescriptorCallback)SwarmBaddie_free,
    (ObjectDescriptorCallback)SwarmBaddie_getObjectTypeId,
    SwarmBaddie_getExtraSize,
};

void SwarmBaddie_updateMovement(GameObject* obj, SwarmBaddieState* state) {
    RomCurveWalker* curve;
    int pathEnded;
    f32 step;

    curve = state->curve;
    pathEnded = Curve_AdvanceAlongPath(&curve->curve, state->curveStep);
    if (((pathEnded != 0) || (curve->atSegmentEnd != gSwarmBaddieLastCurvePoint)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, 400.0f, gSwarmBaddieCurveInitData, -1) !=
         0)) {
        state->flags &= ~SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    gSwarmBaddieLastCurvePoint = curve->atSegmentEnd;
    if ((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0) {
        step = 0.003f;
        obj->anim.velocityX = step * (state->player->anim.localPosX - obj->anim.localPosX) + obj->anim.velocityX;
        obj->anim.velocityY =
            step * ((30.0f + state->player->anim.localPosY) - obj->anim.localPosY) + obj->anim.velocityY;
        obj->anim.velocityZ = step * (state->player->anim.localPosZ - obj->anim.localPosZ) + obj->anim.velocityZ;
    } else {
        step = 0.003f;
        obj->anim.velocityX = step * (curve->posX - obj->anim.localPosX) + obj->anim.velocityX;
        obj->anim.velocityY = step * (curve->posY - obj->anim.localPosY) + obj->anim.velocityY;
        obj->anim.velocityZ = step * (curve->posZ - obj->anim.localPosZ) + obj->anim.velocityZ;
    }

    obj->anim.velocityX *= (step = 0.9f);
    obj->anim.velocityY *= step;
    obj->anim.velocityZ *= step;

    if (obj->anim.velocityX > 0.8f) {
        obj->anim.velocityX = 0.8f;
    }
    if (obj->anim.velocityY > 0.8f) {
        obj->anim.velocityY = 0.8f;
    }
    if (obj->anim.velocityZ > 0.8f) {
        obj->anim.velocityZ = 0.8f;
    }
    if (obj->anim.velocityX < -0.8f) {
        obj->anim.velocityX = -0.8f;
    }
    if (obj->anim.velocityY < -0.8f) {
        obj->anim.velocityY = -0.8f;
    }
    if (obj->anim.velocityZ < -0.8f) {
        obj->anim.velocityZ = -0.8f;
    }

    (void)objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                  obj->anim.velocityZ * timeDelta);

    state->yawWavePhase += (s16)(32.0f * timeDelta);
    state->rollWavePhase += (s16)(23.0f * timeDelta);

    obj->anim.rotX += (s16)(4.0f * (SWARMBADDIE_DEG_TO_ANGLE *
                                    mathSinf((SWARMBADDIE_PI * state->yawWavePhase) / SWARMBADDIE_S16_ANGLE_SCALE)));

    obj->anim.rotZ += (s16)(4.0f * (SWARMBADDIE_DEG_TO_ANGLE *
                                    mathSinf((SWARMBADDIE_PI * state->rollWavePhase) / SWARMBADDIE_S16_ANGLE_SCALE)));
}

int SwarmBaddie_getExtraSize(void) {
    return sizeof(SwarmBaddieState);
}

int SwarmBaddie_getObjectTypeId(void) {
    return 0x9;
}

void SwarmBaddie_free(GameObject* obj) {
    SwarmBaddieState* state = obj->extra;
    objFreeObjectType(obj, SWARMBADDIE_OBJECT_GROUP);
    if (state->curve != NULL) {
        mm_free(state->curve);
        state->curve = NULL;
    }
}

void SwarmBaddie_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    (void)obj;
    (void)fwdArg2;
    (void)fwdArg3;
    (void)fwdArg4;
    (void)fwdArg5;

    if (visible == 0)
        return;
}

void SwarmBaddie_hitDetect(GameObject* obj) {
    (void)obj;
}

void SwarmBaddie_update(GameObject* obj) {
    SwarmBaddieState* state;
    struct {
        f32 x, y, z;
    } delta;
    f32* deltaValues = &delta.x;
    f32 volume;
    RomCurveWalker* curve;
    GameObject* hitObject;
    f32 hitPosX;
    f32 hitPosY;
    f32 hitPosZ;
    int hitSphereIndex;
    u32 hitVolume;

    state = obj->extra;
    curve = state->curve;
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &hitPosX, &hitPosY,
                                           &hitPosZ) != 0) {
        state->hitVolumeEnvelope = 2.0f;
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, SWARMBADDIE_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject(obj);
    if (state->hitVolumeEnvelope > 1.0f) {
        state->hitVolumeEnvelope -= 0.005f;
    }
    volume = state->hitVolumeEnvelope;
    Sfx_SetObjectChannelVolume(obj, 0x40, (63.0f * volume),
                               0.05f * mathSinf((SWARMBADDIE_PI * (f32)(state->yawWavePhase + state->rollWavePhase)) /
                                                SWARMBADDIE_S16_ANGLE_SCALE) +
                                   volume);
    (*gPartfxInterface)->spawnObject((void*)obj, SWARMBADDIE_PARTFX, NULL, 2, -1, &state->hitVolumeEnvelope);
    state->player = Obj_GetPlayerObject();
    if (state->player != NULL) {
        delta.x = state->player->anim.worldPosX - obj->anim.worldPosX;
        delta.y = state->player->anim.worldPosY - obj->anim.worldPosY;
        delta.z = state->player->anim.worldPosZ - obj->anim.worldPosZ;
        state->playerDistance = sqrtf(delta.z * delta.z + (delta.x * delta.x + delta.y * delta.y));
    }
    if (curve != NULL) {
        delta.x = curve->posX - obj->anim.worldPosX;
        delta.y = curve->posY - obj->anim.worldPosY;
        delta.z = curve->posZ - obj->anim.worldPosZ;
        state->pathDistance = sqrtf(delta.z * delta.z + (delta.x * delta.x + delta.y * delta.y));
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0) && (state->pathDistance > 250.0f)) {
        state->flags = (u8)(state->flags & ~SWARMBADDIE_FLAG_CHASE_PLAYER);
        state->flags = (u8)(state->flags | SWARMBADDIE_FLAG_CHASE_LOCKOUT);
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_LOCKOUT) != 0) && (state->pathDistance < 60.0f)) {
        state->flags = (u8)(state->flags & ~SWARMBADDIE_FLAG_CHASE_LOCKOUT);
    }
    if (((state->flags & SWARMBADDIE_FLAG_CHASE_MASK) == 0) && (state->player != NULL) &&
        (state->playerDistance < state->chaseRadius)) {
        state->flags = (u8)(state->flags | SWARMBADDIE_FLAG_CHASE_PLAYER);
    }
    SwarmBaddie_updateMovement(obj, state);
}

void SwarmBaddie_init(GameObject* obj, SwarmBaddiePlacement* placement, int skipAlloc) {
    SwarmBaddieState* state = obj->extra;
    state->curveStep = (f32)(s32)placement->curveStepParam / 50.0f;
    state->chaseRadius = 4.0f * (f32)(s32)placement->chaseRadiusScale;
    state->hitVolumeEnvelope = 1.0f;
    if (skipAlloc == 0) {
        state->curve = mmAlloc(sizeof(RomCurveWalker), 0x1A, 0);
        if (state->curve != NULL) {
            (void)memset(state->curve, 0, sizeof(RomCurveWalker));
        }
        if ((*gRomCurveInterface)
                ->initCurve((void*)state->curve, (void*)obj, state->chaseRadius, gSwarmBaddieCurveInitData, -1) == 0) {
            state->flags |= SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_en_grumb4_c);
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void SwarmBaddie_release(void) {
}

void SwarmBaddie_initialise(void) {
}
