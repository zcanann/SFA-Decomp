/*
 * WispBaddie object (DLL slot 225).
 *
 * Follows a ROM curve, chases nearby players, and owns the family tables
 * shared by the sequence-driven baddie objects.
 */
#include "dlls/objects/225_WispBaddie.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "string.h"
#include "sys/objects.h"
#include "main/curve.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/vecmath.h"

#define WISPBADDIE_HIT_VOLUME_SLOT 10

#define WISPBADDIE_OBJECT_GROUP 3

#define WISPBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define WISPBADDIE_FLAG_CHASE_PLAYER    0x02
#define WISPBADDIE_FLAG_CHASE_LOCKOUT   0x04
#define WISPBADDIE_FLAG_CHASE_MASK      0x06

#define WISPBADDIE_PI              3.1415927f
#define WISPBADDIE_S16_ANGLE_SCALE 32768.0f

int gWispBaddieCurveInitData[2] = {2, 3};
int gWispBaddieLastSegmentEnd;

void WispBaddie_updateMovement(GameObject* obj, WispBaddieState* state) {
    RomCurveWalker* curve;
    int pathEnded;
    f32 step;
    f32 wave;

    curve = state->curve;
    state->pathWavePhase += (s16)(512.0f * timeDelta);
    state->hoverWavePhase += (s16)(2048.0f * timeDelta);

    wave = 1.0f + mathSinf((WISPBADDIE_PI * (f32)state->pathWavePhase) / WISPBADDIE_S16_ANGLE_SCALE);
    pathEnded = Curve_AdvanceAlongPath(&curve->curve, state->hitRadius * wave);
    if (((pathEnded != 0) || (curve->atSegmentEnd != gWispBaddieLastSegmentEnd)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, 400.0f, gWispBaddieCurveInitData, -1) !=
         0)) {
        state->flags = (u8)(state->flags & ~WISPBADDIE_FLAG_PATH_NEEDS_LINK);
    }
    gWispBaddieLastSegmentEnd = curve->atSegmentEnd;

    if ((state->flags & WISPBADDIE_FLAG_CHASE_PLAYER) != 0) {
        obj->anim.velocityX = 0.006f * (state->player->anim.localPosX - obj->anim.localPosX) + obj->anim.velocityX;

        wave = mathSinf((WISPBADDIE_PI * (f32)state->hoverWavePhase) / WISPBADDIE_S16_ANGLE_SCALE);
        wave = ((30.0f + state->player->anim.localPosY) + 40.0f * wave) - obj->anim.localPosY;
        obj->anim.velocityY = 0.006f * wave + obj->anim.velocityY;
        obj->anim.velocityZ = 0.006f * (state->player->anim.localPosZ - obj->anim.localPosZ) + obj->anim.velocityZ;
    } else {
        obj->anim.velocityX = 0.006f * (curve->posX - obj->anim.localPosX) + obj->anim.velocityX;

        wave = mathSinf((WISPBADDIE_PI * (f32)state->hoverWavePhase) / WISPBADDIE_S16_ANGLE_SCALE);
        wave = (40.0f * wave + curve->posY) - obj->anim.localPosY;
        obj->anim.velocityY = 0.006f * wave + obj->anim.velocityY;
        obj->anim.velocityZ = 0.006f * (curve->posZ - obj->anim.localPosZ) + obj->anim.velocityZ;
    }

    obj->anim.velocityX *= (step = 0.9f);
    obj->anim.velocityY *= step;
    obj->anim.velocityZ *= step;

    if (obj->anim.velocityX > 2.1f) {
        obj->anim.velocityX = 2.1f;
    }
    if (obj->anim.velocityY > 2.1f) {
        obj->anim.velocityY = 2.1f;
    }
    if (obj->anim.velocityZ > 2.1f) {
        obj->anim.velocityZ = 2.1f;
    }
    if (obj->anim.velocityX < -2.1f) {
        obj->anim.velocityX = -2.1f;
    }
    if (obj->anim.velocityY < -2.1f) {
        obj->anim.velocityY = -2.1f;
    }
    if (obj->anim.velocityZ < -2.1f) {
        obj->anim.velocityZ = -2.1f;
    }

    (void)objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                  obj->anim.velocityZ * timeDelta);
}

int WispBaddie_getExtraSize(void) {
    return sizeof(WispBaddieState);
}

int WispBaddie_getObjectTypeId(void) {
    return 0x9;
}

void WispBaddie_free(GameObject* obj) {
    WispBaddieState* state = obj->extra;
    objFreeObjectType(obj, WISPBADDIE_OBJECT_GROUP);
    if (state->curve != NULL) {
        mm_free(state->curve);
        state->curve = NULL;
    }
}

void WispBaddie_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    (void)obj;
    (void)fwdArg2;
    (void)fwdArg3;
    (void)fwdArg4;
    (void)fwdArg5;

    if (visible == 0)
        return;
}

void WispBaddie_hitDetect(GameObject* obj) {
    (void)obj;
}

void WispBaddie_update(GameObject* obj) {
    WispBaddieState* state;
    RomCurveWalker* curve;
    int hitPriority;
    GameObject* hitObject;
    f32 hitPosX;
    f32 hitPosY;
    f32 hitPosZ;
    int hitSphereIndex;
    u32 hitVolume;
    f32 delta[3];
    int particleMode;
    u8 flags;
    void* deltaAlias = (void*)delta;

    state = obj->extra;
    curve = state->curve;
    hitPriority = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &hitPosX, &hitPosY,
                                                     &hitPosZ);
    if (hitPriority != 0) {
        state->hitRadius = 0.01f;
        flags = state->flags;
        if ((flags & WISPBADDIE_FLAG_CHASE_PLAYER) != 0) {
            state->flags = (u8)(flags & ~WISPBADDIE_FLAG_CHASE_PLAYER);
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_CHASE_LOCKOUT);
        }
        Sfx_PlayAtPositionFromObject(obj, hitPosX, hitPosY, hitPosZ, SFXTRIG_robolaser16);
    }

    particleMode = 4;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 1, -1, &particleMode);
    particleMode = 3;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleMode);

    if (state->hitRadius < state->maxHitRadius) {
        state->hitRadius += 0.005f;
        ObjHits_DisableObject(obj);
    } else {
        state->hitRadius = state->maxHitRadius;
        particleMode = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleMode);
        particleMode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleMode);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, WISPBADDIE_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
    }

    particleMode = 1;
    (*gPartfxInterface)->spawnObject((void*)obj, state->particleId, NULL, 2, -1, &particleMode);
    state->player = Obj_GetPlayerObject();
    if (state->player != NULL) {
        delta[0] = state->player->anim.worldPosX - obj->anim.worldPosX;
        delta[1] = state->player->anim.worldPosY - obj->anim.worldPosY;
        delta[2] = state->player->anim.worldPosZ - obj->anim.worldPosZ;
        state->playerDistance = sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1]));
    }
    if (curve != NULL) {
        delta[0] = curve->posX - obj->anim.worldPosX;
        delta[1] = curve->posY - obj->anim.worldPosY;
        delta[2] = curve->posZ - obj->anim.worldPosZ;
        state->curveDistance = sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1]));
    }

    flags = state->flags;
    if ((flags & WISPBADDIE_FLAG_CHASE_PLAYER) != 0) {
        if (state->curveDistance > 250.0f) {
            state->flags = (u8)(flags & ~WISPBADDIE_FLAG_CHASE_PLAYER);
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_CHASE_LOCKOUT);
        }
        state->cryTimer -= timeDelta;
        if (state->cryTimer < 0.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_fball2_c);
            state->cryTimer = randomGetRange(60, 120);
        }
        state->particleId = 0x338;
    }
    flags = state->flags;
    if ((flags & WISPBADDIE_FLAG_CHASE_LOCKOUT) != 0) {
        if (state->curveDistance < 60.0f) {
            state->flags = (u8)(flags & ~WISPBADDIE_FLAG_CHASE_LOCKOUT);
        }
        state->particleId = 0x337;
    }
    if ((state->flags & WISPBADDIE_FLAG_CHASE_MASK) == 0) {
        if ((state->hitRadius >= state->maxHitRadius) && (state->player != NULL) &&
            (state->playerDistance < state->triggerDistance)) {
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_CHASE_PLAYER);
        }
        state->particleId = 0x337;
    }
    WispBaddie_updateMovement(obj, state);
}

void WispBaddie_init(GameObject* obj, WispBaddiePlacement* placement, int skipAlloc) {
    WispBaddieState* state;
    f32 value;

    state = obj->extra;
    value = (f32)placement->maxHitRadiusParameter / 25.0f;
    state->maxHitRadius = value;
    state->hitRadius = value;
    state->triggerDistance = 4.0f * (f32)placement->triggerDistanceScale;
    state->particleId = 0x337;

    if (skipAlloc == 0) {
        state->curve = mmAlloc(sizeof(RomCurveWalker), 0x1A, 0);
        if (state->curve != NULL) {
            memset(state->curve, 0, sizeof(RomCurveWalker));
        }
        if ((*gRomCurveInterface)
                ->initCurve((void*)state->curve, (void*)obj, state->triggerDistance, gWispBaddieCurveInitData, -1) ==
            0) {
            state->flags = (u8)(state->flags | WISPBADDIE_FLAG_PATH_NEEDS_LINK);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_id_23b);
    }
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void WispBaddie_release(void) {
}

void WispBaddie_initialise(void) {
}

ObjectDescriptor gWispBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WispBaddie_initialise,
    (ObjectDescriptorCallback)WispBaddie_release,
    0,
    (ObjectDescriptorCallback)WispBaddie_init,
    (ObjectDescriptorCallback)WispBaddie_update,
    (ObjectDescriptorCallback)WispBaddie_hitDetect,
    (ObjectDescriptorCallback)WispBaddie_render,
    (ObjectDescriptorCallback)WispBaddie_free,
    (ObjectDescriptorCallback)WispBaddie_getObjectTypeId,
    WispBaddie_getExtraSize,
};
