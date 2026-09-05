/*
 * flameblast (DLL 0xF3) - Tricky's fire-breath projectiles.
 *
 * Seven staggered blasts fly along Tricky's rotated heading. Each projectile
 * periodically refreshes its launch origin, arms its hit volume after a short
 * delay, and retires when Tricky requests cleanup or is no longer present.
 */
#include "dlls/objects/243_flameblast.h"
#include "dlls/objects/196_Tricky.h"
#include "main/frame_timing.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"
#include "main/objhits.h"

#define FLAMEBLAST_HIT_VOLUME_SLOT 0x1A
#define FLAMEBLAST_HIT_TYPE        1

#define FLAMEBLAST_FORWARD_SPEED -1.5f
#define FLAMEBLAST_REACH_SCALE   0.4f

#define FLAMEBLAST_RENDER_BASE_SCALE 0.2f
#define FLAMEBLAST_RENDER_SCALE_RATE 0.033333335f
#define FLAMEBLAST_RENDER_EFFECT     2

#define FLAMEBLAST_CYCLE_DURATION      24.0f
#define FLAMEBLAST_HIT_ARM_TIME        6.0f
#define FLAMEBLAST_INITIAL_PHASE_SCALE 3.4285715f
#define FLAMEBLAST_INITIAL_HIT_DELAY   2

void flameblast_requestFree(GameObject* obj) {
    ((FlameblastState*)obj->extra)->freeRequested = 1;
}

int flameblast_seedVelocity(GameObject* obj, FlameblastState* state) {
    GameObject* tricky = getTrickyObject();
    f32* origin;
    f32 reachScale = FLAMEBLAST_REACH_SCALE;
    MatrixTransform rotationArg;

    if (state->freeRequested != 0 || tricky == NULL) {
        Obj_FreeObject(obj);
        return 0;
    }
    obj->anim.velocityX = 0.0f;
    obj->anim.velocityY = 0.0f;
    obj->anim.velocityZ = FLAMEBLAST_FORWARD_SPEED;
    rotationArg.x = 0.0f;
    rotationArg.y = 0.0f;
    rotationArg.z = 0.0f;
    rotationArg.scale = 1.0f;
    rotationArg.rotZ = tricky->anim.rotZ;
    rotationArg.rotY = tricky->anim.rotY;
    rotationArg.rotX = tricky->anim.rotX + trickyGetMouthYawOffset(tricky);
    vecRotateZXY(&rotationArg.rotX, &obj->anim.velocity.x);
    if ((tricky->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        origin = trickyGetMouthPosition(tricky);
    } else {
        origin = &tricky->anim.localPosX;
    }
    state->launchOriginX = -(reachScale * obj->anim.velocityX - origin[0]);
    state->launchOriginY = -(reachScale * obj->anim.velocityY - origin[1]);
    state->launchOriginZ = -(reachScale * obj->anim.velocityZ - origin[2]);
    if (state->hitVolumeDelayCycles != 0) {
        state->hitVolumeDelayCycles -= 1;
    } else {
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    }
    return 1;
}

int flameblast_getExtraSize(void) {
    return sizeof(FlameblastState);
}

void flameblast_render(GameObject* obj) {
    f32 offset[3];
    f32 scale =
        FLAMEBLAST_RENDER_SCALE_RATE * ((FlameblastState*)obj->extra)->cycleTimer + FLAMEBLAST_RENDER_BASE_SCALE;

    offset[0] = 0.0f;
    offset[1] = 1.0f;
    offset[2] = 0.0f;
    objfx_spawnPulseBurst(obj, scale, FLAMEBLAST_RENDER_EFFECT, 0, 0, offset);
}

void flameblast_update(GameObject* obj) {
    FlameblastState* state = obj->extra;

    state->cycleTimer += timeDelta;
    if (state->cycleTimer > FLAMEBLAST_CYCLE_DURATION) {
        state->cycleTimer -= FLAMEBLAST_CYCLE_DURATION;
        if (flameblast_seedVelocity(obj, state) == 0) {
            return;
        }
    } else {
        if (state->cycleTimer > FLAMEBLAST_HIT_ARM_TIME) {
            if (state->hitVolumeDelayCycles == 0) {
                ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FLAMEBLAST_HIT_VOLUME_SLOT, FLAMEBLAST_HIT_TYPE, 0);
            }
        }
    }
    obj->anim.localPosX = obj->anim.velocityX * state->cycleTimer + state->launchOriginX;
    obj->anim.localPosY = obj->anim.velocityY * state->cycleTimer + state->launchOriginY;
    obj->anim.localPosZ = obj->anim.velocityZ * state->cycleTimer + state->launchOriginZ;
}

void flameblast_init(GameObject* obj, FlameblastPlacement* placement) {
    FlameblastState* state = obj->extra;

    flameblast_seedVelocity(obj, state);
    state->cycleTimer = FLAMEBLAST_INITIAL_PHASE_SCALE * (f32)placement->streamIndex;
    state->hitVolumeDelayCycles = FLAMEBLAST_INITIAL_HIT_DELAY;
}

ObjectDescriptor gFlameblastObjDescriptor = {
    0,                                           /* reserved0 */
    0,                                           /* reserved1 */
    0,                                           /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,            /* slotCountAndFlags */
    0,                                           /* initialise */
    0,                                           /* release */
    0,                                           /* slot02 */
    (ObjectDescriptorCallback)flameblast_init,   /* init */
    (ObjectDescriptorCallback)flameblast_update, /* update */
    0,                                           /* hitDetect */
    (ObjectDescriptorCallback)flameblast_render, /* render */
    0,                                           /* free */
    0,                                           /* getObjectTypeId */
    flameblast_getExtraSize,                     /* getExtraSize */
};
