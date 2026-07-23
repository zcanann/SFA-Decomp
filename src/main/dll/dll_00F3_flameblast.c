/*
 * flameblast (DLL 0xF3) - Tricky's fire-breath projectile, a member of
 * the pushable/transporter object family.
 *
 * Spawned by Tricky (getTrickyObject), the blast flies along the rotated
 * fire direction: flameblast_seedVelocity seeds the velocity from Tricky's heading and
 * the path/queued-particle origin, and flameblast_update integrates the
 * launch position over a per-frame timer while arming the damage hit
 * volume once the timer passes a threshold. The object frees itself when
 * Tricky is gone or its free flag (state.freeRequested) is set.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/objfx.h"
#include "main/object.h"
#include "main/objhits.h"
#include "main/dll/vecrotatezxy.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/flameblast_api.h"
#include "main/frame_timing.h"

typedef struct FlameblastState
{
    f32 timer;         /* 0x00: per-frame flight timer */
    f32 launchPosX;    /* 0x04: launch origin used by the localPos integration */
    f32 launchPosY;    /* 0x08 */
    f32 launchPosZ;    /* 0x0C */
    u8 freeRequested;  /* 0x10: set externally to free the object next tick */
    u8 hitVolumeDelay; /* 0x11: frames to delay before clearing hit volumes */
    u8 pad12[0x14 - 0x12];
} FlameblastState;

STATIC_ASSERT(offsetof(FlameblastState, freeRequested) == 0x10);
STATIC_ASSERT(offsetof(FlameblastState, hitVolumeDelay) == 0x11);
STATIC_ASSERT(sizeof(FlameblastState) == 0x14);

typedef struct FlameblastPlacement
{
    ObjPlacement base;
    u8 pad18[0x1A - 0x18];
    s16 initialTimer; /* 0x1a: seeds the flight timer (scaled at init) */
} FlameblastPlacement;

STATIC_ASSERT(sizeof(FlameblastPlacement) == 0x1C);
STATIC_ASSERT(offsetof(FlameblastPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(FlameblastPlacement, initialTimer) == 0x1A);

#define FLAMEBLAST_HIT_VOLUME_SLOT 0x1a

int flameblast_seedVelocity(GameObject* obj, FlameblastState* state);

void objSetAnimSpeedTo1(GameObject* obj)
{
    ((FlameblastState*)obj->extra)->freeRequested = 1;
}

int flameblast_seedVelocity(GameObject* obj, FlameblastState* state)
{
    GameObject* tricky = getTrickyObject();
    f32* origin;
    f32 reach = 0.4f;
    VecRotateZXYArg vec;

    if (state->freeRequested != 0 || tricky == NULL)
    {
        Obj_FreeObject(obj);
        return 0;
    }
    obj->anim.velocityX = 0.0f;
    obj->anim.velocityY = 0.0f;
    obj->anim.velocityZ = -1.5f;
    vec.pos[1] = 0.0f;
    vec.pos[2] = 0.0f;
    vec.pos[3] = 0.0f;
    vec.pos[0] = 1.0f;
    vec.dir[2] = tricky->anim.rotZ;
    vec.dir[1] = tricky->anim.rotY;
    vec.dir[0] = tricky->anim.rotX + fn_80138F90(tricky);
    vecRotateZXY(&vec.rotation.x, &obj->anim.velocity.x);
    if ((tricky->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0)
    {
        origin = trickyGetQueuedPathParticlePos(tricky);
    }
    else
    {
        origin = &tricky->anim.localPosX;
    }
    state->launchPosX = -(reach * obj->anim.velocityX - origin[0]);
    state->launchPosY = -(reach * obj->anim.velocityY - origin[1]);
    state->launchPosZ = -(reach * obj->anim.velocityZ - origin[2]);
    if (state->hitVolumeDelay != 0)
    {
        state->hitVolumeDelay -= 1;
    }
    else
    {
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    }
    return 1;
}

int flameblast_getExtraSize(void)
{
    return sizeof(FlameblastState);
}

void flameblast_render(GameObject* obj)
{
    f32 color[3];
    f32 scale = 0.033333335f * ((FlameblastState*)obj->extra)->timer + 0.2f;
    color[0] = 0.0f;
    color[1] = 1.0f;
    color[2] = 0.0f;
    fn_80098B18(obj, scale, 2, 0, 0, color);
}

void flameblast_update(GameObject* obj)
{
    FlameblastState* state = obj->extra;
    state->timer = state->timer + timeDelta;
    if (state->timer > 24.0f)
    {
        state->timer = state->timer - 24.0f;
        if (flameblast_seedVelocity(obj, state) == 0)
        {
            return;
        }
    }
    else
    {
        if (state->timer > 6.0f)
        {
            if (state->hitVolumeDelay == 0)
            {
                ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FLAMEBLAST_HIT_VOLUME_SLOT, 1, 0);
            }
        }
    }
    obj->anim.localPosX = obj->anim.velocityX * state->timer + state->launchPosX;
    obj->anim.localPosY = obj->anim.velocityY * state->timer + state->launchPosY;
    obj->anim.localPosZ = obj->anim.velocityZ * state->timer + state->launchPosZ;
}

void flameblast_init(GameObject* obj, FlameblastPlacement* placement)
{
    FlameblastState* state = obj->extra;
    flameblast_seedVelocity(obj, state);
    state->timer = 3.4285715f * (f32)placement->initialTimer;
    state->hitVolumeDelay = 2;
}

ObjectDescriptor gFlameblastObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)flameblast_init,
    (ObjectDescriptorCallback)flameblast_update,
    0,
    (ObjectDescriptorCallback)flameblast_render,
    0,
    0,
    flameblast_getExtraSize,
};
