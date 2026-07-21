/*
 * arwspeedstr (DLL 0x2A2) - the streaking "speed line" particles that fly
 * past the camera during the on-rails Arwing sections, conveying forward
 * speed. On first update each streak picks a random spread offset in
 * camera space, transforms it through the inverse view matrix into world
 * space and biases it by the player's map offset. It then drifts along its
 * own velocity, fading its alpha up to a cap over its life timer before
 * freeing itself when the timer runs out.
 */
#include "dolphin/mtx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/dll/ARW/dll_02A2_arwspeedstr.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/object_render.h"

static f32 ARWSpeedStr_randomSpread(f32 spread)
{
    return (f32)randomGetRange((int)-spread, (int)spread);
}

int ARWSpeedStr_getExtraSize(void)
{
    return sizeof(ARWSpeedStrState);
}

int ARWSpeedStr_getObjectTypeId(void)
{
    return 0;
}

void ARWSpeedStr_free(void)
{
}

void ARWSpeedStr_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void ARWSpeedStr_hitDetect(void)
{
}

void ARWSpeedStr_update(GameObject* obj)
{
    ARWSpeedStrState* state = obj->extra;
    if (state->flags == 0)
    {
        Vec cameraOffset;
        cameraOffset.x = ARWSpeedStr_randomSpread(state->spreadX);
        cameraOffset.y = ARWSpeedStr_randomSpread(state->spreadY);
        cameraOffset.z = state->viewZ;
        PSMTXMultVec((MtxP)Camera_GetInverseViewMatrix(), &cameraOffset, (Vec*)&obj->anim.localPosX);
        obj->anim.localPosX += playerMapOffsetX;
        obj->anim.localPosZ += playerMapOffsetZ;
        state->flags = (state->flags | ARWSPEEDSTR_FLAG_POSITION_INITIALIZED) & 0xff;
        state->alpha = 0.0f;
    }
    {
        f32 lifeTimer = state->lifeTimer;
        f32 zero = 0.0f;
        if (lifeTimer > zero)
        {
            state->lifeTimer = lifeTimer - timeDelta;
            if (state->lifeTimer <= zero)
            {
                state->lifeTimer = zero;
                Obj_FreeObject(obj);
                return;
            }
        }
        else
        {
            return;
        }
        objMove(obj, zero, zero, state->speed * timeDelta);
        state->alpha = 2.0f * timeDelta + state->alpha;
        if (state->alpha > 140.0f)
            state->alpha = 140.0f;
        obj->anim.alpha = state->alpha;
    }
}

void ARWSpeedStr_init(GameObject* obj, ObjPlacement* placement)
{
    obj->anim.alpha = 0;
}

void ARWSpeedStr_release(void)
{
}

void ARWSpeedStr_initialise(void)
{
}

ObjectDescriptor gARWSpeedStrObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ARWSpeedStr_initialise, (ObjectDescriptorCallback)ARWSpeedStr_release, 0,
    (ObjectDescriptorCallback)ARWSpeedStr_init, (ObjectDescriptorCallback)ARWSpeedStr_update,
    (ObjectDescriptorCallback)ARWSpeedStr_hitDetect, (ObjectDescriptorCallback)ARWSpeedStr_render,
    (ObjectDescriptorCallback)ARWSpeedStr_free, (ObjectDescriptorCallback)ARWSpeedStr_getObjectTypeId,
    ARWSpeedStr_getExtraSize,
};
