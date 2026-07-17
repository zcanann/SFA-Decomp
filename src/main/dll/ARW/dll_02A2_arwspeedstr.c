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
#include "main/object_render_legacy.h"

int ARWSpeedStr_getExtraSize(void)
{
    return 0x1c;
}

int ARWSpeedStr_getObjectTypeId(void)
{
    return 0;
}

void ARWSpeedStr_free(void)
{
}

void ARWSpeedStr_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7100);
}

void ARWSpeedStr_hitDetect(void)
{
}

void ARWSpeedStr_update(GameObject* obj)
{
    ARWSpeedStrState* state = (obj)->extra;
    if (state->flags == 0)
    {
        f32 camOffset[3];
        camOffset[0] = (f32)(int)randomGetRange((int)-state->spreadX, state->spreadX);
        camOffset[1] = (f32)(int)randomGetRange((int)-state->spreadY, state->spreadY);
        camOffset[2] = state->viewZ;
        PSMTXMultVec((MtxP)Camera_GetInverseViewMatrix(), (const Vec*)&camOffset[0], (Vec*)((char*)obj + 12));
        (obj)->anim.localPosX += playerMapOffsetX;
        (obj)->anim.localPosZ += playerMapOffsetZ;
        state->flags = (state->flags | 1) & 0xff;
        state->alpha = lbl_803E7104;
    }
    {
        f32 lifeTimer = state->lifeTimer;
        f32 zero = lbl_803E7104;
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
        objMove((GameObject*)obj, zero, zero, state->speed * timeDelta);
        state->alpha = lbl_803E7108 * timeDelta + state->alpha;
        if (state->alpha > *(f32*)&lbl_803E710C)
            state->alpha = lbl_803E710C;
        (obj)->anim.alpha = state->alpha;
    }
}

void ARWSpeedStr_init(GameObject* obj, int setup)
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
