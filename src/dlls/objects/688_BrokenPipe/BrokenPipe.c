/*
 * BrokenPipe (DLL 688) supplies hit responses for a hidden object. The update
 * callback requests light-blue hit particles and a staff-hit sound on a cooldown;
 * this TU neither renders the object nor implements a breaking transition.
 *
 * Initialization applies packed rotation bytes and an optional scale. It retains
 * the zero-scale check, scales the signed sphere radius, then multiplies the
 * object's scale by the model base scale. The object is marked hidden afterward.
 */
#include "dlls/objects/688_BrokenPipe.h"
#include "game/objects/object.h"
#include "main/objhits.h"

int brokenpipe_getExtraSize(void)
{
    return sizeof(BrokenPipeState);
}

void brokenpipe_update(GameObject* obj)
{
    BrokenPipeState* state = obj->extra;

    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f, &state->hitEffectCooldown);
}

void brokenpipe_init(GameObject* obj, BrokenPipePlacementPrefix* setup)
{
    f32 zeroScale = 0.0f;

    obj->anim.rotZ = (s16)(setup->rotZ << 8);
    obj->anim.rotY = (s16)(setup->rotY << 8);
    obj->anim.rotX = (s16)(setup->rotX << 8);
    if (setup->scale != 0)
    {
        obj->anim.rootMotionScale = (f32)(u32)setup->scale / 255.0f;
        if (obj->anim.rootMotionScale == zeroScale)
        {
            obj->anim.rootMotionScale = 1.0f;
        }
        ObjHitbox_SetSphereRadius(&obj->anim,
                                  (int)((f32)((ObjHitsPriorityState*)obj->anim.hitReactState)->primaryRadius *
                                        obj->anim.rootMotionScale));
        obj->anim.rootMotionScale *= obj->anim.modelInstance->rootMotionScaleBase;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}

ObjectDescriptor gBrokenPipeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    NULL,
    NULL,
    NULL,
    (ObjectDescriptorCallback)brokenpipe_init,
    (ObjectDescriptorCallback)brokenpipe_update,
    NULL,
    NULL,
    NULL,
    NULL,
    brokenpipe_getExtraSize,
};
