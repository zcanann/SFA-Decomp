/*
 * brokenpipe (DLL 0x2B0) - a static, breakable pipe prop.
 *
 * init applies the placement's packed Z/Y/X rotation bytes (1/256 turns)
 * and an optional uniform scale: the scale byte is normalised, and if the
 * normalised value equals a sentinel constant it is replaced with a safe
 * fallback, then used to scale the hitbox sphere radius, then folded into
 * the model's base root-motion scale. update polls the priority hit-react
 * system, flashing a light-blue hit effect on a cooldown.
 */
#include "main/dll/dll_02B0_brokenpipe.h"
#include "main/game_object.h"
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

void brokenpipe_init(GameObject* obj, BrokenPipeSetup* setup)
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
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                  (int)((f32)((ObjHitsPriorityState*)obj->anim.hitReactState)->primaryRadius *
                                        obj->anim.rootMotionScale));
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
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
