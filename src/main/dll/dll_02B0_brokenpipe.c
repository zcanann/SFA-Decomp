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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define BROKENPIPE_OBJFLAG_HIDDEN 0x4000

typedef struct BrokenPipeSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 pad1C[4];
} BrokenPipeSetup;

STATIC_ASSERT(offsetof(BrokenPipeSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(BrokenPipeSetup, scale) == 0x1b);
STATIC_ASSERT(sizeof(BrokenPipeSetup) == 0x20);

typedef struct BrokenPipeState
{
    f32 hitEffectCooldown;
} BrokenPipeState;

STATIC_ASSERT(sizeof(BrokenPipeState) == 4);

int brokenpipe_getExtraSize(void) { return 4; }

void brokenpipe_update(int obj)
{
    BrokenPipeState* state = ((GameObject*)obj)->extra;

    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                              &state->hitEffectCooldown);
}

void brokenpipe_init(int obj, int setup)
{
    GameObject* object = (GameObject*)obj;
    BrokenPipeSetup* setupData = (BrokenPipeSetup*)setup;

    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    if (setupData->scale != 0)
    {
        object->anim.rootMotionScale = (f32)(u32)setupData->scale / lbl_803E7338;
        if (object->anim.rootMotionScale == lbl_803E733C)
        {
            object->anim.rootMotionScale = lbl_803E7340;
        }
        ObjHitbox_SetSphereRadius(obj,
                                  (int)((f32)((ObjHitsPriorityState*)object->anim.hitReactState)->primaryRadius *
                                        object->anim.rootMotionScale));
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags |= BROKENPIPE_OBJFLAG_HIDDEN;
}
