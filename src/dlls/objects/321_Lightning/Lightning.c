/* Periodically connects two linked objects with a lightning effect. */
#include "dlls/objects/321_Lightning.h"

#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/newclouds.h"
#include "main/objtype.h"
#include "main/objfx.h"
#include "main/mm.h"
#include "main/vecmath.h"

#define LIGHTNING_AGE_ROUND_BIAS             0.5f
#define LIGHTNING_BURST_CHANCE               100
#define LIGHTNING_BURST_INDEX                5
#define LIGHTNING_BURST_KIND                 1
#define LIGHTNING_BURST_MODE                 1
#define LIGHTNING_BURST_MULTIPLIER           5.0f
#define LIGHTNING_DELAY_FRAME_SCALE          60
#define LIGHTNING_HIT_EFFECT_COUNT           0x1E
#define LIGHTNING_HIT_EFFECT_ID              1
#define LIGHTNING_HIT_EFFECT_VARIANT         7
#define LIGHTNING_LIFETIME_RANDOM_OFFSET_MAX 5
#define LIGHTNING_LIFETIME_RANDOM_OFFSET_MIN -5

int lightning_getExtraSize(void) {
    return sizeof(LightningState);
}

void lightning_free(GameObject* obj, int flags) {
    LightningState* state = obj->extra;

    objFreeObjectType(obj, LIGHTNING_OBJECT_GROUP);
    if (state->effect != NULL) {
        mm_free(state->effect);
    }
}

void lightning_render(GameObject* obj) {
    LightningState* state = obj->extra;

    if (state->effect != NULL) {
        lightningRender(state->effect);
    }
}

void lightning_update(GameObject* obj) {
    LightningState* state;
    u8* objectData;
    u32* objects;
    u32* targetSlot;
    int objectCount;
    int objectIndex;
    int spawnLightning;
    LightningEffect* effect;
    u16 lifetime;
    f32* start;

    state = obj->extra;
    objectData = (u8*)obj->anim.placementData;
    if (((LightningPlacement*)objectData)->enableGameBit != -1) {
        if (state->flags.enabled) {
            if (mainGetBit(((LightningPlacement*)objectData)->enableGameBit) == 0) {
                state->flags.enabled = 0;
                if (state->effect != 0) {
                    mm_free((void*)state->effect);
                    state->effect = 0;
                }
            }
        } else if (mainGetBit(((LightningPlacement*)objectData)->enableGameBit) != 0) {
            state->flags.enabled = 1;
        }
    }

    if (state->effect == 0 && state->flags.enabled) {
        spawnLightning = 0;
        state->countdown -= timeDelta;
        if (state->countdown <= 0.0f) {
            state->countdown +=
                (f32)(s32)((u32)((LightningPlacement*)objectData)->repeatDelay * LIGHTNING_DELAY_FRAME_SCALE);
            spawnLightning = 1;
        }
        if (spawnLightning != 0) {
            objects = (u32*)objGetAllOfType(LIGHTNING_OBJECT_GROUP, &objectCount);
            objectIndex = 0;
            while (objectIndex < objectCount) {
                u32 linkedIdent = ((GameObject*)objects[objectIndex])->anim.placement->ident;
                if (linkedIdent == state->linkedIdent) {
                    break;
                }
                objectIndex++;
            }
            if (objectIndex == objectCount) {
                state->flags.enabled = 0;
                return;
            }

            lifetime = (u16)(state->lifetimeBase + randomGetRange(LIGHTNING_LIFETIME_RANDOM_OFFSET_MIN,
                                                                  LIGHTNING_LIFETIME_RANDOM_OFFSET_MAX));
            start = (f32*)((u8*)obj + offsetof(GameObject, anim.localPosX));
            targetSlot = &objects[objectIndex];
            effect = lightningCreate((const Vec3f*)start,
                                     (const Vec3f*)&((GameObject*)*targetSlot)->anim.localPos, state->radiusX,
                                     state->radiusY, lifetime, state->width, (state->flags.alternateStyle ? 1 : 0));
            state->effect = effect;
            state->ageTimer = 0.0f;
            if ((state->modeBits.mode & LIGHTNING_MODE_HIT_EFFECT) != 0) {
                objfx_spawnHitEffectBurst(obj, state->hitRadius, LIGHTNING_HIT_EFFECT_ID, LIGHTNING_HIT_EFFECT_VARIANT,
                                          LIGHTNING_HIT_EFFECT_COUNT, NULL);
            }
            objectData = ((GameObject*)*targetSlot)->extra;
            if ((((LightningState*)objectData)->modeBits.mode & LIGHTNING_MODE_HIT_EFFECT) != 0) {
                objfx_spawnHitEffectBurst((GameObject*)*targetSlot, ((LightningState*)objectData)->hitRadius,
                                          LIGHTNING_HIT_EFFECT_ID, LIGHTNING_HIT_EFFECT_VARIANT,
                                          LIGHTNING_HIT_EFFECT_COUNT, NULL);
            }
            if ((state->modeBits.mode & LIGHTNING_MODE_DIRECTIONAL_BURST) != 0) {
                objfx_spawnDirectionalBurst(obj, LIGHTNING_BURST_INDEX, state->burstRadius, LIGHTNING_BURST_KIND,
                                            LIGHTNING_BURST_MODE, LIGHTNING_BURST_CHANCE, LIGHTNING_BURST_MULTIPLIER,
                                            NULL, 0);
            }
            if ((((LightningState*)objectData)->modeBits.mode & LIGHTNING_MODE_DIRECTIONAL_BURST) != 0) {
                objfx_spawnDirectionalBurst((GameObject*)*targetSlot, LIGHTNING_BURST_INDEX,
                                            ((LightningState*)objectData)->burstRadius, LIGHTNING_BURST_KIND,
                                            LIGHTNING_BURST_MODE, LIGHTNING_BURST_CHANCE, LIGHTNING_BURST_MULTIPLIER,
                                            NULL, 0);
            }
        }
    }

    if (state->effect != 0) {
        if (state->flags.persistent == 0) {
            state->ageTimer += timeDelta;
            state->effect->timer = (u16)(int)(LIGHTNING_AGE_ROUND_BIAS + state->ageTimer);
        }
        if (state->effect->timer >= state->effect->lifetime) {
            mm_free((void*)state->effect);
            state->effect = 0;
        }
    }
}

void lightning_init(GameObject* obj, LightningPlacement* placement) {
    LightningState* state;
    f32 defaultScale;

    state = obj->extra;
    objAddObjectType(obj, LIGHTNING_OBJECT_GROUP);
    state->modeBits.mode = placement->mode;
    defaultScale = 1.0f;
    state->hitRadius = defaultScale;
    state->burstRadius = defaultScale;
    state->radiusX = (f32)(u32)placement->radiusX;
    state->radiusY = (f32)(u32)placement->radiusY;
    state->lifetimeBase = placement->lifetimeBase;
    state->width = placement->width;
    state->linkedIdent = placement->linkedIdent;

    state->flags.enabled = (placement->flags & LIGHTNING_PLACEMENT_ENABLED) ? 1 : 0;
    state->flags.alternateStyle = (placement->flags & LIGHTNING_PLACEMENT_ALTERNATE_STYLE) ? 1 : 0;
    state->flags.persistent = (placement->flags & LIGHTNING_PLACEMENT_PERSISTENT) ? 1 : 0;

    state->countdown = (f32)(s32)((u32)placement->initialDelay * LIGHTNING_DELAY_FRAME_SCALE);
}

ObjectDescriptor gLightningObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)lightning_init,
    (ObjectDescriptorCallback)lightning_update,
    0,
    (ObjectDescriptorCallback)lightning_render,
    (ObjectDescriptorCallback)lightning_free,
    0,
    lightning_getExtraSize,
};
