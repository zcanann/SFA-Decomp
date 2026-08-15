/*
 * Waterfall spray emitter with placement-controlled particle variants,
 * random extents, activation radius, cadence, and ambient looped sounds.
 */
#include "dlls/objects/306_WaterFallSp.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define WATERFALLSPRAY_GAME_BIT_NONE -1

#define WATERFALLSPRAY_ROTATION_SHIFT 8
#define WATERFALLSPRAY_RADIUS_SHIFT   4

#define WATERFALLSPRAY_PARTICLE_SPAWN_MODE 4
#define WATERFALLSPRAY_PARTICLE_MODEL_NONE -1

#define WATERFALLSPRAY_EFFECT_320 0x320
#define WATERFALLSPRAY_EFFECT_321 0x321
#define WATERFALLSPRAY_EFFECT_322 0x322
#define WATERFALLSPRAY_EFFECT_351 0x351

#define WATERFALLSPRAY_ALT_SFX_MAP_ID_MIN 0x4BE5C
#define WATERFALLSPRAY_ALT_SFX_MAP_ID_END 0x4BE5E

#define WATERFALLSPRAY_DEFAULT_SFX_A 0x2AF
#define WATERFALLSPRAY_DEFAULT_SFX_B 0x2B2
#define WATERFALLSPRAY_ALT_SFX_A     0x489
#define WATERFALLSPRAY_ALT_SFX_B     0x48A

int WaterFallSpray_getExtraSize(void) {
    return sizeof(WaterFallSprayState);
}

int WaterFallSpray_sequenceCallback(GameObject* obj) {
    WaterFallSpray_update(obj);
    return 0;
}

void WaterFallSpray_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void WaterFallSpray_render(void) {
}

void WaterFallSpray_update(GameObject* obj) {
    WaterFallSprayState* state;
    WaterFallSprayPlacement* placement;
    GameObject* playerObj;
    PartFxSpawnParams partfxArgs;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
    f32 distance;
    int cooldown;
    s16 enabled;
    s16 i;

    state = obj->extra;
    placement = (WaterFallSprayPlacement*)obj->anim.placement;
    playerObj = Obj_GetPlayerObject();
    if (playerObj != NULL) {
        if (placement->enableGameBit != WATERFALLSPRAY_GAME_BIT_NONE) {
            enabled = mainGetBit(placement->enableGameBit);
        } else {
            enabled = 1;
        }
        if (enabled != 0) {
            if ((placement->flags & WATERFALLSPRAY_FLAG_SFX_DISABLED) == 0) {
                Sfx_KeepAliveLoopedObjectSound(obj, state->sfxIdA & 0xFFFF);
                Sfx_KeepAliveLoopedObjectSound(obj, state->sfxIdB & 0xFFFF);
            }

            cooldown = obj->userData1;
            if (cooldown <= 0) {
                xDelta = obj->anim.worldPosX - playerObj->anim.worldPosX;
                yDelta = obj->anim.worldPosY - playerObj->anim.worldPosY;
                zDelta = obj->anim.worldPosZ - playerObj->anim.worldPosZ;
                distance = sqrtf(zDelta * zDelta + (xDelta * xDelta + yDelta * yDelta));
                if (((distance <= (f32)(s32)((u32)placement->triggerRadius << WATERFALLSPRAY_RADIUS_SHIFT)) ||
                     (placement->triggerRadius == 0)) &&
                    ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0)) {
                    for (i = 0; i < placement->emitCount; i++) {
                        partfxArgs.posX = (f32)(s32)randomGetRange(-placement->randomExtentX, placement->randomExtentX);
                        partfxArgs.posY = (f32)(s32)randomGetRange(-placement->randomExtentY, placement->randomExtentY);
                        partfxArgs.posZ = (f32)(s32)randomGetRange(-placement->randomExtentZ, placement->randomExtentZ);
                        if ((placement->flags & WATERFALLSPRAY_FLAG_EFFECT_320) != 0) {
                            (*gPartfxInterface)
                                ->spawnObject(obj, WATERFALLSPRAY_EFFECT_320, &partfxArgs,
                                              WATERFALLSPRAY_PARTICLE_SPAWN_MODE, WATERFALLSPRAY_PARTICLE_MODEL_NONE,
                                              NULL);
                        }
                        if ((placement->flags & WATERFALLSPRAY_FLAG_EFFECT_321) != 0) {
                            (*gPartfxInterface)
                                ->spawnObject(obj, WATERFALLSPRAY_EFFECT_321, &partfxArgs,
                                              WATERFALLSPRAY_PARTICLE_SPAWN_MODE, WATERFALLSPRAY_PARTICLE_MODEL_NONE,
                                              NULL);
                        }
                        if ((placement->flags & WATERFALLSPRAY_FLAG_EFFECT_322) != 0) {
                            (*gPartfxInterface)
                                ->spawnObject(obj, WATERFALLSPRAY_EFFECT_322, &partfxArgs,
                                              WATERFALLSPRAY_PARTICLE_SPAWN_MODE, WATERFALLSPRAY_PARTICLE_MODEL_NONE,
                                              NULL);
                        }
                        if ((placement->flags & WATERFALLSPRAY_FLAG_EFFECT_351) != 0) {
                            (*gPartfxInterface)
                                ->spawnObject(obj, WATERFALLSPRAY_EFFECT_351, &partfxArgs,
                                              WATERFALLSPRAY_PARTICLE_SPAWN_MODE, WATERFALLSPRAY_PARTICLE_MODEL_NONE,
                                              NULL);
                        }
                    }
                }
                obj->userData1 = -placement->emitCount;
            } else if (cooldown > 0) {
                obj->userData1 = cooldown - framesThisStep;
            }
        }
    }
}

void WaterFallSpray_init(GameObject* obj, WaterFallSprayPlacement* placement) {
    WaterFallSprayState* state = obj->extra;
    s16 initialRotZ;
    s16 initialRotY;
    s16 initialRotX;
    int mapId;

    initialRotZ = (s16)((s32)placement->initialRotZ << WATERFALLSPRAY_ROTATION_SHIFT);
    obj->anim.rotZ = initialRotZ;
    initialRotY = (s16)((s32)placement->initialRotY << WATERFALLSPRAY_ROTATION_SHIFT);
    obj->anim.rotY = initialRotY;
    initialRotX = (s16)((s32)placement->initialRotX << WATERFALLSPRAY_ROTATION_SHIFT);
    obj->anim.rotX = initialRotX;
    obj->userData1 = 0;
    obj->animEventCallback = WaterFallSpray_sequenceCallback;
    mapId = ((WaterFallSprayPlacement*)obj->anim.placement)->base.ident;
    switch (mapId) {
    case WATERFALLSPRAY_ALT_SFX_MAP_ID_MIN:
    case WATERFALLSPRAY_ALT_SFX_MAP_ID_END - 1:
        state->sfxIdA = WATERFALLSPRAY_ALT_SFX_A;
        state->sfxIdB = WATERFALLSPRAY_ALT_SFX_B;
        return;
    default:
        state->sfxIdA = WATERFALLSPRAY_DEFAULT_SFX_A;
        state->sfxIdB = WATERFALLSPRAY_DEFAULT_SFX_B;
    }
}

ObjectDescriptor gWaterFallSprayObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)WaterFallSpray_init,
    (ObjectDescriptorCallback)WaterFallSpray_update,
    0,
    (ObjectDescriptorCallback)WaterFallSpray_render,
    (ObjectDescriptorCallback)WaterFallSpray_free,
    0,
    WaterFallSpray_getExtraSize,
};
