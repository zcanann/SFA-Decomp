/*
 * Placed particle emitter with effect-bank, flag-preset, animation-event,
 * GameBit, proximity, interval, and per-axis rotation controls.
 */
#include "dlls/objects/299_FXEmit.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/debug.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/projgfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/resource.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/vecmath.h"
#include "main/objseq.h"

#define FXEMIT_DEBUG_EFFECT_ID              0x11
#define FXEMIT_EVENT_EMIT                   1
#define FXEMIT_EVENT_TOGGLE_SEQUENCE        2
#define FXEMIT_GAME_BIT_NONE                -1
#define FXEMIT_PRESET_0_SPAWN_FLAGS         2
#define FXEMIT_PRESET_1_SPAWN_FLAGS         4
#define FXEMIT_PRESET_2_PARTICLE_FLAGS      0x200001
#define FXEMIT_PRESET_2_RESOURCE_FLAGS      1
#define FXEMIT_MODEL_RESOURCE_ID_BASE       0x58
#define FXEMIT_PROJECTILE_RESOURCE_ID_BASE  0xAB
#define FXEMIT_PROJECTILE_EFFECT_ID_MASK    0xFF
#define FXEMIT_ROTATION_SPEED_DEFAULT       10
#define FXEMIT_ROTATION_SPEED_SCALE         100
#define FXEMIT_INTERVAL_FRAME_SCALE         100
#define FXEMIT_ACTIVATION_RANGE_SCALE_SHIFT 2
#define FXEMIT_INITIAL_ROTATION_SHIFT       8
#define FXEMIT_INITIAL_SCALE                0.1f
#define FXEMIT_RANDOM_DELAY_MAX             10

extern char sFXEmitDebugFormat[];

void FXEmit_emitEffect(GameObject* obj) {
    FXEmitState* state;
    FXEmitPlacement* placement;
    int spawnFlags;
    s16 i;

    state = obj->extra;
    placement = (FXEmitPlacement*)obj->anim.placementData;
    spawnFlags = 0;
    if (state->effectId == FXEMIT_DEBUG_EFFECT_ID) {
        logPrintf(sFXEmitDebugFormat, obj, obj->anim.localPosX, obj->anim.localPosZ);
    }

    switch (placement->flagPreset) {
    case FXEMIT_FLAG_PRESET_0: {
        s16 effectBank = state->effectBank;
        if (effectBank == FXEMIT_EFFECT_BANK_PARTICLE) {
            spawnFlags = FXEMIT_PRESET_0_SPAWN_FLAGS;
        }
        if (effectBank == FXEMIT_EFFECT_BANK_MODEL) {
            spawnFlags = FXEMIT_PRESET_0_SPAWN_FLAGS;
        }
        if (effectBank == FXEMIT_EFFECT_BANK_PROJECTILE) {
            spawnFlags = FXEMIT_PRESET_0_SPAWN_FLAGS;
        }
        break;
    }
    case FXEMIT_FLAG_PRESET_1: {
        s16 effectBank = state->effectBank;
        if (effectBank == FXEMIT_EFFECT_BANK_PARTICLE) {
            spawnFlags = FXEMIT_PRESET_1_SPAWN_FLAGS;
        }
        if (effectBank == FXEMIT_EFFECT_BANK_MODEL) {
            spawnFlags = FXEMIT_PRESET_1_SPAWN_FLAGS;
        }
        if (effectBank == FXEMIT_EFFECT_BANK_PROJECTILE) {
            spawnFlags = FXEMIT_PRESET_1_SPAWN_FLAGS;
        }
        break;
    }
    case FXEMIT_FLAG_PRESET_2: {
        s16 effectBank = state->effectBank;
        if (effectBank == FXEMIT_EFFECT_BANK_PARTICLE) {
            spawnFlags = FXEMIT_PRESET_2_PARTICLE_FLAGS;
        }
        if (effectBank == FXEMIT_EFFECT_BANK_MODEL) {
            spawnFlags = FXEMIT_PRESET_2_RESOURCE_FLAGS;
        }
        if (effectBank == FXEMIT_EFFECT_BANK_PROJECTILE) {
            spawnFlags = FXEMIT_PRESET_2_RESOURCE_FLAGS;
        }
        break;
    }
    case FXEMIT_FLAG_PRESET_NONE:
        spawnFlags = 0;
        break;
    default:
        spawnFlags = FXEMIT_PRESET_0_SPAWN_FLAGS;
        break;
    }

    if ((spawnFlags & 1) != 0) {
        PartFxSpawnParams args;

        args.posX = obj->anim.localPosX;
        args.posY = obj->anim.localPosY;
        args.posZ = obj->anim.localPosZ;
        args.rotX = obj->anim.rotX;
        args.rotZ = obj->anim.rotZ;
        args.rotY = obj->anim.rotY;
        args.scale = 1.0f;
        if (state->emitRate > 0) {
            for (i = 0; i < state->emitRate; i++) {
                (*gPartfxInterface)->spawnObject(obj, state->effectId, &args, spawnFlags, -1, NULL);
            }
        } else {
            (*gPartfxInterface)->spawnObject(obj, state->alternateEffectId, &args, spawnFlags, -1, NULL);
        }
    } else {
        ModgfxResource* resource;
        s16 effectBank = state->effectBank;

        if (effectBank == FXEMIT_EFFECT_BANK_PARTICLE) {
            if (state->emitRate > 0) {
                for (i = 0; i < state->emitRate; i++) {
                    (*gPartfxInterface)->spawnObject(obj, state->effectId, NULL, spawnFlags, -1, NULL);
                }
            } else {
                (*gPartfxInterface)->spawnObject(obj, state->effectId, NULL, spawnFlags, -1, NULL);
            }
        } else if (effectBank == FXEMIT_EFFECT_BANK_MODEL) {
            resource = Resource_Acquire((state->effectId + FXEMIT_MODEL_RESOURCE_ID_BASE), 1);
            if (state->emitRate > 0) {
                for (i = 0; i < state->emitRate; i++) {
                    resource->vtable->spawnEffect(obj, 0, 0, spawnFlags, -1, 0);
                }
            } else {
                resource->vtable->spawnEffect(obj, 0, 0, spawnFlags, -1, 0);
            }
            Resource_Release(resource);
        } else if (effectBank == FXEMIT_EFFECT_BANK_PROJECTILE) {
            resource = Resource_Acquire((state->effectId + FXEMIT_PROJECTILE_RESOURCE_ID_BASE), 1);
            if (state->emitRate > 0) {
                for (i = 0; i < state->emitRate; i++) {
                    ((ProjgfxResource*)resource)
                        ->vtable->spawnEffect(obj, 0, 0, spawnFlags, -1,
                                              state->effectId & FXEMIT_PROJECTILE_EFFECT_ID_MASK, 0);
                }
            } else {
                ((ProjgfxResource*)resource)
                    ->vtable->spawnEffect(obj, 0, 0, spawnFlags, -1, state->effectId & FXEMIT_PROJECTILE_EFFECT_ID_MASK,
                                          0);
            }
            Resource_Release(resource);
        }
    }
}

int FXEmit_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    FXEmitState* state;
    FXEmitPlacement* placement;
    int i;
    s8 rotationSpeed;

    state = obj->extra;
    placement = (FXEmitPlacement*)obj->anim.placementData;
    for (i = 0; i < animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == FXEMIT_EVENT_EMIT) {
            FXEmit_emitEffect(obj);
        }
        if (animUpdate->eventIds[i] == FXEMIT_EVENT_TOGGLE_SEQUENCE) {
            state->sequenceRotate = 1 - state->sequenceRotate;
        }
        animUpdate->eventIds[i] = 0;
    }

    if (state->sequenceRotate != 0) {
        rotationSpeed = placement->yawSpeed;
        if (rotationSpeed == FXEMIT_ROTATION_SPEED_AUTO) {
            obj->anim.rotX = obj->anim.rotX + framesThisStep * FXEMIT_ROTATION_SPEED_DEFAULT;
        } else {
            obj->anim.rotX = obj->anim.rotX + rotationSpeed * framesThisStep * FXEMIT_ROTATION_SPEED_SCALE;
        }

        rotationSpeed = placement->pitchSpeed;
        if (rotationSpeed == FXEMIT_ROTATION_SPEED_AUTO) {
            obj->anim.rotY = obj->anim.rotY + framesThisStep * FXEMIT_ROTATION_SPEED_DEFAULT;
        } else {
            obj->anim.rotY = obj->anim.rotY + rotationSpeed * framesThisStep * FXEMIT_ROTATION_SPEED_SCALE;
        }

        rotationSpeed = placement->rollSpeed;
        if (rotationSpeed == FXEMIT_ROTATION_SPEED_AUTO) {
            obj->anim.rotZ = obj->anim.rotZ + framesThisStep * FXEMIT_ROTATION_SPEED_DEFAULT;
        } else {
            obj->anim.rotZ = obj->anim.rotZ + rotationSpeed * framesThisStep * FXEMIT_ROTATION_SPEED_SCALE;
        }
        FXEmit_emitEffect(obj);
    }

    return 0;
}

int FXEmit_getExtraSize(void) {
    return sizeof(FXEmitState);
}

int FXEmit_getObjectTypeId(void) {
    return 0;
}

void FXEmit_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects(obj);
}

void FXEmit_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0)
        return;
}

void FXEmit_hitDetect(void) {
}

void FXEmit_update(GameObject* obj) {
    FXEmitState* state;
    FXEmitPlacement* placement;
    GameObject* player;
    s16 emitRate;
    s8 rotationSpeed;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 distance;

    state = obj->extra;
    placement = (FXEmitPlacement*)obj->anim.placementData;
    if (state->randomDelay != 0) {
        state->randomDelay -= (s16)timeDelta;
        if (state->randomDelay < 0) {
            state->randomDelay = 0;
        }
    } else {
        obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
        obj->anim.worldPosX = obj->anim.localPosX;
        obj->anim.worldPosY = obj->anim.localPosY;
        obj->anim.worldPosZ = obj->anim.localPosZ;
        player = Obj_GetPlayerObject();
        if (player == NULL || placement == NULL) {
            return;
        }
        if (placement->interval != 0 && placement->interval != FXEMIT_INTERVAL_DISABLED) {
            if (state->intervalTimer <= 0) {
                int sfxId;

                state->disabled = 0;
                state->intervalTimer = placement->interval * FXEMIT_INTERVAL_FRAME_SCALE;
                sfxId = placement->intervalSfxId;
                if (sfxId != 0) {
                    Sfx_PlayFromObject(obj, (u16)sfxId);
                }
            } else {
                state->disabled = 1;
            }
            state->intervalTimer -= framesThisStep;
        }

        rotationSpeed = placement->yawSpeed;
        if (rotationSpeed == FXEMIT_ROTATION_SPEED_AUTO) {
            obj->anim.rotX = obj->anim.rotX + framesThisStep * FXEMIT_ROTATION_SPEED_DEFAULT;
        } else {
            obj->anim.rotX = obj->anim.rotX + rotationSpeed * framesThisStep * FXEMIT_ROTATION_SPEED_SCALE;
        }

        rotationSpeed = placement->pitchSpeed;
        if (rotationSpeed == FXEMIT_ROTATION_SPEED_AUTO) {
            obj->anim.rotY = obj->anim.rotY + framesThisStep * FXEMIT_ROTATION_SPEED_DEFAULT;
        } else {
            obj->anim.rotY = obj->anim.rotY + rotationSpeed * framesThisStep * FXEMIT_ROTATION_SPEED_SCALE;
        }

        rotationSpeed = placement->rollSpeed;
        if (rotationSpeed == FXEMIT_ROTATION_SPEED_AUTO) {
            obj->anim.rotZ = obj->anim.rotZ + framesThisStep * FXEMIT_ROTATION_SPEED_DEFAULT;
        } else {
            obj->anim.rotZ = obj->anim.rotZ + rotationSpeed * framesThisStep * FXEMIT_ROTATION_SPEED_SCALE;
        }

        if (state->toggleGameBit == FXEMIT_GAME_BIT_NONE || mainGetBit(state->toggleGameBit) != 0) {
            switch (state->disabled) {
            case 0: {
                if (state->disableGameBit != FXEMIT_GAME_BIT_NONE && mainGetBit(state->disableGameBit) != 0) {
                    state->disabled = 1;
                }
                if (placement->interval == FXEMIT_INTERVAL_DISABLED) {
                    state->disabled = 1;
                }
                emitRate = state->emitRate;
                if (emitRate >= 0 || (emitRate < 0 && obj->userData1 <= 0)) {
                    deltaX = obj->anim.worldPosX - player->anim.worldPosX;
                    deltaY = obj->anim.worldPosY - player->anim.worldPosY;
                    deltaZ = obj->anim.worldPosZ - player->anim.worldPosZ;
                    if (emitRate == 0) {
                        state->disabled = 1;
                    }
                    distance = sqrtf(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
                    if (distance <= state->activationRange || state->activationRange == 0.0f) {
                        FXEmit_emitEffect(obj);
                    }
                    obj->userData1 = -state->emitRate;
                } else if (emitRate < 0 && obj->userData1 > 0) {
                    obj->userData1 -= framesThisStep;
                }
                break;
            }
            }
        }
    }
}

void FXEmit_init(GameObject* obj, FXEmitPlacement* placement) {
    FXEmitState* state;

    obj->anim.rotX = 0;
    obj->animEventCallback = FXEmit_sequenceCallback;
    state = obj->extra;

    state->activationRange = (f32)((s32)placement->activationRange << FXEMIT_ACTIVATION_RANGE_SCALE_SHIFT);
    state->effectBank = placement->effectBank;
    state->effectId = placement->effectId;
    state->emitRate = placement->emitRate;
    obj->anim.rootMotionScale = FXEMIT_INITIAL_SCALE;
    state->toggleGameBit = placement->toggleGameBit;
    state->disableGameBit = placement->disableGameBit;
    state->disabled = 0;

    if (state->emitRate < 1) {
        obj->userData1 = state->emitRate;
    } else {
        obj->userData1 = 0;
    }

    if (state->disableGameBit != FXEMIT_GAME_BIT_NONE && mainGetBit(state->disableGameBit) != 0) {
        state->disabled = 1;
    }

    obj->anim.rotX = (s16)(placement->initialYaw << FXEMIT_INITIAL_ROTATION_SHIFT);
    obj->anim.rotY = (s16)(placement->initialPitch << FXEMIT_INITIAL_ROTATION_SHIFT);
    obj->anim.rotZ = (s16)(placement->initialRoll << FXEMIT_INITIAL_ROTATION_SHIFT);
    state->intervalTimer = (s16)(placement->interval * FXEMIT_INTERVAL_FRAME_SCALE);
    state->initialX = obj->anim.localPosX;
    state->randomDelay = randomGetRange(0, FXEMIT_RANDOM_DELAY_MAX);
    state->alternateEffectId = 0;
}

void FXEmit_release(void) {
}

void FXEmit_initialise(void) {
}

ObjectDescriptor gFXEmitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FXEmit_initialise,
    (ObjectDescriptorCallback)FXEmit_release,
    0,
    (ObjectDescriptorCallback)FXEmit_init,
    (ObjectDescriptorCallback)FXEmit_update,
    (ObjectDescriptorCallback)FXEmit_hitDetect,
    (ObjectDescriptorCallback)FXEmit_render,
    (ObjectDescriptorCallback)FXEmit_free,
    (ObjectDescriptorCallback)FXEmit_getObjectTypeId,
    FXEmit_getExtraSize,
};

char sFXEmitDebugFormat[12] = "%x   %f %f\n";
