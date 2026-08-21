/*
 * DIMLogFire (DLL 0x1C0) manages the DarkIce Mines log-fire effect,
 * interaction state, child object, and point light.
 */

#include "dlls/objects/448_DIMLogFire.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/objtype.h"

#define DIM_LOG_FIRE_HIT_VOLUME_SLOT 0x1F
#define DIM_LOG_FIRE_SMOKE_PARTICLE  215

#define DIM_LOG_FIRE_MODE_LIT       1
#define DIM_LOG_FIRE_MODE_UNLIT     2
#define DIM_LOG_FIRE_MODE_ANIM_HELD 4

#define DIM_LOG_FIRE_ANIM_COMMAND_TOGGLE_SMOKE 1
#define DIM_LOG_FIRE_ANIM_COMMAND_SET_GAMEBIT  2
#define DIM_LOG_FIRE_ANIM_COMMAND_HOLD         3

#define DIM_LOG_FIRE_ANIM_GAMEBIT   46
#define DIM_LOG_FIRE_OBJECT_GROUP   0x31
#define DIM_LOG_FIRE_OBJECT_TYPE_ID 1

int DIMLogFire_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    DimLogFireState* state = obj->extra;

    (void)unused;

    if (state->mode == DIM_LOG_FIRE_MODE_LIT) {
        Sfx_PlayFromObject(obj, SFXTRIG_mushdizzylp12);
    } else {
        Sfx_StopObjectChannel(obj, 64);
    }
    switch (animUpdate->curEventId) {
    case DIM_LOG_FIRE_ANIM_COMMAND_TOGGLE_SMOKE:
        state->smokeEnabled = state->smokeEnabled ^ 1;
        break;
    case DIM_LOG_FIRE_ANIM_COMMAND_SET_GAMEBIT:
        mainSetBits(DIM_LOG_FIRE_ANIM_GAMEBIT, 1);
        break;
    case DIM_LOG_FIRE_ANIM_COMMAND_HOLD:
        state->mode = DIM_LOG_FIRE_MODE_ANIM_HELD;
        break;
    }
    if (state->smokeEnabled != 0) {
        (*gPartfxInterface)->spawnObject(obj, DIM_LOG_FIRE_SMOKE_PARTICLE, NULL, 0, -1, NULL);
        Sfx_StopObjectChannel(obj, 5);
    } else {
        Sfx_StopObjectChannel(obj, 1);
    }
    animUpdate->curEventId = 0;
    return 0;
}

int dimlogfire_countdownCallback(GameObject* obj, int delta) {
    DimLogFireState* state = obj->extra;

    state->remainingStrength = state->remainingStrength - delta;
    return state->remainingStrength <= 0;
}

int DIMLogFire_getExtraSize(void) {
    return sizeof(DimLogFireState);
}

int DIMLogFire_getObjectTypeId(void) {
    return DIM_LOG_FIRE_OBJECT_TYPE_ID;
}

void DIMLogFire_free(GameObject* obj, int freeMode) {
    DimLogFireState* state = obj->extra;

    (*gExpgfxInterface)->freeSource2((u32)obj);
    if ((void*)state->subObject != NULL && freeMode == 0) {
        Obj_FreeObject((GameObject*)state->subObject);
    }
    objFreeObjectType(obj, DIM_LOG_FIRE_OBJECT_GROUP);
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
    }
}

void DIMLogFire_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DimLogFireState* state;
    ObjAnimComponent* subObject;

    if ((s32)visible != 0) {
        state = obj->extra;
        subObject = (ObjAnimComponent*)state->subObject;
        if (subObject != NULL) {
            ObjModel* model = (ObjModel*)subObject->banks[subObject->bankIndex];
            model->bufferFlags = (u16)(model->bufferFlags & ~0x8);
            ((GameObject*)state->subObject)->anim.renderAlpha = obj->anim.renderAlpha;
            objRenderModelAndHitVolumes((GameObject*)state->subObject, renderArg2, renderArg3, renderArg4, renderArg5,
                                        1.0f);
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        if (state->light != NULL) {
            if (state->light->glowType != 0) {
                if (state->light->enabled != 0) {
                    queueGlowRender(state->light);
                }
            }
        }
    }
}

void DIMLogFire_update(GameObject* obj) {
    int flickerFlagA;
    int flickerFlagB;
    int randomOffset;
    s16 glowAlpha;
    ModelLightStruct* light;
    GameObject* tricky;
    const DimLogFirePlacement* placement;
    DimLogFireState* state;
    Vec3f effectOffset;

    state = obj->extra;
    placement = (const DimLogFirePlacement*)obj->anim.placementData;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    switch (state->mode) {
    case DIM_LOG_FIRE_MODE_LIT:
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 1, 2.0f);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_mushdizzylp12);
        state->flickerTimerA = state->flickerTimerA - timeDelta;
        if (state->flickerTimerA <= 0.0f) {
            flickerFlagA = 7;
            state->flickerTimerA += 10.0f;
        } else {
            flickerFlagA = 0;
        }
        state->flickerTimerB = state->flickerTimerB - timeDelta;
        if (state->flickerTimerB <= 0.0f) {
            flickerFlagB = 1;
            state->flickerTimerB += 1.0f;
        } else {
            flickerFlagB = 0;
        }
        effectOffset.x = 0.0f;
        effectOffset.y = 10.0f;
        effectOffset.z = 0.0f;
        objfx_spawnPulseBurst(obj, obj->anim.rootMotionScale, 2, flickerFlagA, flickerFlagB, &effectOffset.x);
        ObjHits_SetHitVolumeSlot(&obj->anim, DIM_LOG_FIRE_HIT_VOLUME_SLOT, 1, 0);
        break;
    case DIM_LOG_FIRE_MODE_UNLIT:
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 2.0f);
        }
        if (state->remainingStrength <= 0) {
            ObjHits_DisableObject(obj);
            state->mode = DIM_LOG_FIRE_MODE_LIT;
            state->transitionLatch = 1;
            mainSetBits(placement->douseGameBit, 1);
        }
        tricky = getTrickyObject();
        if (tricky != NULL) {
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                TRICKY_INTERFACE(tricky)
                    ->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                        TRICKY_COMMAND_TYPE_FLAME);
            }
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        }
        ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, 0);
        break;
    case DIM_LOG_FIRE_MODE_ANIM_HELD:
        break;
    default:
        if (state->initialMode == 0) {
            state->mode = DIM_LOG_FIRE_MODE_LIT;
            state->transitionLatch = 1;
        } else {
            state->mode = DIM_LOG_FIRE_MODE_UNLIT;
        }
        break;
    }
    if ((s8)state->transitionLatch != 0) {
        state->transitionLatch = 0;
    }
    light = state->light;
    if (light != NULL && light->glowType != 0 && light->enabled != 0) {
        randomOffset = randomGetRange(-0x19, 0x19);
        light = state->light;
        glowAlpha = light->glowAlpha + light->glowAlphaStep + randomOffset;
        if (glowAlpha < 0) {
            glowAlpha = 0;
            light->glowAlphaStep = 0;
        } else if (glowAlpha > 0xFF) {
            glowAlpha = 0xFF;
            light->glowAlphaStep = 0;
        }
        state->light->glowAlpha = glowAlpha;
    }
}

void DIMLogFire_init(GameObject* obj, const DimLogFirePlacement* placement) {
    int radius;
    DimLogFireState* state;

    obj->animEventCallback = DIMLogFire_SeqFn;
    objAddObjectType(obj, DIM_LOG_FIRE_OBJECT_GROUP);
    state = obj->extra;
    state->unknown20 = 0;
    state->initialMode = placement->initialMode;
    state->remainingStrength = (s8)placement->initialStrength;
    state->initialStrength = *(u8*)&state->remainingStrength;
    if (mainGetBit(placement->douseGameBit) != 0) {
        state->mode = DIM_LOG_FIRE_MODE_LIT;
        state->transitionLatch = 1;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->flickerTimerA = 10.0f;
    state->flickerTimerB = 1.0f;
    if (state->light == NULL) {
        state->light = objCreateLight(obj, 1);
    }
    if (state->light != NULL) {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(state->light, 0xff, 0x7f, 0, 0xff);
        radius = (int)(20.0f * obj->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(state->light, radius, 30.0f + radius);
        modelLightStruct_setEnabled(state->light, 1, 0.0f);
        modelLightStruct_setPosition(state->light, 0.0f, 12.0f, 0.0f);
        modelLightStruct_startColorFade(state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor(state->light, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(state->light, 0, 0xff, 0x7f, 0, 0x87, 40.0f * obj->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(state->light, 30.0f);
    }
}

ObjectDescriptor gDIMLogFireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DIMLogFire_init,
    (ObjectDescriptorCallback)DIMLogFire_update,
    0,
    (ObjectDescriptorCallback)DIMLogFire_render,
    (ObjectDescriptorCallback)DIMLogFire_free,
    (ObjectDescriptorCallback)DIMLogFire_getObjectTypeId,
    DIMLogFire_getExtraSize,
};
