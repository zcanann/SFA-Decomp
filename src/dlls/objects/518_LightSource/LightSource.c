/* LightSource (DLL 0x0206) - a placeable point-light and flame-effect object. */
#include "dlls/objects/518_LightSource.h"

#include "game/objects/object.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"

/* Arwing-mounted variants use different light positions and effect offsets. */
#define LIGHTSOURCE_SEQID_ARWING_A  0x705
#define LIGHTSOURCE_SEQID_ARWING_B  0x712
#define LIGHTSOURCE_SEQID_ARWING_FX 0x717

#define LIGHTSOURCE_PARTFX_SPARK 0x7cb

const u8 gLightSourceColorTable[16][3] = {
    {0xFF, 0xC0, 0x00}, {0xFF, 0x7F, 0x00}, {0xFF, 0xC0, 0x00}, {0xFF, 0xC0, 0x00},
    {0x00, 0xFF, 0xFF}, {0xFF, 0x00, 0x00}, {0x00, 0xFF, 0x00}, {0xFF, 0xFF, 0x00},
    {0xFF, 0x40, 0x00}, {0xFF, 0xC0, 0x00}, {0x00, 0x7F, 0xFF}, {0xFF, 0xFF, 0x00},
    {0xFF, 0xFF, 0xFF}, {0xFF, 0xFF, 0xFF}, {0xFF, 0xFF, 0xFF}, {0x00, 0x00, 0x00},
};

int lightsource_getExtraSize(void) {
    return sizeof(LightSourceState);
}

int lightsource_getObjectTypeId(void) {
    return 1;
}

void lightsource_free(GameObject* obj) {
    LightSourceState* state = obj->extra;

    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
    }
}

void lightsource_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    ModelLightStruct* light = ((LightSourceState*)obj->extra)->light;

    if (light != NULL && light->glowType != 0 && light->enabled != 0) {
        queueGlowRender(light);
    }
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void lightsource_hitDetect(void) {
}

void lightsource_update(GameObject* obj) {
    LightSourceState* state;
    ModelLightStruct* light;
    s16 glowAlpha;
    int spawnArg;
    f32 effectOffset[3];
    PartFxSpawnParams sparkParams;

    state = obj->extra;
    switch (state->mode) {
    case LIGHTSOURCE_MODE_STATIC:
        break;
    case LIGHTSOURCE_MODE_INTERACTIVE:
        state->litPrev = state->lit;
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) != 0) {
            state->lit = 1 - state->lit;
        }
        if (state->lit != state->litPrev) {
            if (state->lit != 0) {
                if (state->gameBit != -1 && mainGetBit(state->gameBit) == 0) {
                    mainSetBits(state->gameBit, 1);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_cvdrip1c);
            } else {
                (*gExpgfxInterface)->freeSource((u32)obj);
                if (state->gameBit != -1 && mainGetBit(state->gameBit) != 0) {
                    mainSetBits(state->gameBit, 0);
                }
            }
        }
        break;
    }
    if (state->lit != 0 && (obj->objectFlags & OBJECT_OBJFLAG_RENDERED)) {
        state->fxTimer -= timeDelta;
        if (state->fxTimer <= 0.0f) {
            spawnArg = state->fxArg;
            state->fxTimer += 15.0f;
        } else {
            spawnArg = 0;
        }
        if (state->fxType != 0 || state->fxArg != 0) {
            effectOffset[0] = 0.0f;
            if (obj->anim.romDefNo == LIGHTSOURCE_SEQID_ARWING_FX) {
                effectOffset[1] = effectOffset[0];
            } else {
                effectOffset[1] = 3.5f;
            }
            effectOffset[2] = 0.0f;
            objfx_spawnPulseBurst(obj, 10.0f * obj->anim.rootMotionScale, state->fxType, spawnArg, 0, effectOffset);
        }
        if (state->sparks != 0) {
            state->sparkSpawnTimer -= timeDelta;
            if (state->sparkSpawnTimer <= 0.0f) {
                /* The effect only consumes scale; the remaining parameters stay raw. */
                sparkParams.scale = 1.0f;
                (*gPartfxInterface)->spawnObject(obj, LIGHTSOURCE_PARTFX_SPARK, &sparkParams, 2, -1, NULL);
                state->sparkSpawnTimer += 5.0f;
            }
        }
    }
    light = state->light;
    if (light != NULL && light->glowType != 0 && light->enabled != 0) {
        glowAlpha = (s16)(light->glowAlpha + light->glowAlphaStep);
        if (glowAlpha < 0) {
            glowAlpha = 0;
            light->glowAlphaStep = 0;
        } else if (glowAlpha > 255) {
            glowAlpha = 255;
            light->glowAlphaStep = 0;
        }
        state->light->glowAlpha = glowAlpha;
    }
    if (obj->anim.romDefNo != LIGHTSOURCE_SEQID_ARWING_A && obj->anim.romDefNo != LIGHTSOURCE_SEQID_ARWING_B) {
        if (state->lit != 0) {
            if (!state->loopFlags.loopedSound) {
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_mushdizzylp12);
                state->loopFlags.loopedSound = 1;
            }
        } else if (state->loopFlags.loopedSound) {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_mushdizzylp12);
            state->loopFlags.loopedSound = 0;
        }
    }
}

typedef struct LightSourceColorTableView {
    u8 colors[45];
} LightSourceColorTableView;

void lightsource_init(GameObject* obj, const LightSourcePlacementView* placement) {
    LightSourceState* state;
    LightSourceColorTableView colorTable;
    int flags;
    int range;
    int colorBase;

    state = obj->extra;
    colorTable = *(const LightSourceColorTableView*)gLightSourceColorTable;
    obj->anim.rotX = (s16)(((int)placement->yaw & 0x3fU) << 10);
    range = placement->range;
    if (range > 0) {
        obj->anim.rootMotionScale = range / 8192.0f;
    } else {
        obj->anim.rootMotionScale = 0.1f;
    }

    state->mode = placement->mode;
    state->gameBit = placement->gameBit;
    state->fxType = 1;
    if (placement->flags & LIGHTSOURCE_FLAG_FX_ARG_ZERO) {
        state->fxArg = 0;
    } else {
        state->fxArg = 3;
    }
    if (placement->options & LIGHTSOURCE_OPTION_SPARKS) {
        state->sparks = 1;
    } else {
        state->sparks = 0;
    }

    switch (state->mode) {
    case LIGHTSOURCE_MODE_STATIC:
        state->lit = 1;
        flags = placement->flags;
        if (flags & LIGHTSOURCE_FLAG_FX_TYPE_4) {
            state->fxType = 4;
        } else if (flags & LIGHTSOURCE_FLAG_FX_TYPE_8) {
            state->fxType = 8;
        } else if (flags & LIGHTSOURCE_FLAG_FX_TYPE_6) {
            state->fxType = 6;
        } else if (flags & LIGHTSOURCE_FLAG_FX_ARG_6) {
            state->fxArg = 6;
        }
        break;
    }

    if (placement->flags & LIGHTSOURCE_FLAG_CREATE_LIGHT) {
        if (state->light == NULL) {
            state->light = objCreateLight(obj, 1);
            if (state->light != NULL) {
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            }
        }
        if (state->light != NULL) {
            if (obj->anim.romDefNo == LIGHTSOURCE_SEQID_ARWING_A || obj->anim.romDefNo == LIGHTSOURCE_SEQID_ARWING_B) {
                modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);
            } else {
                modelLightStruct_setPosition(state->light, 0.0f, 7.0f, 0.0f);
            }

            colorBase = state->fxType * 3;
            modelLightStruct_setDiffuseColor(state->light, colorTable.colors[colorBase],
                                             colorTable.colors[colorBase + 1], colorTable.colors[colorBase + 2], 0xff);
            colorBase = state->fxType * 3;
            modelLightStruct_setSpecularColor(state->light, colorTable.colors[colorBase],
                                              colorTable.colors[colorBase + 1], colorTable.colors[colorBase + 2], 0xff);
            modelLightStruct_setDistanceAttenuation(state->light, 40.0f, 65.0f);
            modelLightStruct_setEnabled(state->light, 1, 0.0f);
            modelLightStruct_startColorFade(state->light, 1, 3);

            colorBase = state->fxType * 3;
            modelLightStruct_setDiffuseTargetColor(state->light, (int)(0.8f * (f32)(u32)colorTable.colors[colorBase]),
                                                   (int)(0.8f * (f32)(u32)colorTable.colors[colorBase + 1]),
                                                   (int)(0.8f * (f32)(u32)colorTable.colors[colorBase + 2]), 0xff);
            lightSetField4D(state->light, 1);

            if (placement->flags & LIGHTSOURCE_FLAG_CREATE_GLOW) {
                if (obj->anim.romDefNo == LIGHTSOURCE_SEQID_ARWING_A || obj->anim.romDefNo == LIGHTSOURCE_SEQID_ARWING_B) {
                    colorBase = state->fxType * 3;
                    modelLightStruct_setupGlow(state->light, 0, colorTable.colors[colorBase],
                                               colorTable.colors[colorBase + 1], colorTable.colors[colorBase + 2], 0x8c,
                                               0.6f * (250.0f * obj->anim.rootMotionScale));
                } else {
                    colorBase = state->fxType * 3;
                    modelLightStruct_setupGlow(state->light, 0, colorTable.colors[colorBase],
                                               colorTable.colors[colorBase + 1], colorTable.colors[colorBase + 2], 0x8c,
                                               250.0f * obj->anim.rootMotionScale);
                }
                modelLightStruct_setGlowProjectionRadius(state->light, 20.0f);
            }
        }
    } else {
        state->light = NULL;
    }

    if (placement->flags & LIGHTSOURCE_FLAG_DISABLE_FX_TYPE) {
        state->fxType = 0;
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->fxTimer = 15.0f;
    state->unknown08 = 1.0f;
}

void lightsource_release(void) {
}

void lightsource_initialise(void) {
}

ObjectDescriptor gLightSourceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    lightsource_initialise,
    lightsource_release,
    0,
    (ObjectDescriptorCallback)lightsource_init,
    (ObjectDescriptorCallback)lightsource_update,
    lightsource_hitDetect,
    (ObjectDescriptorCallback)lightsource_render,
    (ObjectDescriptorCallback)lightsource_free,
    (ObjectDescriptorCallback)lightsource_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)lightsource_getExtraSize,
};
