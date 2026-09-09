/* Slot 691 renders the WndLift and SkyVort/DIM_PitVort visual variants.
 * Vortex is the internal family name; the generated source identity is 691.
 * Activation fades geometry, opacity and particle scale together. */
#include "dlls/objects/691.h"
#include "game/objects/object.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/model.h"
#include "main/gameloop_api.h"
#include "main/object_render.h"
#include "main/hud_visibility_api.h"

VortexLayerSpeedTable gVortexAngleSpeed83D = {{8, 0x10, 0x20}, {0, 0}};
VortexLayerSpeedTable gVortexAngleSpeedDefault = {{0x10, 0x20, 0x40}, {0, 0}};
f32 gVortexRadiusScaleInit[2] = {1.0f, 1.0f};
f32 gVortexAlphaScaleInit835[2] = {0.2f, 0.2f};
f32 gVortexAlphaScaleInit838[2] = {0.1f, 0.1f};
s16 gVortexAngleSpeed835[2] = {0x40, 0x80};
s16 gVortexRotZTable[2] = {-1024, 1024};

/* WndLift emits on its timer; the default form emits on each visible render
 * while the HUD pause counter is clear. */
#define VORTEX_PARTFX_WIND_LIFT 0x7f7
#define VORTEX_PARTFX_DEFAULT   0x7c2

/* Object IDs; names corroborated by secondary EN rev1 / JP OBJECTS.bin. */
#define VORTEX_OBJ_WNDLIFTS 0x835 /* WndLiftS */
#define VORTEX_OBJ_WNDLIFTC 0x838 /* WndLiftC */
#define VORTEX_OBJ_DIMPIT   0x83d /* DIM_PitVort (name field truncated at 11 chars) */
#define VORTEX_OBJ_SKYVORTC 0x29a /* SkyVortC */
#define VORTEX_OBJ_SKYVORTS 0x829 /* SkyVortS */

#define VORTEX_ZERO                        0.0f
#define VORTEX_TEXTURE_SCROLL_SPEED        128.0f
#define VORTEX_PARTICLE_INTERVAL           20.0f
#define VORTEX_WIND_LIFT_SCALE_DIVISOR     16384.0f
#define VORTEX_FULL_FADE                   1.0f
#define VORTEX_DIMPIT_TEXTURE_SCROLL_SPEED 127.0f
#define VORTEX_DIMPIT_VERTICAL_OFFSET      80.0f
#define VORTEX_DEFAULT_VERTICAL_OFFSET     250.0f
#define VORTEX_ACTIVATION_FADE_SPEED       0.01f
#define VORTEX_CULL_DISTANCE_SCALE         2.0f

int Vortex_getExtraSize(void) {
    return sizeof(VortexState);
}

int Vortex_getObjectTypeId(void) {
    return 0;
}

void Vortex_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Vortex_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    VortexState* state = obj->extra;
    VortexPlacementPrefix* setup = (VortexPlacementPrefix*)obj->anim.placementData;
    f32 objScale;
    ObjTextureRuntimeSlot* texture;
    ObjModel* model;
    f32 objY;
    f32 dt;
    s16 savedRotX;
    u8 objAlpha;
    u8 i;
    PartFxSpawnParams particleArgs;
    u8 hudHidden;

    if (visible == 0) {
        return;
    }

    hudHidden = getHudHiddenFrameCount();
    if (hudHidden != 0) {
        dt = VORTEX_ZERO;
    } else {
        dt = timeDelta;
    }

    if (state->flags.active == 0 && !state->activationFade) {
        return;
    }

    if (obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTS || obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTC) {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            u8 reverse;
            if (setup->reverseTextureScroll != 0) {
                reverse = 1;
            } else {
                reverse = 0;
            }
            if (setup->control.reverseScrollGameBit != -1 && mainGetBit(setup->control.reverseScrollGameBit) != 0) {
                reverse = !reverse;
            }
            if (reverse != 0) {
                texture->offsetS = texture->offsetS - (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt);
                if ((f32)texture->offsetS <= VORTEX_ZERO) {
                    texture->offsetS += 10000;
                }
            } else {
                texture->offsetS = texture->offsetS + (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt);
                if (texture->offsetS >= 10000) {
                    texture->offsetS -= 10000;
                }
            }
        }

        state->particleTimer -= dt;
        if (state->particleTimer <= VORTEX_ZERO && hudHidden == 0) {
            state->particleTimer = VORTEX_PARTICLE_INTERVAL;
            particleArgs.scale = ((f32)setup->windLiftScaleQ14 / VORTEX_WIND_LIFT_SCALE_DIVISOR) *
                                 (obj->anim.rootMotionScale * state->activationFade);
            particleArgs.posY = VORTEX_ZERO;
            (*gPartfxInterface)
                ->spawnObject((void*)obj, VORTEX_PARTFX_WIND_LIFT, &particleArgs, PARTFXFLAG_2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        savedRotX = obj->anim.rotX;
        objY = obj->anim.localPosY;
        for (i = 0; i < 2; i++) {
            obj->anim.rotZ = gVortexRotZTable[i];
            obj->anim.rotX = state->layerAngles[i];
            state->layerAngles[i] = state->layerAngles[i] + dt * gVortexAngleSpeed835[i];
            obj->anim.rootMotionScale = ((f32)setup->windLiftScaleQ14 / VORTEX_WIND_LIFT_SCALE_DIVISOR) *
                                        (state->activationFade * (state->layerScale[i] * objScale));
            obj->anim.renderAlpha = state->activationFade * (state->layerAlphaScale[i] * (f32)(u32)objAlpha);
            model->bufferFlags = (u16)(model->bufferFlags & ~8);
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, VORTEX_FULL_FADE);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = savedRotX;
        obj->anim.localPosY = objY;
    } else if (obj->anim.romDefNo == VORTEX_OBJ_DIMPIT) {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture->offsetS = texture->offsetS + (int)(VORTEX_DIMPIT_TEXTURE_SCROLL_SPEED * dt);
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt));
        /* Retail checks the offset even when objFindTexture returned NULL. */
        if (texture->offsetS >= 10000) {
            texture->offsetS -= 10000;
        }

        model = Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        savedRotX = obj->anim.rotX;
        objY = obj->anim.localPosY;
        for (i = 0; i < 3; i++) {
            obj->anim.rotX = state->layerAngles[i];
            state->layerAngles[i] = state->layerAngles[i] + dt * gVortexAngleSpeed83D.speeds[i];
            obj->anim.rootMotionScale = state->activationFade * (state->layerScale[i] * objScale);
            obj->anim.renderAlpha = state->activationFade * (state->layerAlphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 radius = VORTEX_DIMPIT_VERTICAL_OFFSET * state->layerScale[i];
                obj->anim.localPosY = objY - radius * state->activationFade;
            }
            model->bufferFlags = (u16)(model->bufferFlags & ~8);
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, VORTEX_FULL_FADE);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = savedRotX;
        obj->anim.localPosY = objY;
    } else {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture->offsetS = texture->offsetS + (int)(VORTEX_DIMPIT_TEXTURE_SCROLL_SPEED * dt);
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt));
        /* Retail checks the offset even when objFindTexture returned NULL. */
        if (texture->offsetS >= 10000) {
            texture->offsetS -= 10000;
        }

        particleArgs.scale = obj->anim.rootMotionScale * state->activationFade;
        if (hudHidden == 0) {
            (*gPartfxInterface)->spawnObject((void*)obj, VORTEX_PARTFX_DEFAULT, &particleArgs, PARTFXFLAG_2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        savedRotX = obj->anim.rotX;
        objY = obj->anim.localPosY;
        for (i = 0; i < 3; i++) {
            obj->anim.rotX = state->layerAngles[i];
            state->layerAngles[i] = state->layerAngles[i] + dt * gVortexAngleSpeedDefault.speeds[i];
            obj->anim.rootMotionScale = state->activationFade * (state->layerScale[i] * objScale);
            obj->anim.renderAlpha = state->activationFade * (state->layerAlphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 radius = VORTEX_DEFAULT_VERTICAL_OFFSET * state->layerScale[i];
                obj->anim.localPosY = radius * state->activationFade + objY;
            }
            model->bufferFlags = (u16)(model->bufferFlags & ~8);
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, VORTEX_FULL_FADE);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = savedRotX;
        obj->anim.localPosY = objY;
    }
}

void Vortex_hitDetect(void) {
}

void Vortex_update(GameObject* obj) {
    VortexState* state = obj->extra;
    VortexPlacementPrefix* setup = (VortexPlacementPrefix*)obj->anim.placementData;
    u32 active;

    state->flags.active = 0;
    if (setup->activeGameBit != -1) {
        state->flags.active = mainGetBit(setup->activeGameBit);
    }

    if (obj->anim.romDefNo == VORTEX_OBJ_SKYVORTC || obj->anim.romDefNo == VORTEX_OBJ_SKYVORTS) {
        if (state->flags.active != 0) {
            if (setup->control.suppressActivationGameBit != -1) {
                state->flags.active = !mainGetBit(setup->control.suppressActivationGameBit);
            }
        }
    }

    active = state->flags.active;
    if (active != 0) {
        if (state->activationFade < VORTEX_FULL_FADE) {
            f32 hi = VORTEX_FULL_FADE;
            state->activationFade = VORTEX_ACTIVATION_FADE_SPEED * timeDelta + state->activationFade;
            if (state->activationFade > hi) {
                state->activationFade = hi;
            }
            return;
        }
    }
    if (active == 0) {
        if (state->activationFade > VORTEX_ZERO) {
            f32 lo = VORTEX_ZERO;
            state->activationFade = state->activationFade - VORTEX_ACTIVATION_FADE_SPEED * timeDelta;
            if (state->activationFade < lo) {
                state->activationFade = lo;
            }
        }
    }
}

/* Retain this helper with the matched declaration order. */
static inline u32 Vortex_gameBitState(u32 value) {
    return value;
}

void Vortex_init(GameObject* obj, VortexPlacementPrefix* setup) {
    f32(*base)[3] = gVortexScaleParams;
    VortexState* state = obj->extra;
    u8 i;

    state->flags.active = 0;
    if (setup->activeGameBit != -1) {
        state->flags.active = Vortex_gameBitState(mainGetBit(setup->activeGameBit));
    }
    if (obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTS) {
        for (i = 0; i < 2; i++) {
            state->layerScale[i] = gVortexRadiusScaleInit[i];
            state->layerAlphaScale[i] = gVortexAlphaScaleInit835[i];
            state->layerAngles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTC) {
        for (i = 0; i < 2; i++) {
            state->layerScale[i] = gVortexRadiusScaleInit[i];
            state->layerAlphaScale[i] = gVortexAlphaScaleInit838[i];
            state->layerAngles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (obj->anim.romDefNo == VORTEX_OBJ_DIMPIT) {
        for (i = 0; i < 3; i++) {
            state->layerScale[i] = base[0][i];
            state->layerAlphaScale[i] = base[1][i];
            state->layerAngles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    } else {
        for (i = 0; i < 3; i++) {
            state->layerScale[i] = base[2][i];
            state->layerAlphaScale[i] = base[3][i];
            state->layerAngles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
        if (state->flags.active != 0) {
            if (setup->control.suppressActivationGameBit != -1) {
                state->flags.active = !mainGetBit(setup->control.suppressActivationGameBit);
            }
        }
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    if (state->flags.active != 0) {
        state->activationFade = VORTEX_FULL_FADE;
    } else {
        state->activationFade = VORTEX_ZERO;
    }
    state->particleTimer = randomGetRange(0, 0x14);
    obj->anim.cullDistance2 *= VORTEX_CULL_DISTANCE_SCALE;
}

void Vortex_release(void) {
}

void Vortex_initialise(void) {
}

f32 gVortexScaleParams[4][3] = {
    {0.8f, 1.0f, 1.2f},
    {0.7f, 0.8f, 0.9f},
    {1.0f, 1.2f, 1.4f},
    {0.6f, 0.4f, 0.2f},
};

ObjectDescriptor gVortexObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    Vortex_initialise,
    Vortex_release,
    0,
    (ObjectDescriptorCallback)Vortex_init,
    (ObjectDescriptorCallback)Vortex_update,
    Vortex_hitDetect,
    (ObjectDescriptorCallback)Vortex_render,
    (ObjectDescriptorCallback)Vortex_free,
    (ObjectDescriptorCallback)Vortex_getObjectTypeId,
    Vortex_getExtraSize,
};
