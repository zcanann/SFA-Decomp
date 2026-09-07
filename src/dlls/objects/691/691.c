#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/model.h"
#include "main/dll/dll_02B3_vortex.h"
#include "main/gameloop_api.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/hud_visibility_api.h"

s16 gVortexAngleSpeed83D[4] = {8, 0x10, 0x20, 0};
s16 gVortexAngleSpeedDefault[4] = {0x10, 0x20, 0x40, 0};
f32 gVortexRadiusScaleInit[2] = {1.0f, 1.0f};
f32 gVortexAlphaScaleInit835[2] = {0.2f, 0.2f};
f32 gVortexAlphaScaleInit838[2] = {0.1f, 0.1f};
s16 gVortexAngleSpeed835[2] = {0x40, 0x80};
s16 gVortexRotZTable[2] = {-1024, 1024};

/* partfx ids emitted per vortex visual variant on the particle-timer tick
   (index-style; roles opaque). A for the WndLiftS/WndLiftC form; B for the default form. */
#define VORTEX_PARTFX_A 0x7f7
#define VORTEX_PARTFX_B 0x7c2

/* the five vortex variants this DLL drives; retail OBJECTS.bin names, all DLL 0x2B3 */
#define VORTEX_OBJ_WNDLIFTS  0x835 /* WndLiftS */
#define VORTEX_OBJ_WNDLIFTC  0x838 /* WndLiftC */
#define VORTEX_OBJ_DIMPIT    0x83d /* DIM_PitVort (name field truncated at 11 chars) */
#define VORTEX_OBJ_SKYVORTC  0x29a /* SkyVortC */
#define VORTEX_OBJ_SKYVORTS  0x829 /* SkyVortS */

#define VORTEX_ZERO                        0.0f
#define VORTEX_TEXTURE_SCROLL_SPEED        128.0f
#define VORTEX_PARTICLE_INTERVAL           20.0f
#define VORTEX_RADIUS_PARAM_SCALE          16384.0f
#define VORTEX_FULL_ALPHA                  1.0f
#define VORTEX_DIMPIT_TEXTURE_SCROLL_SPEED 127.0f
#define VORTEX_DIMPIT_VERTICAL_OFFSET      80.0f
#define VORTEX_DEFAULT_VERTICAL_OFFSET     250.0f
#define VORTEX_ALPHA_FADE_SPEED            0.01f
#define VORTEX_CULL_DISTANCE_SCALE         2.0f

int Vortex_getExtraSize(void)
{
    return 0x28;
}

int Vortex_getObjectTypeId(void)
{
    return 0;
}

void Vortex_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Vortex_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    VortexState* state = obj->extra;
    VortexSetup* setup = (VortexSetup*)obj->anim.placementData;
    f32 objScale;
    ObjTextureRuntimeSlot* texture;
    ObjModel* model;
    f32 objY;
    f32 dt;
    s16 objRotY;
    u8 objAlpha;
    u8 i;
    PartFxSpawnParams particleArgs;
    u8 hudHidden;

    if (visible == 0)
    {
        return;
    }

    hudHidden = getHudHiddenFrameCount();
    if (hudHidden != 0)
    {
        dt = VORTEX_ZERO;
    }
    else
    {
        dt = timeDelta;
    }

    if (state->flags.active == 0 && !state->alpha)
    {
        return;
    }

    if (obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTS || obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTC)
    {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            u8 reverse;
            if (setup->reverseTextureScroll != 0)
                reverse = 1;
            else
                reverse = 0;
            if (setup->invertGameBit != -1 && mainGetBit(setup->invertGameBit) != 0)
            {
                reverse = !reverse;
            }
            if (reverse != 0)
            {
                texture->offsetS = texture->offsetS - (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt);
                if ((f32)texture->offsetS <= VORTEX_ZERO)
                {
                    texture->offsetS += 10000;
                }
            }
            else
            {
                texture->offsetS = texture->offsetS + (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt);
                if (texture->offsetS >= 10000)
                {
                    texture->offsetS -= 10000;
                }
            }
        }

        state->particleTimer -= dt;
        if (state->particleTimer <= VORTEX_ZERO && hudHidden == 0)
        {
            state->particleTimer = VORTEX_PARTICLE_INTERVAL;
            particleArgs.scale = ((f32)setup->radiusParam / VORTEX_RADIUS_PARAM_SCALE) *
                              (obj->anim.rootMotionScale * state->alpha);
            particleArgs.posY = VORTEX_ZERO;
            (*gPartfxInterface)->spawnObject((void*)obj, VORTEX_PARTFX_A, &particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        objRotY = obj->anim.rotX;
        objY = obj->anim.localPosY;
        for (i = 0; i < 2; i++)
        {
            obj->anim.rotZ = gVortexRotZTable[i];
            obj->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeed835[i];
            obj->anim.rootMotionScale = ((f32)setup->radiusParam / VORTEX_RADIUS_PARAM_SCALE) *
                                        (state->alpha * (state->radiusScale[i] * objScale));
            obj->anim.renderAlpha = state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            model->bufferFlags = (u16)(model->bufferFlags & ~8);
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, VORTEX_FULL_ALPHA);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = objRotY;
        obj->anim.localPosY = objY;
    }
    else if (obj->anim.romDefNo == VORTEX_OBJ_DIMPIT)
    {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetS = texture->offsetS + (int)(VORTEX_DIMPIT_TEXTURE_SCROLL_SPEED * dt);
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt));
        if (texture->offsetS >= 10000)
        {
            texture->offsetS -= 10000;
        }

        model = Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        objRotY = obj->anim.rotX;
        objY = obj->anim.localPosY;
        for (i = 0; i < 3; i++)
        {
            obj->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeed83D[i];
            obj->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            obj->anim.renderAlpha = state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 radius = VORTEX_DIMPIT_VERTICAL_OFFSET * state->radiusScale[i];
                obj->anim.localPosY = objY - radius * state->alpha;
            }
            model->bufferFlags = (u16)(model->bufferFlags & ~8);
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, VORTEX_FULL_ALPHA);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = objRotY;
        obj->anim.localPosY = objY;
    }
    else
    {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetS = texture->offsetS + (int)(VORTEX_DIMPIT_TEXTURE_SCROLL_SPEED * dt);
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + (int)(VORTEX_TEXTURE_SCROLL_SPEED * dt));
        if (texture->offsetS >= 10000)
        {
            texture->offsetS -= 10000;
        }

        particleArgs.scale = obj->anim.rootMotionScale * state->alpha;
        if (hudHidden == 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, VORTEX_PARTFX_B, &particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        objRotY = obj->anim.rotX;
        objY = obj->anim.localPosY;
        for (i = 0; i < 3; i++)
        {
            obj->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeedDefault[i];
            obj->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            obj->anim.renderAlpha = state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 radius = VORTEX_DEFAULT_VERTICAL_OFFSET * state->radiusScale[i];
                obj->anim.localPosY = radius * state->alpha + objY;
            }
            model->bufferFlags = (u16)(model->bufferFlags & ~8);
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, VORTEX_FULL_ALPHA);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = objRotY;
        obj->anim.localPosY = objY;
    }
}

void Vortex_hitDetect(void)
{
}

void Vortex_update(GameObject* obj)
{
    VortexState* state = obj->extra;
    VortexSetup* setup = (VortexSetup*)obj->anim.placementData;
    u32 active;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = mainGetBit(setup->activeGameBit);
    }

    if (obj->anim.romDefNo == VORTEX_OBJ_SKYVORTC || obj->anim.romDefNo == VORTEX_OBJ_SKYVORTS)
    {
        if (state->flags.active != 0)
        {
            if (setup->invertGameBit != -1)
            {
                state->flags.active = !mainGetBit(setup->invertGameBit);
            }
        }
    }

    active = state->flags.active;
    if (active != 0)
    {
        if (state->alpha < VORTEX_FULL_ALPHA)
        {
            f32 hi = VORTEX_FULL_ALPHA;
            state->alpha = VORTEX_ALPHA_FADE_SPEED * timeDelta + state->alpha;
            if (state->alpha > hi)
            {
                state->alpha = hi;
            }
            return;
        }
    }
    if (active == 0)
    {
        if (state->alpha > VORTEX_ZERO)
        {
            f32 lo = VORTEX_ZERO;
            state->alpha = state->alpha - VORTEX_ALPHA_FADE_SPEED * timeDelta;
            if (state->alpha < lo)
            {
                state->alpha = lo;
            }
        }
    }
}

static inline u32 Vortex_gameBitState(u32 value)
{
    return value;
}

void Vortex_init(GameObject* obj, VortexSetup* setup)
{
    f32(*base)[3] = gVortexScaleParams;
    VortexState* state = obj->extra;
    u8 i;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = Vortex_gameBitState(mainGetBit(setup->activeGameBit));
    }
    if (obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTS)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = gVortexRadiusScaleInit[i];
            state->alphaScale[i] = gVortexAlphaScaleInit835[i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (obj->anim.romDefNo == VORTEX_OBJ_WNDLIFTC)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = gVortexRadiusScaleInit[i];
            state->alphaScale[i] = gVortexAlphaScaleInit838[i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (obj->anim.romDefNo == VORTEX_OBJ_DIMPIT)
    {
        for (i = 0; i < 3; i++)
        {
            state->radiusScale[i] = base[0][i];
            state->alphaScale[i] = base[1][i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else
    {
        for (i = 0; i < 3; i++)
        {
            state->radiusScale[i] = base[2][i];
            state->alphaScale[i] = base[3][i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
        if (state->flags.active != 0)
        {
            if (setup->invertGameBit != -1)
            {
                state->flags.active = !mainGetBit(setup->invertGameBit);
            }
        }
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    if (state->flags.active != 0)
        state->alpha = VORTEX_FULL_ALPHA;
    else
        state->alpha = VORTEX_ZERO;
    state->particleTimer = randomGetRange(0, 0x14);
    obj->anim.cullDistance2 *= VORTEX_CULL_DISTANCE_SCALE;
}

void Vortex_release(void)
{
}

void Vortex_initialise(void)
{
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
    (ObjectDescriptorCallback)Vortex_initialise,
    (ObjectDescriptorCallback)Vortex_release,
    0,
    (ObjectDescriptorCallback)Vortex_init,
    (ObjectDescriptorCallback)Vortex_update,
    (ObjectDescriptorCallback)Vortex_hitDetect,
    (ObjectDescriptorCallback)Vortex_render,
    (ObjectDescriptorCallback)Vortex_free,
    (ObjectDescriptorCallback)Vortex_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)Vortex_getExtraSize,
};
