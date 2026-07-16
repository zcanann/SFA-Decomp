#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/dll/dll_02B3_vortex.h"
#include "main/gameloop_api.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"

s16 gVortexAngleSpeed83D[4] = {8, 0x10, 0x20, 0};
s16 gVortexAngleSpeedDefault[4] = {0x10, 0x20, 0x40, 0};
f32 gVortexRadiusScaleInit[2] = {1.0f, 1.0f};
f32 gVortexAlphaScaleInit835[2] = {0.2f, 0.2f};
f32 gVortexAlphaScaleInit838[2] = {0.1f, 0.1f};
s16 gVortexAngleSpeed835[2] = {0x40, 0x80};
s16 gVortexRotZTable[2] = {-1024, 1024};

#define VORTEX_OBJFLAG_HITDETECT_DISABLED 0x2000

/* partfx ids emitted per vortex visual variant on the particle-timer tick
   (index-style; roles opaque). A for the 0x835/0x838 seqId form; B for the default form. */
#define VORTEX_PARTFX_A 0x7f7
#define VORTEX_PARTFX_B 0x7c2

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
    int model;
    f32 objZ;
    f32 dt;
    s16 objRotY;
    u8 objAlpha;
    u8 i;
    f32 particleArgs[6];
    u8 hudHidden;

    if (visible == 0)
    {
        return;
    }

    hudHidden = getHudHiddenFrameCount();
    if (hudHidden != 0)
    {
        dt = lbl_803E73D0;
    }
    else
    {
        dt = timeDelta;
    }

    if (state->flags.active == 0 && state->alpha == lbl_803E73D0)
    {
        return;
    }

    if (obj->anim.seqId == 0x835 || obj->anim.seqId == 0x838)
    {
        texture = objFindTexture((GameObject*)obj, 0, 0);
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
                texture->offsetS = (s16)(texture->offsetS - (int)(lbl_803E73D4 * dt));
                if ((f32)texture->offsetS <= lbl_803E73D0)
                {
                    texture->offsetS += 10000;
                }
            }
            else
            {
                texture->offsetS = (s16)(texture->offsetS + (int)(lbl_803E73D4 * dt));
                if (texture->offsetS >= 10000)
                {
                    texture->offsetS -= 10000;
                }
            }
        }

        state->particleTimer = state->particleTimer - dt;
        if (state->particleTimer <= lbl_803E73D0 && hudHidden == 0)
        {
            state->particleTimer = lbl_803E73D8;
            particleArgs[2] = ((f32)setup->radiusParam / gVortexRadiusParamScale) *
                              (obj->anim.rootMotionScale * state->alpha);
            particleArgs[4] = lbl_803E73D0;
            (*gPartfxInterface)->spawnObject((void*)obj, VORTEX_PARTFX_A, particleArgs, 2, -1, NULL);
        }

        model = (int)Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        objRotY = obj->anim.rotX;
        objZ = obj->anim.localPosY;
        for (i = 0; i < 2; i++)
        {
            obj->anim.rotZ = gVortexRotZTable[i];
            obj->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeed835[i];
            obj->anim.rootMotionScale = ((f32)setup->radiusParam / gVortexRadiusParamScale) *
                                        (state->alpha * (state->radiusScale[i] * objScale));
            *((u8*)obj + 0x37) = state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            *(u16*)(model + 0x18) = (u16)(*(u16*)(model + 0x18) & ~8);
            objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = objRotY;
        obj->anim.localPosY = objZ;
    }
    else if (obj->anim.seqId == 0x83d)
    {
        texture = objFindTexture((GameObject*)obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetS = (s16)(texture->offsetS + (int)(lbl_803E73E4 * dt));
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + (int)(lbl_803E73D4 * dt));
        if (texture->offsetS >= 10000)
        {
            texture->offsetS -= 10000;
        }

        model = (int)Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        objRotY = obj->anim.rotX;
        objZ = obj->anim.localPosY;
        for (i = 0; i < 3; i++)
        {
            obj->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeed83D[i];
            obj->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *((u8*)obj + 0x37) = state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 radius = lbl_803E73E8 * state->radiusScale[i];
                obj->anim.localPosY = objZ - radius * state->alpha;
            }
            *(u16*)(model + 0x18) = (u16)(*(u16*)(model + 0x18) & ~8);
            objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = objRotY;
        obj->anim.localPosY = objZ;
    }
    else
    {
        texture = objFindTexture((GameObject*)obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetS = (s16)(texture->offsetS + (int)(lbl_803E73E4 * dt));
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + (int)(lbl_803E73D4 * dt));
        if (texture->offsetS >= 10000)
        {
            texture->offsetS -= 10000;
        }

        particleArgs[2] = obj->anim.rootMotionScale * state->alpha;
        if (hudHidden == 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, VORTEX_PARTFX_B, particleArgs, 2, -1, NULL);
        }

        model = (int)Obj_GetActiveModel(obj);
        objScale = obj->anim.rootMotionScale;
        objAlpha = obj->anim.alpha;
        objRotY = obj->anim.rotX;
        objZ = obj->anim.localPosY;
        for (i = 0; i < 3; i++)
        {
            obj->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeedDefault[i];
            obj->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *((u8*)obj + 0x37) = state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 radius = lbl_803E73EC * state->radiusScale[i];
                obj->anim.localPosY = radius * state->alpha + objZ;
            }
            *(u16*)(model + 0x18) = (u16)(*(u16*)(model + 0x18) & ~8);
            objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        obj->anim.rootMotionScale = objScale;
        obj->anim.alpha = objAlpha;
        obj->anim.rotX = objRotY;
        obj->anim.localPosY = objZ;
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

    if (obj->anim.seqId == 0x29a || obj->anim.seqId == 0x829)
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
        if (state->alpha < lbl_803E73E0)
        {
            f32 hi = lbl_803E73E0;
            state->alpha = gVortexAlphaFadeSpeed * timeDelta + state->alpha;
            if (state->alpha > hi)
            {
                state->alpha = hi;
            }
            return;
        }
    }
    if (active == 0)
    {
        if (state->alpha > lbl_803E73D0)
        {
            f32 lo = lbl_803E73D0;
            state->alpha = state->alpha - gVortexAlphaFadeSpeed * timeDelta;
            if (state->alpha < lo)
            {
                state->alpha = lo;
            }
        }
    }
}

#pragma opt_strength_reduction on
#pragma opt_propagation off
void Vortex_init(GameObject* obj, VortexSetup* setup)
{
    GameObject* o = obj;
    f32(*base)[3] = gVortexScaleParams;
    VortexState* state = o->extra;
    u8 i;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = mainGetBit(setup->activeGameBit);
    }
    if (o->anim.seqId == 0x835)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = gVortexRadiusScaleInit[i];
            state->alphaScale[i] = gVortexAlphaScaleInit835[i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (o->anim.seqId == 0x838)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = gVortexRadiusScaleInit[i];
            state->alphaScale[i] = gVortexAlphaScaleInit838[i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (o->anim.seqId == 0x83d)
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
    o->objectFlags |= VORTEX_OBJFLAG_HITDETECT_DISABLED;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(o), postRenderSetAlphaBlendState);
    if (state->flags.active != 0)
        state->alpha = lbl_803E73E0;
    else
        state->alpha = lbl_803E73D0;
    state->particleTimer = randomGetRange(0, 0x14);
    *(f32*)((int)o + 0x40) = *(f32*)((int)o + 0x40) * lbl_803E7404;
}
#pragma opt_strength_reduction reset
#pragma opt_propagation reset

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
