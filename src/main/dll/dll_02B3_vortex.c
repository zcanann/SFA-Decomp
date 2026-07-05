#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define VORTEX_OBJFLAG_HITDETECT_DISABLED 0x2000

int vortex_getExtraSize(void) { return 0x28; }

int vortex_getObjectTypeId(void) { return 0; }

void vortex_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void vortex_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    VortexState* state = ((GameObject*)obj)->extra;
    VortexSetup* setup = (VortexSetup*)((GameObject*)obj)->anim.placementData;
    f32 dt;
    ObjTextureRuntimeSlot* texture;
    int model;
    f32 objZ;
    f32 objScale;
    s16 objRotY;
    u8 objAlpha;
    u8 i;
    f32 particleArgs[6];
    u8 hudHidden;
    f32 radiusScaleDiv;

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

    if (((GameObject*)obj)->anim.seqId == 0x835 || ((GameObject*)obj)->anim.seqId == 0x838)
    {
        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            u8 reverse;
            if (setup->reverseTextureScroll != 0)
                reverse = 1;
            else
                reverse = 0;
            if (setup->invertGameBit != -1 && GameBit_Get(setup->invertGameBit) != 0)
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
            particleArgs[2] =
                ((f32)setup->radiusParam / gVortexRadiusParamScale) *
                (((GameObject*)obj)->anim.rootMotionScale * state->alpha);
            particleArgs[4] = lbl_803E73D0;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7f7, particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject*)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject*)obj)->anim.alpha;
        objRotY = ((GameObject*)obj)->anim.rotX;
        objZ = ((GameObject*)obj)->anim.localPosY;
        radiusScaleDiv = gVortexRadiusParamScale;
        for (i = 0; i < 2; i++)
        {
            ((GameObject*)obj)->anim.rotZ = gVortexRotZTable[i];
            ((GameObject*)obj)->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeed835[i];
            ((GameObject*)obj)->anim.rootMotionScale = ((f32)setup->radiusParam / radiusScaleDiv) *
                (state->alpha * (state->radiusScale[i] * objScale));
            *(u8*)(obj + 0x37) =
                state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            *(u16*)(model + 0x18) = (u16)(*(u16*)(model + 0x18) & ~8);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        ((GameObject*)obj)->anim.rootMotionScale = objScale;
        ((GameObject*)obj)->anim.alpha = objAlpha;
        ((GameObject*)obj)->anim.rotX = objRotY;
        ((GameObject*)obj)->anim.localPosY = objZ;
    }
    else if (((GameObject*)obj)->anim.seqId == 0x83d)
    {
        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetS = (s16)(texture->offsetS + (int)(lbl_803E73E4 * dt));
        }
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + (int)(lbl_803E73D4 * dt));
        if (texture->offsetS >= 10000)
        {
            texture->offsetS -= 10000;
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject*)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject*)obj)->anim.alpha;
        objRotY = ((GameObject*)obj)->anim.rotX;
        objZ = ((GameObject*)obj)->anim.localPosY;
        radiusScaleDiv = lbl_803E73E8;
        for (i = 0; i < 3; i++)
        {
            ((GameObject*)obj)->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeed83D[i];
            ((GameObject*)obj)->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *(u8*)(obj + 0x37) =
                state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 r = radiusScaleDiv * state->radiusScale[i];
                ((GameObject*)obj)->anim.localPosY = objZ - r * state->alpha;
            }
            *(u16*)(model + 0x18) = (u16)(*(u16*)(model + 0x18) & ~8);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        ((GameObject*)obj)->anim.rootMotionScale = objScale;
        ((GameObject*)obj)->anim.alpha = objAlpha;
        ((GameObject*)obj)->anim.rotX = objRotY;
        ((GameObject*)obj)->anim.localPosY = objZ;
    }
    else
    {
        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetS = (s16)(texture->offsetS + (int)(lbl_803E73E4 * dt));
        }
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + (int)(lbl_803E73D4 * dt));
        if (texture->offsetS >= 10000)
        {
            texture->offsetS -= 10000;
        }

        particleArgs[2] = ((GameObject*)obj)->anim.rootMotionScale * state->alpha;
        if (hudHidden == 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7c2, particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject*)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject*)obj)->anim.alpha;
        objRotY = ((GameObject*)obj)->anim.rotX;
        objZ = ((GameObject*)obj)->anim.localPosY;
        radiusScaleDiv = lbl_803E73EC;
        for (i = 0; i < 3; i++)
        {
            ((GameObject*)obj)->anim.rotX = state->angles[i];
            state->angles[i] = state->angles[i] + dt * gVortexAngleSpeedDefault[i];
            ((GameObject*)obj)->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *(u8*)(obj + 0x37) =
                state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            {
                f32 r = radiusScaleDiv * state->radiusScale[i];
                ((GameObject*)obj)->anim.localPosY = r * state->alpha + objZ;
            }
            *(u16*)(model + 0x18) = (u16)(*(u16*)(model + 0x18) & ~8);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        ((GameObject*)obj)->anim.rootMotionScale = objScale;
        ((GameObject*)obj)->anim.alpha = objAlpha;
        ((GameObject*)obj)->anim.rotX = objRotY;
        ((GameObject*)obj)->anim.localPosY = objZ;
    }
}

void vortex_hitDetect(void)
{
}

void vortex_init(int obj, int initData)
{
    f32 (*base)[3] = (f32 (*)[3])gVortexScaleParams;
    VortexSetup* setup = (VortexSetup*)initData;
    VortexState* state = ((GameObject*)obj)->extra;
    u8 i;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = GameBit_Get(setup->activeGameBit);
    }
    if (((GameObject*)obj)->anim.seqId == 0x835)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = gVortexRadiusScaleInit[i];
            state->alphaScale[i] = gVortexAlphaScaleInit835[i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (((GameObject*)obj)->anim.seqId == 0x838)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = gVortexRadiusScaleInit[i];
            state->alphaScale[i] = gVortexAlphaScaleInit838[i];
            state->angles[i] = randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (((GameObject*)obj)->anim.seqId == 0x83d)
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
                state->flags.active = !GameBit_Get(setup->invertGameBit);
            }
        }
    }
    ((GameObject*)obj)->objectFlags |= VORTEX_OBJFLAG_HITDETECT_DISABLED;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    if (state->flags.active != 0)
        state->alpha = lbl_803E73E0;
    else
        state->alpha = lbl_803E73D0;
    state->particleTimer = randomGetRange(0, 0x14);
    *(f32*)(obj + 0x40) = *(f32*)(obj + 0x40) * lbl_803E7404;
}

void vortex_update(int obj)
{
    VortexState* state = ((GameObject*)obj)->extra;
    VortexSetup* setup = (VortexSetup*)((GameObject*)obj)->anim.placementData;
    u32 active;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = GameBit_Get(setup->activeGameBit);
    }

    if (((GameObject*)obj)->anim.seqId == 0x29a || ((GameObject*)obj)->anim.seqId == 0x829)
    {
        if (state->flags.active != 0)
        {
            if (setup->invertGameBit != -1)
            {
                state->flags.active = !GameBit_Get(setup->invertGameBit);
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

void vortex_release(void)
{
}

void vortex_initialise(void)
{
}

f32 gVortexScaleParams[] = {
    0.8f, 1.0f, 1.2f, 0.7f,
    0.8f, 0.9f, 1.0f, 1.2f,
    1.4f, 0.6f, 0.4f, 0.2f,
};
