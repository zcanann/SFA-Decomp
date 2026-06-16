#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

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
    f32 objScale;
    f32 objZ;
    u8 objAlpha;
    s16 objRotY;
    u8 i;
    f32 particleArgs[6];
    u8 hudHidden;

    if (visible == 0)
    {
        return;
    }

    hudHidden = (u8)getHudHiddenFrameCount();
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
            u8 reverse = setup->reverseTextureScroll != 0 ? 1 : 0;
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
                ((f32)setup->radiusParam / lbl_803E73DC) *
                (((GameObject*)obj)->anim.rootMotionScale * state->alpha);
            particleArgs[4] = lbl_803E73D0;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7f7, particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject*)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject*)obj)->anim.alpha;
        objRotY = ((GameObject*)obj)->anim.rotX;
        objZ = ((GameObject*)obj)->anim.localPosY;
        for (i = 0; i < 2; i++)
        {
            ((GameObject*)obj)->anim.rotZ = lbl_803DC414[i];
            ((GameObject*)obj)->anim.rotX = state->angles[i];
            state->angles[i] = (f32)state->angles[i] + dt * (f32)lbl_803DC410[i];
            ((GameObject*)obj)->anim.rootMotionScale = ((f32)setup->radiusParam / lbl_803E73DC) * state->alpha *
                (state->radiusScale[i] * objScale);
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
        for (i = 0; i < 3; i++)
        {
            ((GameObject*)obj)->anim.rotX = state->angles[i];
            state->angles[i] = (f32)state->angles[i] + dt * (f32)lbl_803DC3E8[i];
            ((GameObject*)obj)->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *(u8*)(obj + 0x37) =
                state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            ((GameObject*)obj)->anim.localPosY = objZ - lbl_803E73E8 * state->radiusScale[i] * state->alpha;
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
        for (i = 0; i < 3; i++)
        {
            ((GameObject*)obj)->anim.rotX = state->angles[i];
            state->angles[i] = (f32)state->angles[i] + dt * (f32)lbl_803DC3F0[i];
            ((GameObject*)obj)->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *(u8*)(obj + 0x37) =
                state->alpha * (state->alphaScale[i] * (f32)(u32)objAlpha);
            ((GameObject*)obj)->anim.localPosY = lbl_803E73EC * state->radiusScale[i] * state->alpha + objZ;
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
    f32* base = lbl_8032BE20;
    VortexSetup* setup = (VortexSetup*)initData;
    VortexState* state = ((GameObject*)obj)->extra;
    u8 i;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = (u8)GameBit_Get(setup->activeGameBit);
    }
    if (((GameObject*)obj)->anim.seqId == 0x835)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = lbl_803DC3F8[i];
            state->alphaScale[i] = lbl_803DC400[i];
            state->angles[i] = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (((GameObject*)obj)->anim.seqId == 0x838)
    {
        for (i = 0; i < 2; i++)
        {
            state->radiusScale[i] = lbl_803DC3F8[i];
            state->alphaScale[i] = lbl_803DC408[i];
            state->angles[i] = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else if (((GameObject*)obj)->anim.seqId == 0x83d)
    {
        for (i = 0; i < 3; i++)
        {
            state->radiusScale[i] = base[i];
            state->alphaScale[i] = base[i + 3];
            state->angles[i] = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    }
    else
    {
        for (i = 0; i < 3; i++)
        {
            state->radiusScale[i] = base[i + 6];
            state->alphaScale[i] = base[i + 9];
            state->angles[i] = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
        if (state->flags.active != 0)
        {
            if (setup->invertGameBit != -1)
            {
                state->flags.active = !GameBit_Get(setup->invertGameBit);
            }
        }
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    if (state->flags.active != 0)
        state->alpha = lbl_803E73E0;
    else
        state->alpha = lbl_803E73D0;
    state->particleTimer = (f32)randomGetRange(0, 0x14);
    *(f32*)(obj + 0x40) = *(f32*)(obj + 0x40) * lbl_803E7404;
}

void vortex_update(int obj)
{
    VortexState* state = ((GameObject*)obj)->extra;
    VortexSetup* setup = (VortexSetup*)((GameObject*)obj)->anim.placementData;

    state->flags.active = 0;
    if (setup->activeGameBit != -1)
    {
        state->flags.active = (u8)GameBit_Get(setup->activeGameBit);
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

    if (state->flags.active != 0)
    {
        f32 lim = lbl_803E73E0;
        if (state->alpha < lim)
        {
            state->alpha = lbl_803E7400 * timeDelta + state->alpha;
            if (state->alpha > lim)
            {
                state->alpha = lim;
            }
        }
    }
    else
    {
        f32 lim = lbl_803E73D0;
        if (state->alpha > lim)
        {
            state->alpha = state->alpha - lbl_803E7400 * timeDelta;
            if (state->alpha < lim)
            {
                state->alpha = lim;
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
