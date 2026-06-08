#include "main/dll/dll_80220608_shared.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"

#pragma peephole on
#pragma scheduling on
int vortex_getExtraSize(void) { return 0x28; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int vortex_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vortex_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    VortexState *state = ((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    f32 dt;
    s16 *texture;
    int model;
    f32 objScale;
    f32 objZ;
    u8 objAlpha;
    s16 objRotY;
    u8 i;
    f32 particleArgs[6];
    int hudHidden;

    if (visible == 0) {
        return;
    }

    hudHidden = (u8)getHudHiddenFrameCount();
    if (hudHidden != 0) {
        dt = lbl_803E73D0;
    } else {
        dt = timeDelta;
    }

    if (state->flags.active == 0 && state->alpha == lbl_803E73D0) {
        return;
    }

    if (((GameObject *)obj)->anim.seqId == 0x835 || ((GameObject *)obj)->anim.seqId == 0x838) {
        texture = (s16 *)objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            u8 reverse = *(s16 *)(setup + 0x1c) != 0;
            if (*(s16 *)(setup + 0x1e) != -1 && GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
                reverse = !reverse;
            }
            if (reverse != 0) {
                texture[4] = (s16)(texture[4] - (s16)(int)(lbl_803E73D4 * dt));
                if ((f32)texture[4] <= lbl_803E73D0) {
                    texture[4] = (s16)(texture[4] + 10000);
                }
            } else {
                texture[4] = (s16)(texture[4] + (s16)(int)(lbl_803E73D4 * dt));
                if (texture[4] >= 10000) {
                    texture[4] = (s16)(texture[4] - 10000);
                }
            }
        }

        state->particleTimer = state->particleTimer - dt;
        if (state->particleTimer <= lbl_803E73D0 && hudHidden == 0) {
            state->particleTimer = lbl_803E73D8;
            particleArgs[2] =
                ((f32)*(s16 *)(setup + 0x1a) / lbl_803E73DC) * ((GameObject *)obj)->anim.rootMotionScale * state->alpha;
            particleArgs[4] = lbl_803E73D0;
            (*gPartfxInterface)->spawnObject((void *)obj, 0x7f7, particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject *)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject *)obj)->anim.alpha;
        objRotY = ((GameObject *)obj)->anim.rotX;
        objZ = ((GameObject *)obj)->anim.localPosY;
        for (i = 0; i < 2; i++) {
            ((GameObject *)obj)->anim.rotZ = lbl_803DC414[i];
            ((GameObject *)obj)->anim.rotX = state->angles[i];
            state->angles[i] = (s16)((f32)state->angles[i] + dt * (f32)lbl_803DC410[i]);
            ((GameObject *)obj)->anim.rootMotionScale = ((f32)*(s16 *)(setup + 0x1a) / lbl_803E73DC) * state->alpha *
                                  (state->radiusScale[i] * objScale);
            *(u8 *)(obj + 0x37) =
                (s8)(int)(state->alpha * state->alphaScale[i] * (f32)(u32)objAlpha);
            *(u16 *)(model + 0x18) = (u16)(*(u16 *)(model + 0x18) & ~8);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        ((GameObject *)obj)->anim.rootMotionScale = objScale;
        ((GameObject *)obj)->anim.alpha = objAlpha;
        ((GameObject *)obj)->anim.rotX = objRotY;
        ((GameObject *)obj)->anim.localPosY = objZ;
    } else if (((GameObject *)obj)->anim.seqId == 0x83d) {
        texture = (s16 *)objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture[4] = (s16)(texture[4] + (s16)(int)(lbl_803E73E4 * dt));
        }
        ((GameObject *)obj)->anim.rotX = (s16)(((GameObject *)obj)->anim.rotX + (s16)(int)(lbl_803E73D4 * dt));
        if (texture[4] >= 10000) {
            texture[4] = (s16)(texture[4] - 10000);
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject *)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject *)obj)->anim.alpha;
        objRotY = ((GameObject *)obj)->anim.rotX;
        objZ = ((GameObject *)obj)->anim.localPosY;
        for (i = 0; i < 3; i++) {
            ((GameObject *)obj)->anim.rotX = state->angles[i];
            state->angles[i] = (s16)((f32)state->angles[i] + dt * (f32)lbl_803DC3E8[i]);
            ((GameObject *)obj)->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *(u8 *)(obj + 0x37) =
                (s8)(int)(state->alpha * state->alphaScale[i] * (f32)(u32)objAlpha);
            ((GameObject *)obj)->anim.localPosY = objZ - lbl_803E73E8 * state->radiusScale[i] * state->alpha;
            *(u16 *)(model + 0x18) = (u16)(*(u16 *)(model + 0x18) & ~8);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        ((GameObject *)obj)->anim.rootMotionScale = objScale;
        ((GameObject *)obj)->anim.alpha = objAlpha;
        ((GameObject *)obj)->anim.rotX = objRotY;
        ((GameObject *)obj)->anim.localPosY = objZ;
    } else {
        texture = (s16 *)objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture[4] = (s16)(texture[4] + (s16)(int)(lbl_803E73E4 * dt));
        }
        ((GameObject *)obj)->anim.rotX = (s16)(((GameObject *)obj)->anim.rotX + (s16)(int)(lbl_803E73D4 * dt));
        if (texture[4] >= 10000) {
            texture[4] = (s16)(texture[4] - 10000);
        }

        particleArgs[2] = ((GameObject *)obj)->anim.rootMotionScale * state->alpha;
        if (hudHidden == 0) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x7c2, particleArgs, 2, -1, NULL);
        }

        model = Obj_GetActiveModel(obj);
        objScale = ((GameObject *)obj)->anim.rootMotionScale;
        objAlpha = ((GameObject *)obj)->anim.alpha;
        objRotY = ((GameObject *)obj)->anim.rotX;
        objZ = ((GameObject *)obj)->anim.localPosY;
        for (i = 0; i < 3; i++) {
            ((GameObject *)obj)->anim.rotX = state->angles[i];
            state->angles[i] = (s16)((f32)state->angles[i] + dt * (f32)lbl_803DC3F0[i]);
            ((GameObject *)obj)->anim.rootMotionScale = state->alpha * (state->radiusScale[i] * objScale);
            *(u8 *)(obj + 0x37) =
                (s8)(int)(state->alpha * state->alphaScale[i] * (f32)(u32)objAlpha);
            ((GameObject *)obj)->anim.localPosY = lbl_803E73EC * state->radiusScale[i] * state->alpha + objZ;
            *(u16 *)(model + 0x18) = (u16)(*(u16 *)(model + 0x18) & ~8);
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E73E0);
        }
        ((GameObject *)obj)->anim.rootMotionScale = objScale;
        ((GameObject *)obj)->anim.alpha = objAlpha;
        ((GameObject *)obj)->anim.rotX = objRotY;
        ((GameObject *)obj)->anim.localPosY = objZ;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vortex_init(int obj, int initData)
{
    f32 *base = lbl_8032BE20;
    int state = *(int *)&((GameObject *)obj)->extra;
    u8 i;

    ((VortexFlags *)(state + 0x26))->active = 0;
    if (*(s16 *)(initData + 0x20) != -1) {
        ((VortexFlags *)(state + 0x26))->active = (u8)GameBit_Get(*(s16 *)(initData + 0x20));
    }
    if (((GameObject *)obj)->anim.seqId == 0x835) {
        for (i = 0; i < 2; i++) {
            *(f32 *)(state + i * 4 + 0x14) = lbl_803DC3F8[i];
            *(f32 *)(state + i * 4 + 0x8) = lbl_803DC400[i];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (((GameObject *)obj)->anim.seqId == 0x838) {
        for (i = 0; i < 2; i++) {
            *(f32 *)(state + i * 4 + 0x14) = lbl_803DC3F8[i];
            *(f32 *)(state + i * 4 + 0x8) = lbl_803DC408[i];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (((GameObject *)obj)->anim.seqId == 0x83d) {
        for (i = 0; i < 3; i++) {
            *(f32 *)(state + i * 4 + 0x14) = base[i];
            *(f32 *)(state + i * 4 + 0x8) = base[i + 3];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else {
        for (i = 0; i < 3; i++) {
            *(f32 *)(state + i * 4 + 0x14) = base[i + 6];
            *(f32 *)(state + i * 4 + 0x8) = base[i + 9];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
        if (((VortexFlags *)(state + 0x26))->active != 0) {
            if (*(s16 *)(initData + 0x1e) != -1) {
                ((VortexFlags *)(state + 0x26))->active = !GameBit_Get(*(s16 *)(initData + 0x1e));
            }
        }
    }
    ((GameObject *)obj)->objectFlags |= 0x2000;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    if (((VortexFlags *)(state + 0x26))->active != 0)
        *(f32 *)(state + 0) = lbl_803E73E0;
    else
        *(f32 *)(state + 0) = lbl_803E73D0;
    *(f32 *)(state + 4) = (f32)randomGetRange(0, 0x14);
    *(f32 *)(obj + 0x40) = *(f32 *)(obj + 0x40) * lbl_803E7404;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vortex_update(int obj)
{
    VortexState *state = ((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;

    state->flags.active = 0;
    if (*(s16 *)(setup + 0x20) != -1) {
        state->flags.active = (u8)GameBit_Get(*(s16 *)(setup + 0x20));
    }

    if (((GameObject *)obj)->anim.seqId == 0x29a || ((GameObject *)obj)->anim.seqId == 0x829) {
        if (state->flags.active != 0) {
            if (*(s16 *)(setup + 0x1e) != -1) {
                state->flags.active = !GameBit_Get(*(s16 *)(setup + 0x1e));
            }
        }
    }

    if (state->flags.active != 0) {
        f32 lim = lbl_803E73E0;
        if (state->alpha < lim) {
            state->alpha = lbl_803E7400 * timeDelta + state->alpha;
            if (state->alpha > lim) {
                state->alpha = lim;
            }
        }
    } else {
        f32 lim = lbl_803E73D0;
        if (state->alpha > lim) {
            state->alpha = state->alpha - lbl_803E7400 * timeDelta;
            if (state->alpha < lim) {
                state->alpha = lim;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
