/*
 * DLL 0x004F - camera mode 4F (curve-driven boss/cutscene framing).
 * Tiny camera-mode handler living at [0x8010F2F8-0x8010F540).
 *
 * Holds a single blend factor (CameraMode4FState.blendProgress) that
 * ramps each frame. dll_4F_update evaluates a Hermite curve on that
 * factor to derive a framing height, then orbits the camera around its
 * target object: yaw is anchored to (0x8000 - target rotX) plus a
 * curve-scaled offset, position is laid out on a circle of fixed radius
 * with a height bias, and the camera pitch/roll/fov are pinned to mode
 * constants. dll_4F_init lazily allocates the state block; dll_4F_func05
 * frees it. func06/release/initialise are no-ops for this mode.
 *
 * All tunables come from the lbl_803E1A88..lbl_803E1AB4 constant block.
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_4f_state.h"
#include "main/game_object.h"

extern CameraMode4FState* lbl_803DD590;

extern f32 Curve_EvalHermite(f32* pts, int mode, f32 t); /* #57 */
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 timeDelta;

extern f32 lbl_803E1A88;
extern f32 lbl_803E1A8C;
extern f32 lbl_803E1A90;
extern f32 lbl_803E1A94;
extern f32 lbl_803E1A98;
extern const f32 lbl_803E1A9C;
extern const f32 lbl_803E1AA0;
extern const f32 lbl_803E1AA4;
extern f32 lbl_803E1AA8;
extern f32 lbl_803E1AAC;
extern f32 lbl_803E1AB0;
extern f32 lbl_803E1AB4;

#pragma scheduling off /* file-wide */
#pragma peephole off
void dll_4F_func06_nop(void)
{
}

void dll_4F_release_nop(void)
{
}

void dll_4F_initialise_nop(void)
{
}

void dll_4F_init(void)
{
    if (lbl_803DD590 == NULL)
    {
        lbl_803DD590 = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    lbl_803DD590->blendProgress = lbl_803E1A88;
}

void dll_4F_update(int* obj)
{
    CameraObject* camera;
    GameObject* target;
    f32 pts[4];
    f32 fz;
    f32 cv;
    f32 sv;
    s16 a;

    camera = (CameraObject*)obj;
    pts[0] = lbl_803E1A88;
    pts[1] = lbl_803E1A8C;
    pts[2] = lbl_803E1A88;
    pts[3] = lbl_803E1A88;
    {
        f32 t0 = lbl_803DD590->blendProgress;
        fz = Curve_EvalHermite(pts, 0, t0);
    }
    target = (GameObject*)camera->anim.targetObj;
    {
        s16 a0 = (s16)(0x8000 - target->anim.rotX);
        a = (s16)(a0 + (s32)(lbl_803E1A90 * fz));
    }
    {
        f32 t = (lbl_803E1A94 * (f32)(s32)a) / lbl_803E1A98;
        cv = mathCosf(t);
        sv = mathSinf(t);
    }
    camera->anim.localPosX = target->anim.worldPosX + (lbl_803E1A9C * cv - lbl_803E1AA0 * sv);
    camera->anim.localPosZ = target->anim.worldPosZ + (lbl_803E1A9C * sv + lbl_803E1AA0 * cv);
    camera->anim.localPosY = (lbl_803E1AA4 + target->anim.worldPosY) - lbl_803E1AA8 * fz;
    camera->anim.rotY = (s16)(0x11c6 - (s32)(lbl_803E1AA4 * (lbl_803E1AAC * fz)));
    camera->anim.rotX = (s16)(a + 0x1ffe);
    camera->anim.rotZ = 0;
    camera->letterboxTargetOffset = 0;
    camera->fov = lbl_803E1AB0;
    lbl_803DD590->blendProgress = lbl_803E1AB4 * timeDelta + lbl_803DD590->blendProgress;
    if (lbl_803DD590->blendProgress > *(f32*)&lbl_803E1A8C)
    {
        lbl_803DD590->blendProgress = lbl_803E1A8C;
    }
}

#pragma opt_common_subs off
#pragma opt_common_subs reset

void dll_4F_func05(void)
{
    extern void mm_free(u32); /* #57: this TU declares mm_free(u32) */
    mm_free((u32)lbl_803DD590);
    lbl_803DD590 = NULL;
}
