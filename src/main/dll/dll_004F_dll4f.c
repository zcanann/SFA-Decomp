/* DLL 0x004F - Camera mode misc handler [0x8010F2F8-0x8010F540). */
#include "main/mm.h"
extern float mathSinf(float x);
extern float mathCosf(float x);
#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_4f_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
extern u32 FUN_80294964();
extern u32 DAT_802c2910;
extern u32 DAT_802c2914;
extern u32 DAT_802c2918;
extern float* DAT_803de1fc;
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E1A88;
extern CameraMode4FState* gCameraMode4FState;
extern f32 Curve_EvalHermite(f32* pts, f32 t, int mode);
extern f32 lbl_803E1A8C;
extern f32 lbl_803E1A90;
extern f32 gCameraMode4FPi;
extern f32 lbl_803E1A98;
extern const f32 lbl_803E1A9C;
extern const f32 lbl_803E1AA0;
extern const f32 lbl_803E1AA4;
extern f32 lbl_803E1AA8;
extern f32 lbl_803E1AAC;
extern f32 lbl_803E1AB0;
extern f32 lbl_803E1AB4;
extern CameraModeCloudRunnerState* lbl_803DD5B8;

void FUN_8010de18_v11_drift(u32 param_1, u32 param_2, float* outPosY, float* outPosZ)
{
    float bias;
    float* config;
    int target;
    double dist;
    double cosA;
    double offZ;
    double dx;
    double offX;
    u64 result;

    result = FUN_8028683c();
    config = DAT_803de1fc;
    target = (int)((u64)result >> 0x20);
    dx = (double)(*(float*)(target + 0x18) - *DAT_803de1fc);
    cosA = (double)(*(float*)(target + 0x20) - DAT_803de1fc[2]);
    dist = FUN_80293900((double)(float)(dx * dx + (double)(float)(cosA * cosA)));
    FUN_80017730();
    offX = (double)((float)(dx * (double)DAT_803de1fc[0x11]) + *config);
    offZ = (double)((float)(cosA * (double)DAT_803de1fc[0x11]) + config[2]);
    cosA = (double)FUN_80293f90();
    dx = (double)FUN_80294964();
    if (dist < (double)DAT_803de1fc[0x10])
    {
        dist = (double)DAT_803de1fc[0x10];
    }
    bias = DAT_803de1fc[4];
    *(float*)result = (float)(cosA * (double)(float)(dist + (double)bias) + offX);
    *outPosY = -(lbl_803E2658 * ((lbl_803E265C + *(float*)(target + 0x1c)) - config[1]) -
        (*(float*)(target + 0x1c) + DAT_803de1fc[0xc]));
    *outPosZ = (float)(dx * (double)(float)(dist + (double)bias) + offZ);
    FUN_80286888();
    return;
}

void FUN_801115e0(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int obj, int state)
{
    u32 active;
    u16* model;
    u32 newChild;
    u32 in_r8;
    u32 in_r9;
    u32 in_r10;
    u16 nameTail;
    u32 name0;
    u32 name4;
    u16 name8;

    name0 = DAT_802c2910;
    name4 = DAT_802c2914;
    name8 = DAT_802c2918;
    if ((*(char*)(state + 0x407) != *(char*)(state + 0x409)) &&
        (((GameObject*)obj)->anim.alpha != 0))
    {
        if (*(int*)&((GameObject*)obj)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)obj)->childObjs[0]);
            *(u32*)&((GameObject*)obj)->childObjs[0] = 0;
        }
        active = FUN_80017ae8();
        if ((active & 0xff) == 0)
        {
            *(u8*)(state + 0x409) = 0;
        }
        else
        {
            if (0 < *(char*)(state + 0x407))
            {
                model = FUN_80017aa4(0x18, (&nameTail)[*(char*)(state + 0x407)]);
                newChild = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, model,
                                     4, 0xff, 0xffffffff, *(u32**)&((GameObject*)obj)->anim.parent, in_r8, in_r9,
                                     in_r10);
                *(u32*)&((GameObject*)obj)->childObjs[0] = newChild;
                *(u16*)(*(int*)&((GameObject*)obj)->childObjs[0] + 0xb0) = ((GameObject*)obj)->objectFlags &
                    7;
            }
            *(u8*)(state + 0x409) = *(u8*)(state + 0x407);
        }
    }
    return;
}

void CameraModeNpcSpeak_release(void);

#pragma scheduling off
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

void CameraModeCrawl_release(void);

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void);

void fn_801101E4(void)
{
}

void CameraModeCloudRunner_release(void);

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void);

void dll_4F_init(void)
{
    if (gCameraMode4FState == NULL)
    {
        gCameraMode4FState = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    gCameraMode4FState->blendProgress = lbl_803E1A88;
}

void dll_4F_update(int* obj)
{
    CameraObject* camera;
    GameObject* target;
    f32 pts[4];
    f32 fz;
    f32 sn;
    f32 cs;
    s16 a;

    camera = (CameraObject*)obj;
    pts[0] = lbl_803E1A88;
    pts[1] = lbl_803E1A8C;
    pts[2] = lbl_803E1A88;
    pts[3] = lbl_803E1A88;
    fz = Curve_EvalHermite(pts, gCameraMode4FState->blendProgress, 0);
    a = (s16)(0x8000 - ((GameObject*)camera->anim.targetObj)->anim.rotX);
    a += (s32)(lbl_803E1A90 * fz);
    target = (GameObject*)camera->anim.targetObj;
    {
        f32 t = (gCameraMode4FPi * (f32)(s32)
        a
        )
        /
        lbl_803E1A98;
        sn = mathCosf(t);
        cs = mathSinf(t);
    }
    camera->anim.localPosX = target->anim.worldPosX + (lbl_803E1A9C * sn - lbl_803E1AA0 * cs);
    camera->anim.localPosZ = target->anim.worldPosZ + (lbl_803E1A9C * cs + lbl_803E1AA0 * sn);
    camera->anim.localPosY = (lbl_803E1AA4 + target->anim.worldPosY) - lbl_803E1AA8 * fz;
    camera->anim.rotY = (s16)(0x11c6 - (s32)(lbl_803E1AA4 * (lbl_803E1AAC * fz)));
    camera->anim.rotX = (s16)(a + 0x1ffe);
    camera->anim.rotZ = 0;
    camera->letterboxTargetOffset = 0;
    camera->fov = lbl_803E1AB0;
    gCameraMode4FState->blendProgress += lbl_803E1AB4 * timeDelta;
    if (gCameraMode4FState->blendProgress > *(f32*)&lbl_803E1A8C)
    {
        gCameraMode4FState->blendProgress = lbl_803E1A8C;
    }
}

void CameraModeCrawl_init(void);

#pragma opt_common_subs off
#pragma opt_common_subs reset

void dll_4F_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)gCameraMode4FState);
    gCameraMode4FState = NULL;
}

void CameraModeCrawl_free(void);

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

#pragma dont_inline on
#pragma dont_inline reset

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */
