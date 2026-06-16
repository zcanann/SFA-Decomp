/*
 * DLL 0x0052 (cameramodeforcebehind) - "force behind" camera mode handlers
 * 0x8010FC74..0x801101E4. Init seeds the camera's orbit radius from the
 * target's facing, then update keeps the camera locked behind the target:
 * it eases yaw/pitch toward the target's aim angles, re-derives the orbit
 * position, traces against geometry (camcontrol_traceFromTarget) and converts
 * the result back to the target's local space. The empty release/free/copy
 * stubs are the mode's vtable no-ops. fn_801101E8 (at 0x801101E8) is a related
 * free-function just past the mode's range that frees the shared cloudrunner
 * state (lbl_803DD5B8).
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/player_motion.h"

extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
/* called as (f32 from[3], GameObject *target, f32 to[3], void *out); out is f32* or s16* per site */
extern void camcontrol_traceFromTarget();
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx);

extern f32 timeDelta;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern f32 lbl_803E1B00; /* binary-angle -> radians scale (numerator) */
extern f32 lbl_803E1B04; /* binary-angle -> radians divisor (half-circle = 0x8000) */
extern f32 lbl_803E1B08; /* camera height offset above the target */
extern f32 lbl_803E1B1C; /* default orbit radius (when no override is supplied) */
extern f32 lbl_803DB9C8; /* orbit radius */
extern f32 lbl_803DD5AC; /* active height offset */
extern f32 lbl_803DD5B0; /* derived horizontal trace distance */
extern f32 lbl_803DD5A8; /* derived orbit radius used to place the camera */
extern f32 lbl_803E1B18; /* yaw/pitch ease rate fed to interpolate() */

void CameraModeForceBehind_func06_nop(void);
void CameraModeForceBehind_func05_nop(void);
void CameraModeForceBehind_release(void);
void CameraModeForceBehind_initialise(void);
void CameraModeForceBehind_copyToCurrent(void);
void CameraModeForceBehind_free(void);
void fn_801101E8(void);
void CameraModeForceBehind_init(u8* obj, int p2, f32* p3);
void CameraModeForceBehind_update(u8* obj);

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void)
{
}

void CameraModeForceBehind_initialise(void)
{
}

void CameraModeForceBehind_copyToCurrent(void)
{
}

void CameraModeForceBehind_free(void)
{
}

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57: u32 form needed for codegen; mm.h declares void* */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeForceBehind_init(u8* obj, int p2, f32* p3)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 angle;
    f32 cosv, sinv;
    f32 baseX, baseZ;
    f32 pos[3];
    f32 extra;
    f32 dx, dz;

    {
        int a = target->anim.rotX;
        angle = lbl_803E1B00 * (f32)a / lbl_803E1B04;
    }
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    pos[0] = cosv * lbl_803DB9C8 + (baseX = target->anim.worldPosX);
    pos[1] = lbl_803E1B08 + target->anim.worldPosY;
    baseZ = target->anim.worldPosZ;
    pos[2] = sinv * lbl_803DB9C8 + baseZ;
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    dx = pos[0] - baseX;
    dz = pos[2] - baseZ;
    lbl_803DD5B0 = sqrtf(dx * dx + dz * dz);
    if (p3 != NULL)
    {
        lbl_803DB9C8 = p3[0];
        lbl_803DD5AC = p3[1];
    }
    else
    {
        lbl_803DB9C8 = lbl_803E1B1C;
        lbl_803DD5AC = lbl_803E1B08;
    }
}

void CameraModeForceBehind_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    s16 extra;
    s16 pitch;
    s16 yaw;
    f32 pos[3];
    f32 angle;
    f32 cosv, sinv;
    f32 sx, sz;
    f32 baseX, baseY, baseZ;
    f32 cosYaw, sinYaw, sinPitch, cosPitch;
    f32 radius;

    angle = lbl_803E1B00 * (f32)(0x8000 - camera->anim.rotX) / lbl_803E1B04;
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    sx = target->anim.worldPosX;
    pos[0] = cosv * lbl_803DB9C8 + sx;
    pos[1] = lbl_803E1B08 + target->anim.worldPosY;
    sz = target->anim.worldPosZ;
    pos[2] = sinv * lbl_803DB9C8 + sz;
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    lbl_803DD5A8 = lbl_803DD5B0 = sqrtf((pos[0] - sx) * (pos[0] - sx) + (pos[2] - sz) * (pos[2] - sz));

    Player_GetAimAngles((int)target, &yaw, &pitch);
    yaw = (s16)((0x8000 - target->anim.rotX) + (yaw >> 1));
    pitch = (s16)(pitch >> 1);
    baseX = target->anim.worldPosX;
    baseY = target->anim.worldPosY + lbl_803DD5AC;
    baseZ = target->anim.worldPosZ;

    yaw = (s16)(yaw - (u16)camera->anim.rotX);
    if (yaw > 0x8000)
    {
        yaw -= 0xffff;
    }
    if (yaw < -0x8000)
    {
        yaw += 0xffff;
    }
    camera->anim.rotX = (s16)(s32)((f32)(s32)camera->anim.rotX + interpolate((f32)yaw, lbl_803E1B18, timeDelta));

    pitch = (s16)(pitch - (u16)camera->anim.rotY);
    if (pitch > 0x8000)
    {
        pitch -= 0xffff;
    }
    if (pitch < -0x8000)
    {
        pitch += 0xffff;
    }
    camera->anim.rotY = (s16)(s32)((f32)(s32)camera->anim.rotY +
                                   interpolate((f32)pitch, lbl_803E1B18, timeDelta));

    cosYaw = mathSinf(lbl_803E1B00 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B04);
    sinYaw = mathCosf(lbl_803E1B00 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B04);
    sinPitch = mathCosf(lbl_803E1B00 * (f32)(s32)camera->anim.rotY / lbl_803E1B04);
    cosPitch = mathSinf(lbl_803E1B00 * (f32)(s32)camera->anim.rotY / lbl_803E1B04);
    radius = lbl_803DD5A8;
    camera->anim.worldPosX = baseX + radius * sinPitch * sinYaw;
    camera->anim.worldPosY = baseY + radius * cosPitch;
    camera->anim.worldPosZ = baseZ + radius * sinPitch * cosYaw;
    camcontrol_traceFromTarget(&camera->anim.worldPosX, target, &camera->anim.worldPosX, &camera->anim.rotY);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}
