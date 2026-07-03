/*
 * cameramodecloudrunner (DLL 0x0053) - the CloudRunner-flight camera mode
 * handlers (text [0x801101E4-0x801106B4)).
 *
 * The mode keeps a single shared CameraModeCloudRunnerState (lbl_803DD5B8)
 * holding the orbit focus point and radius; init allocates it, free
 * releases it. update() orbits the camera around the target object: it
 * reads the player's aim angles, eases the camera yaw/pitch toward the
 * target's facing, then places the camera at radius*(cos/sin) about a base
 * point derived either from a curve node (when the target's curve tag is
 * 1049) or from the target's world position, and finally transforms the
 * world position back into the target's local frame.
 *
 * Most of the mode's vtable slots are empty no-op stubs.
 *
 * WIP boundary split: fn_80110C80 / fn_80110EC0 fall outside
 * [0x801101E4-0x801106B4); they belong to neighbouring camera-mode TUs and
 * are pending relocation before the header range claim is fully accurate.
 *
 * CameraModeForceBehind_func05_nop / _func06_nop are likewise out of this
 * TU's range (no symbols.txt entry here; canonical defs live in dll_0052 /
 * dll_0051). They are intentional shared vtable no-op stubs replicated across
 * the camera-mode TUs (linker-pick-one), kept here so the mode's vtable is
 * fully populated.
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/player_motion.h"
#include "main/vecmath.h"
#include "main/object_transform.h"
#include "main/dll/fx_800944A0_shared.h"


extern int getAngle(float y, float x);
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern int fn_802972A8(int obj);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 lbl_803E1B20;
extern f32 lbl_803E1B24;
extern f32 lbl_803E1B28;
extern f32 lbl_803E1B2C;
extern f32 lbl_803E1B30;
extern f32 lbl_803E1B34;
extern f32 lbl_803DB9D0;
extern int lbl_803DB9D4;

/* curve-node tag selecting the matrix-based base point in update() */
#define CLOUDRUNNER_CURVE_TAG 1049

/* object-placement transform fed to setMatrixFromObjectPos() (24 bytes) */
typedef struct CloudRunnerObjectPos
{
    s16 angles[3];
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CloudRunnerObjectPos;

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void fn_80110C80(void)
{
}

void fn_80110EC0(void)
{
}

void CameraModeCloudRunner_copyToCurrent(void)
{
}

void CameraModeCloudRunner_init(int* camera, int radius, f32* focus)
{
    int* targetObj = ((int**)camera)[0xA4 / 4];
    if (lbl_803DD5B8 == NULL)
    {
        lbl_803DD5B8 = (CameraModeCloudRunnerState*)mmAlloc(sizeof(CameraModeCloudRunnerState), 15, 0);
    }
    {
        f32 r;
        if (focus != NULL)
        {
            lbl_803DD5B8->focusX = focus[0];
            lbl_803DD5B8->focusY = focus[1];
            lbl_803DD5B8->focusZ = focus[2];
            r = focus[3];
        }
        else
        {
            lbl_803DD5B8->focusX = ((GameObject*)targetObj)->anim.worldPosX;
            lbl_803DD5B8->focusY = ((GameObject*)targetObj)->anim.worldPosY;
            lbl_803DD5B8->focusZ = ((GameObject*)targetObj)->anim.worldPosZ;
            r = radius;
        }
        lbl_803DD5B8->radius = r;
    }
    getAngle(
        ((GameObject*)camera)->anim.worldPosX - lbl_803DD5B8->focusX,
        ((GameObject*)camera)->anim.worldPosZ - lbl_803DD5B8->focusZ);
    {
        int* target = ((int**)camera)[0xA4 / 4];
        f32* state = (f32*)lbl_803DD5B8;
        getAngle(
            ((GameObject*)target)->anim.worldPosX - state[0],
            ((GameObject*)target)->anim.worldPosZ - state[2]);
    }
}

void CameraModeCloudRunner_free(void)
{
    mm_free(lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

#pragma opt_propagation off
void CameraModeCloudRunner_update(u8* obj)
{

    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    u8* curve;
    s16 tgtYaw;
    s16 tgtPitch;
    f32 baseX, baseY, baseZ;
    f32 cosYaw, sinYaw, sinPitch, cosPitch;
    f32 radius;
    f32 rx, ry, rs;
    CloudRunnerObjectPos mxin;
    f32 matrix[16];

    Player_GetAimAngles((int)target, &tgtYaw, &tgtPitch);
    curve = (u8*)fn_802972A8((int)target);
    if (curve != NULL)
    {
        if (*(s16*)(curve + 70) == CLOUDRUNNER_CURVE_TAG)
        {
            mxin.x = *(f32*)(curve + 24);
            mxin.y = *(f32*)(curve + 28);
            mxin.z = *(f32*)(curve + 32);
            mxin.angles[0] = *(s16*)(curve + 0);
            mxin.angles[1] = *(s16*)(curve + 2);
            mxin.angles[2] = *(s16*)(curve + 4);
            mxin.scale = lbl_803E1B20;
            setMatrixFromObjectPos(matrix, &mxin);
            Matrix_TransformPoint(matrix, lbl_803E1B24, lbl_803E1B28, lbl_803E1B2C,
                                  &baseX, &baseY, &baseZ);
        }
        else
        {
            baseX = target->anim.worldPosX;
            baseY = target->anim.worldPosY + lbl_803DB9D0;
            baseZ = target->anim.worldPosZ;
        }
    }
    else
    {
        baseX = target->anim.worldPosX;
        baseY = target->anim.worldPosY + lbl_803DB9D0;
        baseZ = target->anim.worldPosZ;
    }

    tgtYaw = (s16)((0x8000 - target->anim.rotX) + tgtYaw);
    tgtYaw = (s16)(tgtYaw - (u16)camera->anim.rotX);
    if (tgtYaw > 0x8000)
    {
        tgtYaw = tgtYaw - 0xffff;
    }
    if (tgtYaw < -0x8000)
    {
        tgtYaw = tgtYaw + 0xffff;
    }
    camera->anim.rotX += tgtYaw;

    tgtPitch = (s16)(tgtPitch - (u16)camera->anim.rotY);
    if (tgtPitch > 0x8000)
    {
        tgtPitch = tgtPitch - 0xffff;
    }
    if (tgtPitch < -0x8000)
    {
        tgtPitch = tgtPitch + 0xffff;
    }
    camera->anim.rotY += tgtPitch;

    camera->anim.rotZ = (s16)(target->anim.rotZ * lbl_803DB9D4);

    cosYaw = mathSinf(lbl_803E1B30 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B34);
    sinYaw = mathCosf(lbl_803E1B30 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B34);
    sinPitch = mathCosf(lbl_803E1B30 * (f32)(s32)camera->anim.rotY / lbl_803E1B34);
    cosPitch = mathSinf(lbl_803E1B30 * (f32)(s32)camera->anim.rotY / lbl_803E1B34);
    radius = lbl_803DD5B8->radius;
    ry = radius * cosPitch;
    rs = radius * sinPitch;
    rx = rs * sinYaw;
    rs = rs * cosYaw;
    camera->anim.worldPosX = baseX + rx;
    camera->anim.worldPosY = baseY + ry;
    camera->anim.worldPosZ = baseZ + rs;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}
#pragma opt_propagation reset

void CameraModeCloudRunner_release(void)
{
}

void CameraModeCloudRunner_initialise(void)
{
}
