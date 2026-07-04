/*
 * DLL 0x54 - CameraModeNpcSpeak
 *
 * Camera mode used while the player talks to an NPC. dll_54_init allocates the
 * mode-54 state (mmAlloc), snaps the camera onto the optional source camera and
 * records the starting pose for the transition. dll_54_update locates the
 * look-at object (seqId 0x2AB) and origin object (seqId 0x4DC), frames the
 * player between them, derives FOV/height/yaw/pitch from the configured curve
 * constants, eases the camera from its start pose over transitionTimer, then
 * transforms the result into the camera's local space. The exit flag switches
 * back to camera mode 0x42.
 *
 * Also hosts the shared force-behind / cloud-runner camera no-op and free
 * callbacks referenced from the sibling camera-mode DLLs, plus two drifted
 * helpers (FUN_8010de18_v11_drift, FUN_801115e0) that the camera DLLs call.
 */
#include "main/mm.h"
#include "main/camera_object.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camera_mode_54_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/dll/VF/vf_shared.h"
#include "string.h"
#include "main/object_transform.h"
#include "main/objlib.h"
extern f32 sqrtf(f32 x);
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;
extern CameraMode54State* gCameraModeNpcSpeakState;
extern f32 lbl_803E1B5C;
extern CameraModeCloudRunnerState* lbl_803DD5B8;

extern f32 lbl_803E1B40;
extern f32 lbl_803E1B44;
extern f32 lbl_803E1B48;
extern f32 lbl_803E1B4C;
extern f32 lbl_803E1B50;
extern f32 lbl_803E1B54;
extern f32 lbl_803E1B58;
extern f32 lbl_803E1B60;
extern f32 lbl_803E1B64;
extern const f32 lbl_803E1B68;

#pragma scheduling on
#pragma peephole on
#pragma scheduling off
#pragma peephole off
void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void dll_54_func06_nop(void)
{
}

void dll_54_release_nop(void)
{
}

void dll_54_initialise_nop(void)
{
}

void dll_54_init(int* p1, int unused, int* p3)
{
    CameraObject* camera = (CameraObject*)p1;
    CameraObject* source = (CameraObject*)p3;

    if (gCameraModeNpcSpeakState == NULL)
    {
        gCameraModeNpcSpeakState = (CameraMode54State*)mmAlloc(sizeof(CameraMode54State), 15, 0);
    }
    memset(gCameraModeNpcSpeakState, 0, sizeof(CameraMode54State));
    gCameraModeNpcSpeakState->transitionTimer = lbl_803E1B5C;
    gCameraModeNpcSpeakState->transitionDone = 0;
    if (p3 != NULL)
    {
        camera->anim.localPosX = source->anim.worldPosX;
        camera->anim.localPosY = source->anim.worldPosY;
        camera->anim.localPosZ = source->anim.worldPosZ;
        camera->anim.rotX = source->anim.rotX;
        camera->anim.rotY = source->anim.rotY;
        camera->anim.rotZ = source->anim.rotZ;
        camera->fov = source->fov;
    }
    gCameraModeNpcSpeakState->startX = camera->anim.worldPosX;
    gCameraModeNpcSpeakState->startY = camera->anim.worldPosY;
    gCameraModeNpcSpeakState->startZ = camera->anim.worldPosZ;
    gCameraModeNpcSpeakState->startYaw = camera->anim.rotX;
    gCameraModeNpcSpeakState->startPitch = camera->anim.rotY;
    gCameraModeNpcSpeakState->startRoll = camera->anim.rotZ;
}

void dll_54_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)gCameraModeNpcSpeakState);
    gCameraModeNpcSpeakState = NULL;
}

void dll_54_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    int i;
    int count;
    f32 zz, xx;
    f32 dx, dy, dz;
    f32 dist;
    f32 nx, nz;
    f32 fx, fz;
    f32 d2, h, t;
    f32 t2;
    f32 lim;
    s16 cur;
    s16 d;

    if (gCameraModeNpcSpeakState->exitRequested != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    else
    {
        if (gCameraModeNpcSpeakState->lookAtObj == NULL)
        {
            int* arr = (int*)ObjList_GetObjects(&i, &count);
            for (; i < count; i++)
            {
                GameObject* o = (GameObject*)arr[i];
                if (o->anim.seqId == 0x2ab)
                {
                    gCameraModeNpcSpeakState->lookAtObj = o;
                }
                else if (o->anim.seqId == 0x4dc)
                {
                    gCameraModeNpcSpeakState->originObj = o;
                }
            }
        }
        if (gCameraModeNpcSpeakState->playerObj == NULL)
        {
            gCameraModeNpcSpeakState->playerObj = (GameObject*)Obj_GetPlayerObject();
        }
        {
            GameObject* a = gCameraModeNpcSpeakState->lookAtObj;
            dx = a->anim.worldPosX - gCameraModeNpcSpeakState->originObj->anim.worldPosX;
            dy = a->anim.worldPosY - gCameraModeNpcSpeakState->originObj->anim.worldPosY;
            dz = a->anim.worldPosZ - gCameraModeNpcSpeakState->originObj->anim.worldPosZ;
        }
        zz = dz * dz;
        xx = dx * dx;
        dist = sqrtf(zz + (dy * dy + xx));
        nx = dx / dist;
        nz = dz / dist;
        fx = -(lbl_803E1B40 * nx - gCameraModeNpcSpeakState->originObj->anim.worldPosX) -
            gCameraModeNpcSpeakState->playerObj->anim.worldPosX;
        fz = -(lbl_803E1B40 * nz - gCameraModeNpcSpeakState->originObj->anim.worldPosZ) -
            gCameraModeNpcSpeakState->playerObj->anim.worldPosZ;
        d2 = sqrtf(fx * fx + fz * fz);
        t = (lbl_803E1B44 - d2) / lbl_803E1B44;
        camera->fov = lbl_803E1B4C * t + lbl_803E1B48;
        h = lbl_803E1B54 * t + lbl_803E1B50;
        camera->anim.worldPosX = -(nx * h - gCameraModeNpcSpeakState->originObj->anim.worldPosX);
        camera->anim.worldPosY =
            lbl_803E1B5C * t + (lbl_803E1B58 + gCameraModeNpcSpeakState->originObj->anim.worldPosY);
        camera->anim.worldPosZ = -(nz * h - gCameraModeNpcSpeakState->originObj->anim.worldPosZ);
        camera->anim.rotX = -getAngle(dx, dz);
        camera->anim.rotY =
            -getAngle(-(lbl_803E1B60 * (dist / lbl_803E1B64) - dy), sqrtf(xx + zz));

        if (gCameraModeNpcSpeakState->transitionDone == 0)
        {
            t2 = gCameraModeNpcSpeakState->transitionTimer / lbl_803E1B5C;
            camera->anim.worldPosX =
                t2 * (gCameraModeNpcSpeakState->startX - camera->anim.worldPosX) + camera->anim.worldPosX;
            camera->anim.worldPosY =
                t2 * (gCameraModeNpcSpeakState->startY - camera->anim.worldPosY) + camera->anim.worldPosY;
            camera->anim.worldPosZ =
                t2 * (gCameraModeNpcSpeakState->startZ - camera->anim.worldPosZ) + camera->anim.worldPosZ;

            cur = camera->anim.rotX;
            d = (s16)(gCameraModeNpcSpeakState->startYaw - (u16)cur);
            if (d > 0x8000)
            {
                d = (s16)(d - 0xffff);
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            camera->anim.rotX = d * t2 + cur;

            cur = camera->anim.rotY;
            d = (s16)(gCameraModeNpcSpeakState->startPitch - (u16)cur);
            d = (d > 0x8000) ? (s16)(d - 0xffff) : d;
            d = (d < -0x8000) ? (s16)(d + 0xffff) : d;
            camera->anim.rotY = d * t2 + cur;

            gCameraModeNpcSpeakState->transitionTimer -= timeDelta;
            if (gCameraModeNpcSpeakState->transitionTimer < lbl_803E1B68)
            {
                gCameraModeNpcSpeakState->transitionDone = 1;
                gCameraModeNpcSpeakState->transitionTimer = lbl_803E1B68;
            }
        }
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       *(int*)&camera->anim.parent);
    }
}
