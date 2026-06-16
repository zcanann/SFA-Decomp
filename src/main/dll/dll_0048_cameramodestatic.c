/*
 * cameramodestatic (DLL 0x48) - the "static" camera mode.
 *
 * Locks the camera to a placed static-camera object (class 18) nearest the
 * focus target. The chosen object's placement record supplies the camera's
 * orientation: each of yaw/pitch/roll is either taken straight from the
 * placement defaults (defaultYaw/defaultPitch/defaultRoll) or, when the
 * matching axis flag is set, computed to look toward the focus object. A fov
 * byte and a per-axis flag byte live alongside those defaults. State (the
 * chosen object + active/missing markers) is kept in a single
 * CameraModeStaticState allocated on first init; CameraModeStatic_free
 * releases it.
 */
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camstatic_state.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/objlib.h"

/* placement record for a static-camera object (anim.placementData). */
typedef struct CameraModeStaticPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 setupId;       /* 0x18 */
    u8 pad19[0x1A - 0x19];
    u8 fov;           /* 0x1A */
    u8 axisFlags;     /* 0x1B */
    s16 defaultYaw;   /* 0x1C */
    s16 defaultPitch; /* 0x1E */
    s16 defaultRoll;  /* 0x20 */
    u8 pad22[0x28 - 0x22];
} CameraModeStaticPlacement;

/* placement+0x1b axis flags: set bit = derive that axis from the focus
   object instead of using the placement default. */
#define CAMSTATIC_AXIS_YAW 1
#define CAMSTATIC_AXIS_PITCH 2
#define CAMSTATIC_AXIS_ROLL 4

#define ANGLE_HALF_TURN 0x8000
#define ANGLE_FULL_TURN 0xffff

extern int getAngle(f32 x, f32 z);
extern f32 sqrtf(f32 x);

extern u8 framesThisStep;
extern CameraModeStaticState* lbl_803DD558;
extern f32 lbl_803E1878; /* max search distance sentinel (.sdata2) */

#pragma dont_inline on
void* fn_80109B04(f32 x, f32 y, f32 z, int setupId, int classId)
{
    int* list;
    int i;
    void* best;
    double bestDist;
    int count;
    int* obj;
    int* objects;
    f32 dx, dy, dz;
    f32 yy;
    double dist;

    bestDist = lbl_803E1878;
    best = NULL;
    objects = (int*)ObjGroup_GetObjects(7, &count);
    for (i = 0, list = objects; i < count; i++)
    {
        obj = (int*)*list;
        if (((GameObject*)obj)->anim.classId == classId &&
            ((CameraModeStaticPlacement*)((GameObject*)obj)->anim.placementData)->setupId == setupId)
        {
            dx = x - ((GameObject*)obj)->anim.worldPosX;
            dy = y - ((GameObject*)obj)->anim.worldPosY;
            dz = z - ((GameObject*)obj)->anim.worldPosZ;
            yy = dy * dy;
            dist = sqrtf(yy + dx * dx + dz * dz);
            if (dist < bestDist)
            {
                bestDist = dist;
                best = obj;
            }
        }
        list++;
    }
    return best;
}
#pragma dont_inline reset

void CameraModeStatic_update(short* camObj)
{
    CameraObject* cam = (CameraObject*)camObj;
    int angle;
    int pitch;
    int placement;
    int viewObj;
    f32 dx;
    f32 dy;
    f32 dz;

    if (lbl_803DD558->missingObject != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    else
    {
        viewObj = *(int*)(camObj + 0x52); /* focus GameObject* at +0xA4 (inside the ObjAnimComponent pad) */
        placement = (int)lbl_803DD558->staticObject->anim.placementData;
        if ((*(u8*)(placement + 0x1b) & CAMSTATIC_AXIS_YAW) == 0)
        {
            cam->anim.rotX = ((CameraModeStaticPlacement*)placement)->defaultYaw + ANGLE_HALF_TURN;
        }
        if ((*(u8*)(placement + 0x1b) & CAMSTATIC_AXIS_PITCH) == 0)
        {
            cam->anim.rotY = ((CameraModeStaticPlacement*)placement)->defaultPitch;
        }
        if ((*(u8*)(placement + 0x1b) & CAMSTATIC_AXIS_ROLL) == 0)
        {
            cam->anim.rotZ = ((CameraModeStaticPlacement*)placement)->defaultRoll;
        }
        cam->anim.worldPosX = lbl_803DD558->staticObject->anim.worldPosX;
        cam->anim.worldPosY = lbl_803DD558->staticObject->anim.worldPosY;
        cam->anim.worldPosZ = lbl_803DD558->staticObject->anim.worldPosZ;
        cam->fov = (float)(u32)((CameraModeStaticPlacement*)placement)->fov;
        dx = cam->anim.worldPosX - ((GameObject*)viewObj)->anim.worldPosX;
        dy = cam->anim.worldPosY - ((GameObject*)viewObj)->anim.worldPosY;
        dz = cam->anim.worldPosZ - ((GameObject*)viewObj)->anim.worldPosZ;
        if ((*(u8*)(placement + 0x1b) & CAMSTATIC_AXIS_YAW) != 0)
        {
            angle = getAngle(dx, dz);
            cam->anim.rotX = ANGLE_HALF_TURN - angle;
        }
        if ((*(u8*)(placement + 0x1b) & CAMSTATIC_AXIS_PITCH) != 0)
        {
            pitch = getAngle(dy, sqrtf(dx * dx + dz * dz));
            angle = pitch & 0xffff;
            angle = (angle - (int)((CameraModeStaticPlacement*)placement)->defaultPitch) - (u32)(u16)cam->anim.rotY;
            if (ANGLE_HALF_TURN < angle)
            {
                angle = angle + -ANGLE_FULL_TURN;
            }
            if (angle < -ANGLE_HALF_TURN)
            {
                angle = angle + ANGLE_FULL_TURN;
            }
            cam->anim.rotY = (short)(*(short*)&cam->anim.rotY + ((int)(angle * (u32)framesThisStep) >> 3));
        }
        if ((*(u8*)(placement + 0x1b) & CAMSTATIC_AXIS_ROLL) != 0)
        {
            viewObj = (int)cam->anim.rotZ - (u32)(u16)((GameObject*)viewObj)->anim.rotZ;
            if (ANGLE_HALF_TURN < viewObj)
            {
                viewObj = viewObj + -ANGLE_FULL_TURN;
            }
            if (viewObj < -ANGLE_HALF_TURN)
            {
                viewObj = viewObj + ANGLE_FULL_TURN;
            }
            cam->anim.rotZ = (short)(*(short*)&cam->anim.rotZ + ((int)(viewObj * (u32)framesThisStep) >> 3));
        }
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY,
                                       cam->anim.worldPosZ, &cam->anim.localPosX, &cam->anim.localPosY,
                                       &cam->anim.localPosZ, *(int*)&cam->anim.parent);
    }
}

void CameraModeStatic_init(u8* cam, int p2, int* setupId)
{
    GameObject* target;
    GameObject* best;
    u8* setup;
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 dx;
    f32 dy;
    f32 dz;

    target = ((CameraObject*)cam)->anim.targetObj;
    if (lbl_803DD558 == NULL)
    {
        lbl_803DD558 = (CameraModeStaticState*)mmAlloc(sizeof(CameraModeStaticState), 15, 0);
    }
    lbl_803DD558->active = 1;
    lbl_803DD558->missingObject = 0;
    best = (GameObject*)fn_80109B04(target->anim.worldPosX, target->anim.worldPosY, target->anim.worldPosZ, *setupId, 18);
    if (best == NULL)
    {
        lbl_803DD558->missingObject = 1;
        return;
    }
    lbl_803DD558->staticObject = best;
    setup = (u8*)best->anim.placementData;
    dx = best->anim.worldPosX - target->anim.worldPosX;
    dy = best->anim.worldPosY - target->anim.worldPosY;
    dz = best->anim.worldPosZ - target->anim.worldPosZ;
    if ((((CameraModeStaticPlacement*)setup)->axisFlags & CAMSTATIC_AXIS_YAW) != 0)
    {
        yaw = ANGLE_HALF_TURN - getAngle(dx, dz);
    }
    else
    {
        yaw = ((CameraModeStaticPlacement*)setup)->defaultYaw + ANGLE_HALF_TURN;
    }
    if ((((CameraModeStaticPlacement*)setup)->axisFlags & CAMSTATIC_AXIS_PITCH) != 0)
    {
        pitch = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz)) - ((CameraModeStaticPlacement*)setup)->defaultPitch;
    }
    else
    {
        pitch = ((CameraModeStaticPlacement*)setup)->defaultPitch;
    }
    if ((((CameraModeStaticPlacement*)setup)->axisFlags & CAMSTATIC_AXIS_ROLL) != 0)
    {
        roll = target->anim.rotZ;
    }
    else
    {
        roll = ((CameraModeStaticPlacement*)setup)->defaultRoll;
    }
    {
        f32 fov = (f32)(u32)((CameraModeStaticPlacement*)setup)->fov;
        ((CameraObject*)cam)->anim.worldPosX = best->anim.worldPosX;
        ((CameraObject*)cam)->anim.worldPosY = best->anim.worldPosY;
        ((CameraObject*)cam)->anim.worldPosZ = best->anim.worldPosZ;
        ((CameraObject*)cam)->anim.rotX = yaw;
        ((CameraObject*)cam)->anim.rotY = pitch;
        ((CameraObject*)cam)->anim.rotZ = roll;
        ((CameraObject*)cam)->fov = fov;
    }
    Obj_TransformWorldPointToLocal(((CameraObject*)cam)->anim.worldPosX, ((CameraObject*)cam)->anim.worldPosY,
                                   ((CameraObject*)cam)->anim.worldPosZ,
                                   (f32*)(cam + 12), (f32*)(cam + 16), (f32*)(cam + 20),
                                   *(int*)&((CameraObject*)cam)->anim.parent);
}

void CameraModeStatic_copyToCurrent_nop(void)
{
}

void CameraModeStatic_release(void)
{
}

void CameraModeStatic_initialise(void)
{
}

void CameraModeStatic_free(void)
{
    mm_free(lbl_803DD558);
    lbl_803DD558 = 0;
}
