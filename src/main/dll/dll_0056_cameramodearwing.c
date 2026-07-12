/*
 * DLL 0x56 — camera mode "arwing" [80110E30-801115E4)
 *
 * Camera mode that follows the Arwing flight vehicle. Shared work state lives
 * in the global gCamArwingWork (CameraArwingWork): _init seeds the camera offset
 * and the per-axis input scales from the lbl_803E1Bxx constant table; _update
 * positions the camera from the scaled control input each frame, easing yaw,
 * pitch and roll toward their targets by timeDelta, with special handling when
 * the followed object is dead (aim at the nearest target) or exploding/warping
 * (spin the roll out). _copyToCurrent patches the live work state from an
 * external setter, dispatched on a value kind (position / input angles / one
 * float / two floats).
 *
 * The remaining bodies are the empty camera-mode vtable slots (release / free /
 * initialise / per-mode nops) this DLL leaves unimplemented.
 */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/object_transform.h"
#include "dolphin/mtx/mtx_legacy.h"

typedef struct CameraArwingWork
{
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    f32 basePosX;
    f32 basePosY;
    f32 basePosZ;
    u8 pad18[0x24 - 0x18];
    f32 xScale;
    f32 yScale;
    f32 unk2C;
    f32 initOffsetX;
    f32 initOffsetY;
    f32 posZOffset;
    f32 zEaseDenom;
    f32 zEaseNum;
    f32 yawScale;
    f32 pitchScale;
    f32 rollScale;
    f32 rollRate;
    s16 inputYaw;
    s16 inputPitch;
    s16 inputRoll;
    u8 zScaleNear;
    u8 zScaleFar;
    u8 pad5C[0x5E - 0x5C];
    u8 active;
    u8 pad5F[0x60 - 0x5F];
} CameraArwingWork;

extern f32 gCamArwingWork[];
extern f32 lbl_803E1BA0;
extern f32 lbl_803E1BA4;
extern f32 lbl_803E1BA8;
extern f32 gCamArwingRotEaseScale;
extern f32 gCamArwingRollDecay;
extern f32 lbl_803E1BC0;
extern f32 lbl_803E1BC4;
extern f32 gCamArwingYawScaleDefault;
extern f32 gCamArwingPitchScaleDefault;
extern f32 gCamArwingRollScaleDefault;
extern f32 gCamArwingXScaleDefault;
extern f32 gCamArwingYScaleDefault;
extern f32 lbl_803E1BDC;

#pragma scheduling off
#pragma peephole off
void CameraModeArwing_release(void)
{
}

void CameraModeArwing_initialise(void)
{
}

void CameraModeArwing_free(void)
{
}

void CameraModeArwing_copyToCurrent(void* p1, u32 kind)
{
    if (kind == 12)
    {
        gCamArwingWork[0] = ((f32*)p1)[0];
        gCamArwingWork[1] = ((f32*)p1)[1];
        gCamArwingWork[2] = ((f32*)p1)[2];
        return;
    }
    if (kind == 6)
    {
        ((CameraArwingWork*)gCamArwingWork)->inputYaw = ((s16*)p1)[0];
        ((CameraArwingWork*)gCamArwingWork)->inputPitch = ((s16*)p1)[1];
        ((CameraArwingWork*)gCamArwingWork)->inputRoll = ((s16*)p1)[2];
        return;
    }
    if (kind == 4)
    {
        ((CameraArwingWork*)gCamArwingWork)->posZOffset = ((f32*)p1)[0];
        return;
    }
    ((CameraArwingWork*)gCamArwingWork)->zEaseDenom = ((f32*)p1)[0];
    ((CameraArwingWork*)gCamArwingWork)->zEaseNum = ((f32*)p1)[1];
}

#pragma opt_common_subs off
void CameraModeArwing_init(int* obj, int mode, int unused)
{
    int* a4 = ((int**)obj)[0xA4 / 4];
    char* base;
    f32* p;
    f32 fc2;
    f32 fc;
    if (mode != 1)
    {
        ((CameraArwingWork*)gCamArwingWork)->basePosX = ((GameObject*)a4)->anim.worldPosX;
        ((CameraArwingWork*)gCamArwingWork)->basePosY = ((GameObject*)a4)->anim.worldPosY;
        ((CameraArwingWork*)gCamArwingWork)->basePosZ = ((GameObject*)a4)->anim.worldPosZ;
    }
    *(p = (f32*)((base = (char*)gCamArwingWork) + 48)) = lbl_803E1BA4;
    *(f32*)(base + 52) = lbl_803E1BC0;
    *(f32*)(base + 56) = lbl_803E1BC4;
    PSVECAdd(&((GameObject*)a4)->anim.worldPosX, p, &((GameObject*)obj)->anim.worldPosX);
    ((CameraArwingWork*)gCamArwingWork)->active = 1;
    ((CameraArwingWork*)gCamArwingWork)->yawScale = gCamArwingYawScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->pitchScale = gCamArwingPitchScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->rollScale = gCamArwingRollScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->xScale = gCamArwingXScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->yScale = gCamArwingYScaleDefault;
    fc = lbl_803E1BA4;
    ((CameraArwingWork*)gCamArwingWork)->unk2C = fc;
    fc2 = lbl_803E1BDC;
    ((CameraArwingWork*)gCamArwingWork)->zEaseNum = fc2;
    ((CameraArwingWork*)gCamArwingWork)->zEaseDenom = fc2;
    ((CameraArwingWork*)gCamArwingWork)->zScaleFar = 90;
    ((CameraArwingWork*)gCamArwingWork)->zScaleNear = 100;
    ((CameraArwingWork*)gCamArwingWork)->offsetZ = fc;
    ((CameraArwingWork*)gCamArwingWork)->offsetY = fc;
    ((CameraArwingWork*)gCamArwingWork)->offsetX = fc;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)a4)->anim.worldPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)a4)->anim.worldPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)a4)->anim.worldPosZ + *(f32*)(base + 56);
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_propagation off
void CameraModeArwing_update(u8* obj)
{
    int yaw0, pitch0;
    u8* state = *(u8**)&((GameObject*)obj)->anim.targetObj;
    int angleDelta;

    ((GameObject*)obj)->anim.worldPosX = gCamArwingWork[0] * ((CameraArwingWork*)gCamArwingWork)->xScale;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + ((CameraArwingWork*)gCamArwingWork)->basePosX;
    ((GameObject*)obj)->anim.worldPosY = gCamArwingWork[1] * ((CameraArwingWork*)gCamArwingWork)->yScale;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.worldPosY + ((CameraArwingWork*)gCamArwingWork)->basePosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)state)->anim.worldPosZ + ((CameraArwingWork*)gCamArwingWork)->
        posZOffset;

    if ((s8)state[0xac] != 0x26)
    {
        f32 t = ((CameraArwingWork*)gCamArwingWork)->zEaseNum / ((CameraArwingWork*)gCamArwingWork)->zEaseDenom;
        t = t - lbl_803E1BA0;
        if (t < lbl_803E1BA4)
        {
            ((GameObject*)obj)->anim.worldPosZ =
                (f32) - (s32)((CameraArwingWork*)gCamArwingWork)->zScaleNear * t + ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            ((GameObject*)obj)->anim.worldPosZ =
                (f32) - (s32)((CameraArwingWork*)gCamArwingWork)->zScaleFar * t + ((GameObject*)obj)->anim.worldPosZ;
        }
    }

    yaw0 = (s32)((f32)((CameraArwingWork*)gCamArwingWork)->inputYaw *
        ((CameraArwingWork*)gCamArwingWork)->yawScale);
    pitch0 = (s32)((f32)((CameraArwingWork*)gCamArwingWork)->inputPitch *
        ((CameraArwingWork*)gCamArwingWork)->pitchScale);

    if (arwarwing_isDead((GameObject*)state) != 0)
    {
        f32 va, vb, vc, vd;
        int step;
        CameraArwingWork* work;
        ((CameraArwingWork*)gCamArwingWork)->rollRate = lbl_803E1BA8;
        work = (CameraArwingWork*)gCamArwingWork;
        (*(void (**)(u8*, f32*, f32*, f32*, f32*, f32, int))(*(int*)gCameraInterface + 56))(
            obj, &va, &vb, &vc, &vd, lbl_803E1BA4, 0);
        ((GameObject*)obj)->anim.rotZ = work->rollRate * timeDelta +
            (f32)((GameObject*)obj)->anim.rotZ;
        angleDelta = 0x8000 - (u16)getAngle(va, vc);
        yaw0 = (u16)getAngle(vb, vd);
        angleDelta -= (u16)((GameObject*)obj)->anim.rotX;
        if (angleDelta > 0x8000)
        {
            angleDelta = angleDelta - 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xffff;
        }
        step = (s32)((f32)angleDelta * timeDelta);
        ((GameObject*)obj)->anim.rotX = step * gCamArwingRotEaseScale + (f32) * (s16*)obj;
        angleDelta = yaw0 - (u16)((GameObject*)obj)->anim.rotY;
        if (angleDelta > 0x8000)
        {
            angleDelta = angleDelta - 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xffff;
        }
        step = (s32)((f32)angleDelta * timeDelta);
        ((GameObject*)obj)->anim.rotY = step * gCamArwingRotEaseScale + (f32)((GameObject*)obj)->anim.rotY;
    }
    else if (arwarwing_isExplodingOrWarping((GameObject*)state) != 0)
    {
        f32 nv = ((CameraArwingWork*)gCamArwingWork)->rollRate * gCamArwingRollDecay;
        ((CameraArwingWork*)gCamArwingWork)->rollRate = nv;
        ((GameObject*)obj)->anim.rotZ = nv * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
    }
    else
    {
        f32 step;
        int roll0 = (s32)((f32)((CameraArwingWork*)gCamArwingWork)->inputRoll *
            ((CameraArwingWork*)gCamArwingWork)->rollScale);
        roll0 = roll0 - (u16)((GameObject*)obj)->anim.rotZ;
        if (roll0 > 0x8000)
        {
            roll0 = roll0 - 0xffff;
        }
        if (roll0 < -0x8000)
        {
            roll0 = roll0 + 0xffff;
        }
        step = (f32)roll0 * timeDelta;
        ((GameObject*)obj)->anim.rotZ = step * gCamArwingRotEaseScale + (f32)((GameObject*)obj)->anim.rotZ;
        yaw0 = yaw0 - (u16)((GameObject*)obj)->anim.rotX;
        if (yaw0 > 0x8000)
        {
            yaw0 = yaw0 - 0xffff;
        }
        if (yaw0 < -0x8000)
        {
            yaw0 = yaw0 + 0xffff;
        }
        step = (f32)yaw0 * timeDelta;
        ((GameObject*)obj)->anim.rotX = step * gCamArwingRotEaseScale + (f32) * (s16*)obj;
        pitch0 = pitch0 - (u16)((GameObject*)obj)->anim.rotY;
        if (pitch0 > 0x8000)
        {
            pitch0 = pitch0 - 0xffff;
        }
        if (pitch0 < -0x8000)
        {
            pitch0 = pitch0 + 0xffff;
        }
        step = (f32)pitch0 * timeDelta;
        ((GameObject*)obj)->anim.rotY = step * gCamArwingRotEaseScale + (f32)((GameObject*)obj)->anim.rotY;
    }
    Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                   ((GameObject*)obj)->anim.worldPosZ,
                                   &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosY,
                                   &((GameObject*)obj)->anim.localPosZ,
                                   *(int*)&((GameObject*)obj)->anim.parent);
}
#pragma opt_propagation reset
