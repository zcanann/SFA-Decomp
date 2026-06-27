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
#include "main/game_object.h"
#include "main/engine_shared.h"

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
    f32 unk30;
    f32 unk34;
    f32 posZOffset;
    f32 unk3C;
    f32 unk40;
    f32 yawScale;
    f32 pitchScale;
    f32 rollScale;
    f32 rollRate;
    s16 inputYaw;
    s16 inputPitch;
    s16 inputRoll;
    u8 unk5A;
    u8 unk5B;
    u8 pad5C[0x5E - 0x5C];
    u8 unk5E;
    u8 pad5F[0x60 - 0x5F];
} CameraArwingWork;

#pragma scheduling on
#pragma peephole on
extern f32 gCamArwingWork[];
extern CameraModeCloudRunnerState* lbl_803DD5B8;
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
extern int arwarwing_isDead(int state);
extern int arwarwing_isExplodingOrWarping(int state);
extern int getAngle(float y, float x);

#pragma scheduling off
#pragma peephole off
void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void fn_801101E4(void)
{
}

void fn_80110C80(void)
{
}

void fn_80110EC0(void)
{
}

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
    ((CameraArwingWork*)gCamArwingWork)->unk3C = ((f32*)p1)[0];
    ((CameraArwingWork*)gCamArwingWork)->unk40 = ((f32*)p1)[1];
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
    ((CameraArwingWork*)gCamArwingWork)->unk5E = 1;
    ((CameraArwingWork*)gCamArwingWork)->yawScale = gCamArwingYawScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->pitchScale = gCamArwingPitchScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->rollScale = gCamArwingRollScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->xScale = gCamArwingXScaleDefault;
    ((CameraArwingWork*)gCamArwingWork)->yScale = gCamArwingYScaleDefault;
    fc = lbl_803E1BA4;
    ((CameraArwingWork*)gCamArwingWork)->unk2C = fc;
    fc2 = lbl_803E1BDC;
    ((CameraArwingWork*)gCamArwingWork)->unk40 = fc2;
    ((CameraArwingWork*)gCamArwingWork)->unk3C = fc2;
    ((CameraArwingWork*)gCamArwingWork)->unk5B = 90;
    ((CameraArwingWork*)gCamArwingWork)->unk5A = 100;
    ((CameraArwingWork*)gCamArwingWork)->offsetZ = fc;
    ((CameraArwingWork*)gCamArwingWork)->offsetY = fc;
    ((CameraArwingWork*)gCamArwingWork)->offsetX = fc;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)a4)->anim.worldPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)a4)->anim.worldPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)a4)->anim.worldPosZ + *(f32*)(base + 56);
}
#pragma opt_common_subs reset

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma opt_common_subs off
#pragma opt_propagation off
void CameraModeArwing_update(u8* obj)
{
    int yaw0, pitch0;
    u8* state = *(u8**)&((GameObject*)obj)->anim.targetObj;
    int d;

    ((GameObject*)obj)->anim.worldPosX = gCamArwingWork[0] * ((CameraArwingWork*)gCamArwingWork)->xScale;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + ((CameraArwingWork*)gCamArwingWork)->basePosX;
    ((GameObject*)obj)->anim.worldPosY = gCamArwingWork[1] * ((CameraArwingWork*)gCamArwingWork)->yScale;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.worldPosY + ((CameraArwingWork*)gCamArwingWork)->basePosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)state)->anim.worldPosZ + ((CameraArwingWork*)gCamArwingWork)->
        posZOffset;

    if ((s8)state[0xac] != 0x26)
    {
        f32 t = ((CameraArwingWork*)gCamArwingWork)->unk40 / ((CameraArwingWork*)gCamArwingWork)->unk3C;
        t = t - lbl_803E1BA0;
        if (t < lbl_803E1BA4)
        {
            ((GameObject*)obj)->anim.worldPosZ =
                (f32) - (s32)((CameraArwingWork*)gCamArwingWork)->unk5A * t + ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            ((GameObject*)obj)->anim.worldPosZ =
                (f32) - (s32)((CameraArwingWork*)gCamArwingWork)->unk5B * t + ((GameObject*)obj)->anim.worldPosZ;
        }
    }

    yaw0 = (s32)((f32)((CameraArwingWork*)gCamArwingWork)->inputYaw *
        ((CameraArwingWork*)gCamArwingWork)->yawScale);
    pitch0 = (s32)((f32)((CameraArwingWork*)gCamArwingWork)->inputPitch *
        ((CameraArwingWork*)gCamArwingWork)->pitchScale);

    if (arwarwing_isDead((int)state) != 0)
    {
        f32 va, vb, vc, vd;
        int step;
        CameraArwingWork* work = (CameraArwingWork*)gCamArwingWork;
        work->rollRate = lbl_803E1BA8;
        (*(void (**)(u8*, f32*, f32*, f32*, f32*, f32, int))(*(int*)gCameraInterface + 56))(
            obj, &va, &vb, &vc, &vd, lbl_803E1BA4, 0);
        ((GameObject*)obj)->anim.rotZ = work->rollRate * timeDelta +
            (f32)((GameObject*)obj)->anim.rotZ;
        d = 0x8000 - (u16)getAngle(va, vc);
        pitch0 = (u16)getAngle(vb, vd);
        d -= (u16)((GameObject*)obj)->anim.rotX;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        step = (s32)((f32)d * timeDelta);
        ((GameObject*)obj)->anim.rotX = step * gCamArwingRotEaseScale + (f32) * (s16*)obj;
        d = pitch0 - (u16)((GameObject*)obj)->anim.rotY;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        step = (s32)((f32)d * timeDelta);
        ((GameObject*)obj)->anim.rotY = step * gCamArwingRotEaseScale + (f32)((GameObject*)obj)->anim.rotY;
    }
    else if (arwarwing_isExplodingOrWarping((int)state) != 0)
    {
        f32 nv = ((CameraArwingWork*)gCamArwingWork)->rollRate * gCamArwingRollDecay;
        ((CameraArwingWork*)gCamArwingWork)->rollRate = nv;
        ((GameObject*)obj)->anim.rotZ = nv * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
    }
    else
    {
        int roll0 = (s32)((f32)((CameraArwingWork*)gCamArwingWork)->inputRoll *
            ((CameraArwingWork*)gCamArwingWork)->rollScale);
        d = roll0 - (u16)((GameObject*)obj)->anim.rotZ;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        ((GameObject*)obj)->anim.rotZ = d * timeDelta * gCamArwingRotEaseScale + (f32)((GameObject*)obj)->anim.rotZ;
        yaw0 = yaw0 - (u16)((GameObject*)obj)->anim.rotX;
        if (yaw0 > 0x8000)
        {
            yaw0 -= 0xffff;
        }
        if (yaw0 < -0x8000)
        {
            yaw0 += 0xffff;
        }
        ((GameObject*)obj)->anim.rotX = yaw0 * timeDelta * gCamArwingRotEaseScale + (f32) * (s16*)obj;
        d = pitch0 - (u16)((GameObject*)obj)->anim.rotY;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        ((GameObject*)obj)->anim.rotY = d * timeDelta * gCamArwingRotEaseScale + (f32)((GameObject*)obj)->anim.rotY;
    }
    Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                   ((GameObject*)obj)->anim.worldPosZ,
                                   &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosY,
                                   &((GameObject*)obj)->anim.localPosZ,
                                   *(int*)&((GameObject*)obj)->anim.parent);
}
#pragma opt_propagation reset
#pragma opt_common_subs reset

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
