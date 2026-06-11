#include "main/dll/CAM/dll_62.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camclimb_state.h"
#include "main/object_transform.h"


extern uint getAngle(f32 dx, f32 dz);
extern void camcontrol_traceMove(f32* from, void* to, f32* out, void* work, int a, int b, int c, f32 radius);

extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern u8 framesThisStep;
extern CameraModeClimbState* lbl_803DD578;
extern f64 lbl_803E1990;
extern f64 lbl_803E1998;
extern f32 timeDelta;
extern f32 lbl_803E19A0;
extern f32 lbl_803E19A4;
extern f32 lbl_803E19A8;
extern f32 lbl_803E19AC;
extern f32 lbl_803E19B0;
extern f32 lbl_803E19B4;

/*
 * --INFO--
 *
 * Function: CameraModeClimb_update
 * EN v1.0 Address: 0x8010D36C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010D608
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeClimb_update(short* camObj)
{
    f32 blend;
    f32 fb;
    f32 hi;
    f32 lo;
    int yawDelta;
    short* viewObj;
    f32 trigValue;
    f32 fd;
    f32 clamped;
    f32 fc;
    f32 dist;
    f32 traceFrom[3];
    f32 traceOut[3];
    undefined auStack176[112];

    viewObj = *(short**)(camObj + 0x52);
    if (lbl_803DD578->transitionTimer != 0)
    {
        lbl_803DD578->transitionTimer -= framesThisStep;
        if (lbl_803DD578->transitionTimer < 0)
        {
            lbl_803DD578->transitionTimer = 0;
        }
        blend = (f32)(s32)(lbl_803DD578->transitionDuration - lbl_803DD578->transitionTimer) /
            (f32)(s32)
        lbl_803DD578->transitionDuration;
        lbl_803DD578->relativePosition =
            blend * (f32)(s32)((u16)lbl_803DD578->targetRelativePosition - (u16)lbl_803DD578->startRelativePosition) +
            (f32)(u32)(u16)
        lbl_803DD578->startRelativePosition;
        lbl_803DD578->targetDistance = blend * (lbl_803DD578->endDistance - lbl_803DD578->startDistance) + lbl_803DD578
            ->startDistance;
        lbl_803DD578->minHeight = blend * (lbl_803DD578->endMinHeight - lbl_803DD578->startMinHeight) + lbl_803DD578->
            startMinHeight;
        lbl_803DD578->maxHeight = blend * (lbl_803DD578->endMaxHeight - lbl_803DD578->startMaxHeight) + lbl_803DD578->
            startMaxHeight;
    }
    fb = *(f32*)(viewObj + 0xe);
    hi = fb + lbl_803DD578->maxHeight;
    lo = fb + lbl_803DD578->minHeight;
    blend = *(f32*)(camObj + 0xe);
    if (blend < lo)
    {
        clamped = lo - blend;
    }
    else if (blend > hi)
    {
        clamped = hi - blend;
    }
    else
    {
        clamped = lbl_803E19A0;
    }
    clamped = clamped * (lbl_803DD578->heightAdjustRate * timeDelta);
    *(f32*)(camObj + 0xe) = *(f32*)(camObj + 0xe) + clamped;
    dist = lbl_803DD578->targetDistance;
    dist = dist - lbl_803DD578->smoothedDistance;
    dist = dist * (lbl_803E19A4 * timeDelta);
    lbl_803DD578->smoothedDistance = lbl_803DD578->smoothedDistance + dist;
    trigValue = mathSinf((lbl_803E19AC * (f32)(s32) * viewObj) / lbl_803E19B0);
    traceFrom[0] = lbl_803E19A8 * trigValue + *(f32*)(viewObj + 0xc);
    traceFrom[1] = *(f32*)(viewObj + 0xe);
    trigValue = mathCosf((lbl_803E19AC * (f32)(s32) * viewObj) / lbl_803E19B0);
    traceFrom[2] = lbl_803E19A8 * trigValue + *(f32*)(viewObj + 0x10);
    trigValue = mathSinf((lbl_803E19AC * (f32)(s32) * viewObj) / lbl_803E19B0);
    *(f32*)(camObj + 0xc) = lbl_803DD578->smoothedDistance * trigValue + traceFrom[0];
    trigValue = mathCosf((lbl_803E19AC * (f32)(s32) * viewObj) / lbl_803E19B0);
    *(f32*)(camObj + 0x10) = lbl_803DD578->smoothedDistance * trigValue + traceFrom[2];
    camcontrol_traceMove(traceFrom, camObj + 0xc, traceOut, auStack176, 3, 1, 1, lbl_803E19B4);
    *(f32*)(camObj + 0xc) = traceOut[0];
    *(f32*)(camObj + 0xe) = traceOut[1];
    *(f32*)(camObj + 0x10) = traceOut[2];
    (*gCameraInterface)->getRelativePosition((f32)(u32)(u16)lbl_803DD578->relativePosition,
                                             (int)camObj, &fd, &clamped,
                                             &fc, &dist, 0);
    {
        int t = 0x8000 - (u16)getAngle(fd, fc);
        yawDelta = t - (u16) * camObj;
    }
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    *camObj += yawDelta;
    clamped = *(f32*)(camObj + 0xe) -
        (*(f32*)(viewObj + 0xe) + (f32)(u32)(u16)
    lbl_803DD578->relativePosition
    )
    ;
    yawDelta = (u16)getAngle(clamped, dist) - (u16)camObj[1];
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    camObj[1] += (yawDelta * framesThisStep) / 6;
    Obj_TransformWorldPointToLocal(*(f32*)(camObj + 0xc), *(f32*)(camObj + 0xe),
                                   *(f32*)(camObj + 0x10), (f32*)(camObj + 6), (f32*)(camObj + 8),
                                   (f32*)(camObj + 10),
                                   *(int*)(camObj + 0x18));
}
