#include "main/dll/CAM/pathcam.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/object_transform.h"
#include "string.h"

extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1748;

void camcontrol_samplePathState(f32* outX, f32* height, f32* outZ, undefined4 param_4, int param_5)
{
    CamcontrolPathSampleWork work;
    int iVar1;
    int iVar2;
    f32 pathT;

    memset(&work, 0, 0x144);
    work.model = *(int*)(param_5 + 0x30);
    work.sampleX = gCamcontrolPathState->pointsX[gCamcontrolPathState->pathCurve.count - 2];
    work.sampleY = *height;
    work.sampleZ = gCamcontrolPathState->pointsZ[gCamcontrolPathState->pathCurve.count - 2];
    work.localX = work.sampleX;
    work.localY = work.sampleY;
    work.localZ = work.sampleZ;
    Obj_TransformLocalPointToWorld((double)work.sampleX, (double)work.sampleY, (double)work.sampleZ,
                                   &work.worldX, &work.worldY, work.worldZ, work.model);
    work.targetObj = param_4;
    iVar1 = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    (*(code*)(**(int**)(iVar1 + 4) + 0x14))(&work, param_4);
    Obj_TransformLocalPointToWorld(work.sampleX, work.sampleY, work.sampleZ,
                                   &work.targetX, &work.targetY, work.targetZ, work.model);
    (*(code*)(**(int**)(iVar1 + 4) + 0x24))
        (&work, 1, 3, &gCamcontrolPathState->curveMin, &gCamcontrolPathState->curveMax);
    iVar2 = gCamcontrolPathState->pathCurve.count + -3;
    for (; iVar2 < gCamcontrolPathState->pathCurve.count; iVar2 = iVar2 + 1)
    {
        gCamcontrolPathState->pointsX[iVar2] = work.sampleX;
        gCamcontrolPathState->pointsZ[iVar2] = work.sampleZ;
    }
    if (lbl_803E1740 != gCamcontrolPathState->pathCurve.pathLength)
    {
        pathT = gCamcontrolPathState->pathCurve.pathDistance /
            gCamcontrolPathState->pathCurve.pathLength;
    }
    else
    {
        pathT = lbl_803E1740;
    }
    if (pathT > lbl_803E1744)
    {
        pathT = lbl_803E1744;
    }
    else if (pathT < lbl_803E1740)
    {
        pathT = lbl_803E1740;
    }
    pathT = Curve_EvalHermite(pathT,gCamcontrolPathState->initialiseCurve, (float*)0x0);
    if (pathT < lbl_803E1748)
    {
        pathT = lbl_803E1748;
    }
    Curve_AdvanceAlongPath(&gCamcontrolPathState->pathCurve, pathT);
    *outX = gCamcontrolPathState->pathCurve.sample[0];
    *outZ = gCamcontrolPathState->pathCurve.sample[2];
    return;
}
