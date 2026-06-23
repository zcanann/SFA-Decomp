/*
 * pathcam - camera path sampling shared by the path-following camera modes
 * (DLL 0x42 / 0x43). camcontrol_samplePathState projects the target onto the
 * active Hermite path, advances the curve, and writes the resulting world
 * X/Z sample back to the caller.
 */
#include "main/dll/CAM/pathcam.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/object_transform.h"
#include "string.h"

extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1748;

u8 camcontrol_samplePathState(f32* outX, f32* height, f32* outZ, GameObject* target,
                              CameraObject* camera)
{
    CamcontrolPathSampleWork work;
    int handler;
    int i;
    f32 pathT;

    memset(&work, 0, 0x144);
    work.model = (int)camera->anim.parent;
    work.sampleX = gCamcontrolPathState->pointsX[gCamcontrolPathState->pathCurve.count - 2];
    work.sampleY = *height;
    work.sampleZ = gCamcontrolPathState->pointsZ[gCamcontrolPathState->pathCurve.count - 2];
    work.localX = work.sampleX;
    work.localY = work.sampleY;
    work.localZ = work.sampleZ;
    Obj_TransformLocalPointToWorld((double)work.localX, (double)work.localY, (double)work.localZ,
                                   &work.worldX, &work.worldY, work.worldZ, work.model);
    work.targetObj = target;
    handler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    (*(VtableFn*)(**(int**)(handler + 4) + 0x14))(&work, target);
    Obj_TransformLocalPointToWorld(work.sampleX, work.sampleY, work.sampleZ,
                                   &work.targetX, &work.targetY, work.targetZ, work.model);
    (*(VtableFn*)(**(int**)(handler + 4) + 0x24))
        (&work, 1, 3, &gCamcontrolPathState->curveMin, &gCamcontrolPathState->curveMax);
    i = gCamcontrolPathState->pathCurve.count + -3;
    for (; i < gCamcontrolPathState->pathCurve.count; i = i + 1)
    {
        gCamcontrolPathState->pointsX[i] = work.sampleX;
        gCamcontrolPathState->pointsZ[i] = work.sampleZ;
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
    else if (pathT < *(f32*)&lbl_803E1740)
    {
        pathT = *(f32*)&lbl_803E1740;
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
