/*
 * camlockon - camera lock-on path builder.
 * Builds the set of intermediate 3D points that define the spline path
 * a lock-on camera follows between its base position and a target.
 * camcontrol_buildPathAngles recursively subdivides an angular range into
 * a sorted array of angles; camcontrol_buildPathPoints rotates the
 * base→target delta by each angle to produce the gCamcontrolPathState
 * points array used by the curve evaluator.
 */
#include "main/dll/CAM/camlockon.h"
#include "main/dll/CAM/camcontrol_path_state.h"

extern void vecRotateZXY(s16 * rot, f32 * vec);

#pragma inline_depth(4)
void camcontrol_buildPathAngles(s16* outArr, u16* outCount, s16 baseAngle, s16 deltaAngle,
                                s16 limit)
{
    if (deltaAngle >= limit)
    {
        camcontrol_buildPathAngles(outArr, outCount, baseAngle, deltaAngle >> 1, limit);
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + (deltaAngle >> 1), deltaAngle >> 1,
                                   limit);
    }
    else
    {
        outArr[(*outCount)++] = baseAngle;
    }
}

void camcontrol_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 baseY, f32 targetZ,
                                f32 targetY, s16 angleRange, s16 angleLimit,
                                int* outPointCount)
{
    u16 angleCount;
    s16 rot[3];
    f32 vec[3];
    s16 pathAngles[CAMCONTROL_PATH_POINT_CAPACITY];
    s16 absAngleRange;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    int i;
    int pointCount;

    if (angleRange < 0)
    {
        absAngleRange = -angleRange;
    }
    else
    {
        absAngleRange = angleRange;
    }

    angleCount = 0;
    camcontrol_buildPathAngles(pathAngles, &angleCount, 0, absAngleRange, angleLimit);

    deltaX = targetX - baseX;
    deltaY = targetY - baseY;
    deltaZ = targetZ - baseZ;
    i = 1;
    pointCount = 3;

    while (i < angleCount)
    {
        vec[0] = deltaX;
        vec[1] = deltaY;
        vec[2] = deltaZ;

        rot[0] = angleRange < 0 ? pathAngles[i] : -pathAngles[i];
        rot[1] = 0;
        rot[2] = 0;
        vecRotateZXY(rot, vec);

        gCamcontrolPathState->pointsX[pointCount] = baseX + vec[0];
        gCamcontrolPathState->pointsY[pointCount] =
            baseY + (deltaY * ((f32)pathAngles[i] / (f32)absAngleRange));
        gCamcontrolPathState->pointsZ[pointCount] = baseZ + vec[2];

        i++;
        pointCount++;
    }

    *outPointCount = pointCount;
}
