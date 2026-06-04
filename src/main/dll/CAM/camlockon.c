#include "ghidra_import.h"
#include "main/dll/CAM/camlockon.h"

#pragma peephole off
#pragma scheduling off

extern void mathFn_80021ac8(s16 *rot, f32 *vec);

extern u8 *lbl_803DD538;
extern f64 lbl_803E1750;

#define gCamcontrolPathState lbl_803DD538

/*
 * --INFO--
 *
 * Function: camcontrol_buildPathAngles
 * EN v1.0 Address: 0x8010684C
 * EN v1.0 Size: 1336b
 * EN v1.1 Address: 0x80106888
 * EN v1.1 Size: 1336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma inline_depth(4)
void camcontrol_buildPathAngles(s16 *outArr, u16 *outCount, s16 baseAngle, s16 deltaAngle,
                                s16 limit)
{
  if (deltaAngle >= limit) {
    camcontrol_buildPathAngles(outArr, outCount, baseAngle, deltaAngle >> 1, limit);
    camcontrol_buildPathAngles(outArr, outCount, baseAngle + (deltaAngle >> 1), deltaAngle >> 1,
                               limit);
  }
  else {
    outArr[(*outCount)++] = baseAngle;
  }
}

/*
 * --INFO--
 *
 * Function: camcontrol_buildPathPoints
 * EN v1.0 Address: 0x80106D84
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x80106DC0
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 baseY, f32 targetZ,
                                f32 targetY, s16 angleRange, s16 angleLimit,
                                int *outPointCount)
{
  u16 angleCount;
  s16 rot[3];
  f32 vec[3];
  s16 pathAngles[20];
  s16 absAngleRange;
  f32 deltaX;
  f32 deltaY;
  f32 deltaZ;
  int i;
  int pointCount;

  if (angleRange < 0) {
    absAngleRange = -angleRange;
  }
  else {
    absAngleRange = angleRange;
  }

  angleCount = 0;
  camcontrol_buildPathAngles(pathAngles, &angleCount, 0, absAngleRange, angleLimit);

  deltaX = targetX - baseX;
  deltaY = targetY - baseY;
  deltaZ = targetZ - baseZ;
  i = 1;
  pointCount = 3;

  while (i < angleCount) {
    vec[0] = deltaX;
    vec[1] = deltaY;
    vec[2] = deltaZ;

    rot[0] = angleRange < 0 ? pathAngles[i] : -pathAngles[i];
    rot[1] = 0;
    rot[2] = 0;
    mathFn_80021ac8(rot, vec);

    *(f32 *)(gCamcontrolPathState + pointCount * 4 + 0x1c) = baseX + vec[0];
    *(f32 *)(gCamcontrolPathState + pointCount * 4 + 0x6c) =
        baseY + (deltaY * ((f32)pathAngles[i] / (f32)absAngleRange));
    *(f32 *)(gCamcontrolPathState + pointCount * 4 + 0xbc) = baseZ + vec[2];

    i++;
    pointCount++;
  }

  *outPointCount = pointCount;
}

