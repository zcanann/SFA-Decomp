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
void camcontrol_buildPathAngles(s16 *outArr, u16 *outCount, s16 baseAngle, s16 deltaAngle,
                                s16 limit)
{
  u16 count;
  s16 angle;
  s16 half;
  s16 quarter;
  s16 eighth;
  s16 sixteenth;

  if (deltaAngle < limit) {
    count = *outCount;
    *outCount = count + 1;
    outArr[count] = baseAngle;
  }
  else {
    half = deltaAngle >> 1;
    quarter = half >> 1;
    eighth = quarter >> 1;
    sixteenth = eighth >> 1;
    if (half < limit) {
      count = *outCount;
      *outCount = count + 1;
      outArr[count] = baseAngle;
    }
    else {
      if (quarter < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle;
      }
      else if (eighth < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle;
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + eighth;
      }
      else {
        camcontrol_buildPathAngles(outArr, outCount, baseAngle, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + sixteenth, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + eighth, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + eighth + sixteenth,
                                   sixteenth, limit);
      }
      if (quarter < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + quarter;
      }
      else if (eighth < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + quarter;
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + quarter + eighth;
      }
      else {
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + quarter, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + quarter + sixteenth,
                                   sixteenth, limit);
        angle = baseAngle + quarter + eighth;
        camcontrol_buildPathAngles(outArr, outCount, angle, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, angle + sixteenth, sixteenth, limit);
      }
    }
    if (half < limit) {
      count = *outCount;
      *outCount = count + 1;
      outArr[count] = baseAngle + half;
    }
    else {
      if (quarter < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + half;
      }
      else if (eighth < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + half;
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + half + eighth;
      }
      else {
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + half, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, baseAngle + half + sixteenth,
                                   sixteenth, limit);
        angle = baseAngle + half + eighth;
        camcontrol_buildPathAngles(outArr, outCount, angle, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, angle + sixteenth, sixteenth, limit);
      }
      if (quarter < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + half + quarter;
      }
      else if (eighth < limit) {
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + half + quarter;
        count = *outCount;
        *outCount = count + 1;
        outArr[count] = baseAngle + half + quarter + eighth;
      }
      else {
        angle = baseAngle + half + quarter;
        camcontrol_buildPathAngles(outArr, outCount, angle, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, angle + sixteenth, sixteenth, limit);
        angle = baseAngle + half + quarter + eighth;
        camcontrol_buildPathAngles(outArr, outCount, angle, sixteenth, limit);
        camcontrol_buildPathAngles(outArr, outCount, angle + sixteenth, sixteenth, limit);
      }
    }
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
void camcontrol_buildPathPoints(s16 angleRange, s16 angleLimit, int *outPointCount, f32 baseX,
                                f32 baseZ, f32 targetX, f32 baseY, f32 targetZ,
                                f32 targetY)
{
  s16 absAngleRange;
  s16 pathAngles[32];
  u16 angleCount;
  s16 rot[3];
  f32 vec[3];
  f32 deltaX;
  f32 deltaY;
  f32 deltaZ;
  int i;
  int pointCount;
  int storeOffset;

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
  pointCount = 3;
  storeOffset = 0xc;

  for (i = 1; i < angleCount; i++) {
    vec[0] = deltaX;
    vec[1] = deltaY;
    vec[2] = deltaZ;

    if (angleRange < 0) {
      rot[0] = pathAngles[i];
    }
    else {
      rot[0] = -pathAngles[i];
    }
    rot[1] = 0;
    rot[2] = 0;
    mathFn_80021ac8(rot, vec);

    *(f32 *)(gCamcontrolPathState + storeOffset + 0x1c) = baseX + vec[0];
    *(f32 *)(gCamcontrolPathState + storeOffset + 0x6c) =
        baseY + (deltaY * ((f32)pathAngles[i] / (f32)absAngleRange));
    *(f32 *)(gCamcontrolPathState + storeOffset + 0xbc) = baseZ + vec[2];

    pointCount++;
    storeOffset += 4;
  }

  *outPointCount = pointCount;
}
