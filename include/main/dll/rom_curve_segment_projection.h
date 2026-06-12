#ifndef MAIN_DLL_ROM_CURVE_SEGMENT_PROJECTION_H_
#define MAIN_DLL_ROM_CURVE_SEGMENT_PROJECTION_H_

#include "global.h"

typedef struct RomCurveSegmentProjection {
  f32 startX;
  f32 startY;
  f32 startZ;
  f32 endX;
  f32 endY;
  f32 endZ;
  f32 nearestX;
  f32 nearestY;
  f32 nearestZ;
} RomCurveSegmentProjection;

#endif
