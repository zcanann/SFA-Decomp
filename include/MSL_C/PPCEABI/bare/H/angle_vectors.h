#ifndef MSL_ANGLE_VECTORS_H_
#define MSL_ANGLE_VECTORS_H_

#include "types.h"

void angleToVec2Fast(int angle, float* sinOut, float* cosOut);
void angleToVec2Precise(int angle, float* sinOut, float* cosOut);

void angleToVec2(int angle, f32* sinOut, f32* cosOut);

#endif
