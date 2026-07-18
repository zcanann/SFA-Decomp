#ifndef MAIN_TRACK_DOLPHIN_EXT_H_
#define MAIN_TRACK_DOLPHIN_EXT_H_

#include "types.h"

void objDrawFn_80061654(int obj, int placementObj);
int findSurfaceInYRange(int obj, f32 x, f32 lo, f32 z, f32 hi, f32* outSurfaceY, int* outSurfaceId);

#endif /* MAIN_TRACK_DOLPHIN_EXT_H_ */
