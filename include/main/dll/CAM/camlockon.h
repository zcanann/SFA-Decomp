#ifndef MAIN_DLL_CAM_CAMLOCKON_H_
#define MAIN_DLL_CAM_CAMLOCKON_H_

#include "ghidra_import.h"

void camcontrol_buildPathAngles(s16 *outArr, u16 *outCount, s16 baseAngle, s16 deltaAngle,
                                s16 limit);
void camcontrol_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 baseY, f32 targetZ,
                                f32 targetY, s16 angleRange, s16 angleLimit,
                                int *outPointCount);

#endif /* MAIN_DLL_CAM_CAMLOCKON_H_ */
