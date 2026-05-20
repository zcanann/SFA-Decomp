#ifndef MAIN_DLL_CAM_ATTENTION_H_
#define MAIN_DLL_CAM_ATTENTION_H_

#include "ghidra_import.h"

void camcontrol_updateVerticalBounds(int camera,int flags,s8 param_3,float *upperBound,
                                     float *lowerBound);
void CameraModeNormal_func0A(float *distanceOut,float *yOffsetOut,float *zOffsetOut,
                             float *xAngleOut,float *targetHeightOut);

#endif /* MAIN_DLL_CAM_ATTENTION_H_ */
