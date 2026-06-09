#ifndef MAIN_DLL_CAM_ATTENTION_H_
#define MAIN_DLL_CAM_ATTENTION_H_

#include "ghidra_import.h"

void camcontrol_updateVerticalBounds(int camera,int flags,int param_3,float *upperBound,
                                     float *lowerBound);
void CameraModeNormal_func0A(float *minDistanceOut,float *maxDistanceOut,
                             float *lowerHeightOffsetOut,float *upperHeightOffsetOut,
                             float *targetHeightOut);

#endif /* MAIN_DLL_CAM_ATTENTION_H_ */
