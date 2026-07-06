#ifndef MAIN_DLL_DF_DLL_194_H_
#define MAIN_DLL_DF_DLL_194_H_

#include "ghidra_import.h"

int dfropenode_findNearestRopePoint(int obj, f32 x, f32 y, f32 z, float *distanceOut, float *phaseOut,
                      u8 *sideOut);
void dfropenode_applyForceAtPhase(f32 phase, f32 force, int obj);
void dfropenode_advancePhaseByDistance(f32 distance, int obj, float *phase);
void dfropenode_getWorldPosAtPhase(f32 phase, int obj, float *xOut, float *yOut, float *zOut);

#endif /* MAIN_DLL_DF_DLL_194_H_ */
