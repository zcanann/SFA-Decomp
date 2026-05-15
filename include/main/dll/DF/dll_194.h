#ifndef MAIN_DLL_DF_DLL_194_H_
#define MAIN_DLL_DF_DLL_194_H_

#include "ghidra_import.h"

int dfropenode_func0E(int obj, f32 x, f32 y, f32 z, float *distanceOut, float *phaseOut,
                      u8 *sideOut);
void dfropenode_render2(double phase, double force, int obj);
void dfropenode_modelMtxFn(double distance, int obj, float *phase);
void dfropenode_func0B(double phase, int obj, float *xOut, float *yOut, float *zOut);

#endif /* MAIN_DLL_DF_DLL_194_H_ */
