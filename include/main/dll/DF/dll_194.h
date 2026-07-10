#ifndef MAIN_DLL_DF_DLL_194_H_
#define MAIN_DLL_DF_DLL_194_H_

#include "main/game_object.h"
#include "ghidra_import.h"

int dfropenode_findNearestRopePoint(GameObject* obj, f32 x, f32 y, f32 z, float* distanceOut, float* phaseOut,
                                    u8* sideOut);
void dfropenode_applyForceAtPhase(f32 phase, f32 force, GameObject* obj);
void dfropenode_advancePhaseByDistance(GameObject* distance, int obj, float* phase);
void dfropenode_getWorldPosAtPhase(f32 phase, GameObject* obj, float* xOut, float* yOut, float* zOut);

#endif /* MAIN_DLL_DF_DLL_194_H_ */
