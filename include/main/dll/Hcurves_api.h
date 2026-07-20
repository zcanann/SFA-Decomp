#ifndef MAIN_DLL_HCURVES_API_H_
#define MAIN_DLL_HCURVES_API_H_

#include "main/dll/curve_walker.h"

void RomCurve_swapEndpointNodes(RomCurveWalker* walker);
int RomCurve_setSegmentEndNode(RomCurveWalker* walker, void* curve);
int walkGroupFn_800db3e4(f32* prevPoint, f32* nextPoint, u32 currentWalkGroupIndex);
#ifdef OBJFSA_PATCH_EXIT_U16
int Objfsa_GetNearestPatchExit(f32* point, f32* outVec, u16 id);
#else
int Objfsa_GetNearestPatchExit(f32* point, f32* outVec, int id);
#endif
int isPointWithinPatchGroup(f32* point, u32 patchGroupIndex, int groupId);
int isInWalkGroupOrPatch(f32* point);
int Objfsa_GetPatchGroupIdAtPoint(f32* point);

#endif /* MAIN_DLL_HCURVES_API_H_ */
