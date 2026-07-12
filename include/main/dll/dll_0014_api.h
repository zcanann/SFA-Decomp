#ifndef MAIN_DLL_DLL_0014_API_H_
#define MAIN_DLL_DLL_0014_API_H_

#include "types.h"

int curves_isPointInsideLoop();
int getPatchGroup(f32* pos, int patchGroup);
u32 RomCurve_getAdjacentWindow();
u32 RomCurve_projectPointToAdjacentWindow();

#endif /* MAIN_DLL_DLL_0014_API_H_ */
