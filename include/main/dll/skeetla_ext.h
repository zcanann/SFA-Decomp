#ifndef MAIN_DLL_SKEETLA_EXT_H_
#define MAIN_DLL_SKEETLA_EXT_H_

#include "types.h"
#include "main/dll/curve_walker.h"

void skeetla_spawnLinkedSparks(u8* obj);

int trickyAdvanceRouteTargetAhead(int obj, RomCurveWalker* route, f32 speed);
#endif /* MAIN_DLL_SKEETLA_EXT_H_ */
