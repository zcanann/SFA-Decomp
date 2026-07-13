#ifndef MAIN_DLL_SKEETLA_ROUTE_API_H_
#define MAIN_DLL_SKEETLA_ROUTE_API_H_

#include "global.h"

typedef struct RomCurveWalker RomCurveWalker;

void trickyUpdateCollisionAndPathState(u8* obj);
int trickyAdvanceRouteTargetAhead(int obj, RomCurveWalker* route, f32 speed);

#endif /* MAIN_DLL_SKEETLA_ROUTE_API_H_ */
