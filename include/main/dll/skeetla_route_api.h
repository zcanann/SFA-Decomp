#ifndef MAIN_DLL_SKEETLA_ROUTE_API_H_
#define MAIN_DLL_SKEETLA_ROUTE_API_H_

#include "global.h"
#include "game/objects/object_fwd.h"

typedef struct RomCurveWalker RomCurveWalker;

void trickyUpdateCollisionAndPathState(GameObject* obj);
int trickyAdvanceRouteTargetAhead(GameObject* obj, RomCurveWalker* route, f32 speed);

#endif /* MAIN_DLL_SKEETLA_ROUTE_API_H_ */
