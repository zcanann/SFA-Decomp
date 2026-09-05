#ifndef MAIN_DLL_SKEETLA_H_
#define MAIN_DLL_SKEETLA_H_

#include "types.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/skeetla_route_api.h"
#include "game/objects/object.h"

typedef struct TrickyState TrickyState;

typedef struct SkeetlaParticleSpawnArgs {
    s16 objectId;
    s16 pad0;
    u16 sourceId;
    u16 pad1;
    u32 pad2;
    f32 x;
    f32 y;
    f32 z;
} SkeetlaParticleSpawnArgs;

int trickyTurnTowardYaw(GameObject* obj, s16 targetYaw);
int moveTricky(GameObject* obj, f32* targetPos);
RomCurveDef* trickyFindNearestLinkedRouteEntry(TrickyState* state, RomCurveDef* routeDef, int targetWalkGroup,
                                               int directionBits);
RomCurveDef* trickyFindPathRouteEntry(TrickyState* state, RomCurveDef* route, int targetWalkGroup);
RomCurveDef* trickySelectRouteEntry(TrickyState* state, RomCurveDef* routeDef, u8 routeDirection);
int trickyFindReachableRouteIndex(TrickyState* state, RomCurveDef** candidateRoutes, u8* candidateRouteDirections,
                                  int targetWalkGroup);
void trickyRankLinkedRouteCandidates(GameObject* obj, u8* outRouteDirections, s16 objectWalkGroup,
                                     RomCurveDef** outRoutes);
void skeetla_spawnLinkedSparks(GameObject* obj);
void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* targetPos, f32* center, f32 minDistance, f32 moveDistance);
void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* targetPos);

#endif /* MAIN_DLL_SKEETLA_H_ */
