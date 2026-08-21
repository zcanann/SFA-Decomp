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
void* trickyFindNearestLinkedRouteEntry(TrickyState* context, u8* routeDef, int linkSelector, int routeFlagValue);
void* trickyFindPathRouteEntry(TrickyState* state, u32 route, int pathId);
void* trickySelectRouteEntry(TrickyState* state, u8* routeDef, u8 routeFlagValue);
int trickyFindReachableRouteIndex(TrickyState* state, RomCurveDef** candidateRoutes, u8* candidateRouteFlags,
                                  int targetWalkGroup);
void trickyRankLinkedRouteCandidates(GameObject* obj, u8* outRouteFlags, s16 linkSelector, RomCurveDef** outRoutes);
void skeetla_spawnLinkedSparks(GameObject* obj);
void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* guardPoint, f32* center, f32 minDistance, f32 moveDistance);
void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint);

#endif /* MAIN_DLL_SKEETLA_H_ */
