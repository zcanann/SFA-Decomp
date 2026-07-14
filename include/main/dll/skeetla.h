#ifndef MAIN_DLL_SKEETLA_H_
#define MAIN_DLL_SKEETLA_H_

#include "ghidra_import.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/skeetla_route_api.h"

typedef struct SkeetlaParticleSpawnArgs
{
    s16 objectId;
    s16 pad0;
    u16 sourceId;
    u16 pad1;
    u32 pad2;
    f32 x;
    f32 y;
    f32 z;
} SkeetlaParticleSpawnArgs;

int trickyTurnTowardYaw(u8* obj, s16 targetYaw);
int trickyMove(u8* obj, f32* targetPos);
void* trickyFindNearestLinkedRouteEntry(u8* context, u8* routeDef, int linkSelector, int routeFlagValue);
void* trickyFindPathRouteEntry(u8* state, u32 route, int pathId);
int trickyFindReachableRouteIndex(u8* state, u32* routes, u8* routeFlags, int pathId);
void* trickySelectRouteEntry(u8* state, u8* routeDef, u32 routeFlagValue);
void trickyRankLinkedRouteCandidates(u8* obj, u8* outRouteFlags, s16 linkSelector, void** outRoutes);
void skeetla_spawnLinkedSparks(u8* obj);
void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* guardPoint, f32* center, f32 minDistance, f32 moveDistance);
void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint);

#endif /* MAIN_DLL_SKEETLA_H_ */
