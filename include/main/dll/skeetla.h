#ifndef MAIN_DLL_SKEETLA_H_
#define MAIN_DLL_SKEETLA_H_

#include "ghidra_import.h"
#include "main/dll/rom_curve_interface.h"

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

void trickyUpdateCollisionAndPathState(u8* obj);
int trickyAdvanceRouteTargetAhead(int obj, RomCurveWalker* route, f32 speed);
int trickyTurnTowardYaw(u8* obj, s16 targetYaw);
int trickyMove(u8* obj, f32* targetPos);
int objAnimFn_8013a3f0(int obj, int newState, f32 speed, u32 flags);
void* trickyFindNearestLinkedRouteEntry(u8* context, u8* routeDef, int linkSelector, int routeFlagValue);
void* trickyFindPathRouteEntry(u8* state, u32 route, int pathId);
int trickyFindReachableRouteIndex(u8* state, u32* routes, u8* routeFlags, int pathId);
void* trickySelectRouteEntry(u8* state, u8* routeDef, u32 routeFlagValue);
void trickyRankLinkedRouteCandidates(u8* obj, u8* outRouteFlags, s16 linkSelector, void** outRoutes);
void skeetla_spawnLinkedSparks(u8* obj);
void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* guardPoint, f32* center, f32 minDistance, f32 moveDistance);
void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint);

#endif /* MAIN_DLL_SKEETLA_H_ */
