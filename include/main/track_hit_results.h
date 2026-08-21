#ifndef MAIN_TRACK_HIT_RESULTS_H_
#define MAIN_TRACK_HIT_RESULTS_H_

#include "types.h"
#include "global.h"
#include "game/objects/object.h"

typedef struct TrackGroundHit {
    f32 height;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    GameObject* object;
    s8 surfaceType;
    u8 pad15[3];
} TrackGroundHit;

STATIC_ASSERT(sizeof(TrackGroundHit) == 0x18);

typedef struct TrackQueryBounds {
    s32 minX;
    s32 minY;
    s32 minZ;
    s32 maxX;
    s32 maxY;
    s32 maxZ;
} TrackQueryBounds;

STATIC_ASSERT(sizeof(TrackQueryBounds) == 0x18);

typedef struct TrackHitResults {
    f32 planes[4][4];
    f32 radii[4];
    s8 surfaceTypes[4];
    s8 queryTypes[4];
    u8 triangleFlags[4];
    GameObject* objects[4];
    s16 hitCount;
    u8 hitMask;
    u8 pad6F;
} TrackHitResults;

STATIC_ASSERT(sizeof(TrackHitResults) == 0x70);
STATIC_ASSERT(offsetof(TrackHitResults, radii) == 0x40);
STATIC_ASSERT(offsetof(TrackHitResults, surfaceTypes) == 0x50);
STATIC_ASSERT(offsetof(TrackHitResults, queryTypes) == 0x54);

#endif /* MAIN_TRACK_HIT_RESULTS_H_ */
