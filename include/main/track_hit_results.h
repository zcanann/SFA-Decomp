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
    u8 surfaceType;
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

#define TRACK_HIT_MAX_POINTS 4

typedef struct TrackHitResults {
    f32 planes[TRACK_HIT_MAX_POINTS][4];
    f32 radii[TRACK_HIT_MAX_POINTS];
    s8 surfaceTypes[TRACK_HIT_MAX_POINTS];
    s8 queryTypes[TRACK_HIT_MAX_POINTS];
    u8 triangleFlags[TRACK_HIT_MAX_POINTS];
    GameObject* objects[TRACK_HIT_MAX_POINTS];
    s16 hitCount;
    u8 hitMask;
    u8 pad6F;
} TrackHitResults;

STATIC_ASSERT(sizeof(TrackHitResults) == 0x70);
STATIC_ASSERT(offsetof(TrackHitResults, radii) == 0x40);
STATIC_ASSERT(offsetof(TrackHitResults, surfaceTypes) == 0x50);
STATIC_ASSERT(offsetof(TrackHitResults, queryTypes) == 0x54);

STATIC_ASSERT(offsetof(TrackHitResults, triangleFlags) == 0x58);
STATIC_ASSERT(offsetof(TrackHitResults, objects) == 0x5C);
STATIC_ASSERT(offsetof(TrackHitResults, hitCount) == 0x6C);
STATIC_ASSERT(offsetof(TrackHitResults, hitMask) == 0x6E);

#endif /* MAIN_TRACK_HIT_RESULTS_H_ */
