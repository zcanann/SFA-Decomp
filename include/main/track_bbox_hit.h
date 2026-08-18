#ifndef MAIN_TRACK_BBOX_HIT_H_
#define MAIN_TRACK_BBOX_HIT_H_

#include "types.h"
#include "global.h"
#include "game/objects/object.h"

typedef struct TrackBBoxHit
{
    GameObject* object;
    f32 lineStartX;
    f32 lineEndX;
    f32 lineStartY;
    f32 lineEndY;
    f32 lineStartZ;
    f32 lineEndZ;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 normalW;
    f32 sourceNormalX;
    f32 sourceNormalY;
    f32 sourceNormalZ;
    f32 sourceNormalW;
    f32 upperY0;
    f32 upperY1;
    f32 distance;
    f32 interpolation;
    s16 adjacentLine0;
    s16 adjacentLine1;
    s8 surfaceType;
    s8 kind;
    u8 flags;
    u8 pad53;
} TrackBBoxHit;

STATIC_ASSERT(sizeof(TrackBBoxHit) == 0x54);
STATIC_ASSERT(offsetof(TrackBBoxHit, normalX) == 0x1C);
STATIC_ASSERT(offsetof(TrackBBoxHit, sourceNormalX) == 0x2C);
STATIC_ASSERT(offsetof(TrackBBoxHit, sourceNormalW) == 0x38);
STATIC_ASSERT(offsetof(TrackBBoxHit, upperY0) == 0x3C);
STATIC_ASSERT(offsetof(TrackBBoxHit, distance) == 0x44);
STATIC_ASSERT(offsetof(TrackBBoxHit, surfaceType) == 0x50);

#endif /* MAIN_TRACK_BBOX_HIT_H_ */
