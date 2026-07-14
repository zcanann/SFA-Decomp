#ifndef MAIN_TRACK_BBOX_API_H_
#define MAIN_TRACK_BBOX_API_H_

#include "types.h"
#include "main/game_object.h"

typedef struct TrackBBoxHit
{
    GameObject* object;
    f32 minX;
    f32 maxX;
    f32 minY;
    f32 maxY;
    f32 minZ;
    f32 maxZ;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 normalW;
    u8 pad2C[0xC];
    f32 upperY0;
    f32 upperY1;
    f32 upperY2;
    f32 distance;
    union
    {
        u8 pad48[8];
        struct
        {
            f32 interpolation;
            u8 pad4C[4];
        };
    };
    s8 surfaceType;
    s8 kind;
    u8 pad52[2];
} TrackBBoxHit;

STATIC_ASSERT(sizeof(TrackBBoxHit) == 0x54);

/* Callers pass the final arguments at ABI int width; the owner narrows them to bytes in its definition. */
#ifndef TRACK_BBOX_IMPLEMENTATION
int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, TrackBBoxHit* hit, GameObject* self, int flags,
                       int mask, int slot, int arg10);
#endif

#endif /* MAIN_TRACK_BBOX_API_H_ */
