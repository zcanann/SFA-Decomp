#ifndef MAIN_GROUND_SHADOW_H_
#define MAIN_GROUND_SHADOW_H_

#include "main/vec_types.h"

struct GameObject;
struct ObjModel;

typedef struct GroundShadowQuad {
    Vec3s vertices[4]; /* Object-relative coordinates with eight fractional bits. */
    u8 status;        /* 0 = not built, 1 = ready, 0xff = no ground found. */
    u8 pad19;
} GroundShadowQuad;

STATIC_ASSERT(sizeof(GroundShadowQuad) == 0x1A);
STATIC_ASSERT(offsetof(GroundShadowQuad, vertices) == 0x00);
STATIC_ASSERT(offsetof(GroundShadowQuad, status) == 0x18);

void objDrawGroundShadow(struct GameObject* obj, struct ObjModel* model);

#endif /* MAIN_GROUND_SHADOW_H_ */
