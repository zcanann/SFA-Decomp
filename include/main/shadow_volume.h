#ifndef MAIN_SHADOW_VOLUME_H_
#define MAIN_SHADOW_VOLUME_H_

#include "main/vec_types.h"

typedef struct ShadowVolumePlane {
    Vec3f normal;
    f32 distance;
    u8 unk10[4];
} ShadowVolumePlane;

STATIC_ASSERT(sizeof(ShadowVolumePlane) == 0x14);
STATIC_ASSERT(offsetof(ShadowVolumePlane, normal) == 0x00);
STATIC_ASSERT(offsetof(ShadowVolumePlane, distance) == 0x0C);

void buildShadowVolumeBox(Vec3f* direction, Vec3f* corners, f32 lowerScale);

#endif /* MAIN_SHADOW_VOLUME_H_ */
