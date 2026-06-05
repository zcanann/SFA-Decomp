#ifndef MAIN_FRUSTUM_H_
#define MAIN_FRUSTUM_H_

#include "ghidra_import.h"

typedef struct FrustumPlane {
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 distance;
    u8 aabbCornerIndex;
    u8 pad[3];
} FrustumPlane;

void frustumPlanes_updateAabbCornerIndices(FrustumPlane *planes, int count);

#endif /* MAIN_FRUSTUM_H_ */
