#ifndef DOLPHIN_MTX_VEC_TYPES_H_
#define DOLPHIN_MTX_VEC_TYPES_H_

#include "dolphin/types.h"

typedef struct Vec {
    f32 x;
    f32 y;
    f32 z;
} Vec, *VecPtr, Point3d, *Point3dPtr;

#endif /* DOLPHIN_MTX_VEC_TYPES_H_ */
