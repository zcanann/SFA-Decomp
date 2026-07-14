#ifndef MAIN_DLL_TRICKYCURVE_OBJECT_H_
#define MAIN_DLL_TRICKYCURVE_OBJECT_H_

#include "types.h"

typedef struct TrickyCurveObject
{
    u8 pad0[0xC];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0xA0];
    void* state;
} TrickyCurveObject;

#endif /* MAIN_DLL_TRICKYCURVE_OBJECT_H_ */
