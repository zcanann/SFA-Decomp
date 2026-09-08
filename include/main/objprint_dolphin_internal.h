#ifndef MAIN_OBJPRINT_DOLPHIN_INTERNAL_H_
#define MAIN_OBJPRINT_DOLPHIN_INTERNAL_H_

#include "global.h"
#include "types.h"

typedef u8 (*ObjModelRenderCb)(int* obj, int* am, int p3);

typedef struct IndTexMtx23
{
    f32 m[2][3];
} IndTexMtx23;

STATIC_ASSERT(sizeof(IndTexMtx23) == 0x18);

#endif /* MAIN_OBJPRINT_DOLPHIN_INTERNAL_H_ */
