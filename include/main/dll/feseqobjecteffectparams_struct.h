#ifndef MAIN_DLL_FESEQOBJECTEFFECTPARAMS_STRUCT_H_
#define MAIN_DLL_FESEQOBJECTEFFECTPARAMS_STRUCT_H_

#include "types.h"

typedef struct FEseqobjectEffectParams
{
    s16 xRot;
    s16 yRot;
    s16 variant;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} FEseqobjectEffectParams;

#endif
