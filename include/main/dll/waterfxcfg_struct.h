#ifndef MAIN_DLL_WATERFXCFG_STRUCT_H_
#define MAIN_DLL_WATERFXCFG_STRUCT_H_

#include "types.h"

typedef struct WaterfxCfg
{
    union {
        struct {
            s16 x;
            s16 y;
            s16 z;
            u8 pad6[2];
        };
        struct {
            s16 rotX;
            s16 rotY;
            s16 rotZ;
            s16 padRot;
        };
    };
    union {
        f32 f8;
        f32 scale;
    };
    union {
        f32 fc;
        f32 posX;
    };
    union {
        f32 f10;
        f32 posY;
    };
    union {
        f32 f14;
        f32 posZ;
    };
} WaterfxCfg;

#endif
