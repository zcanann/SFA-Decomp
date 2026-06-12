#ifndef MAIN_DLL_FB_CMD_H_
#define MAIN_DLL_FB_CMD_H_

#include "types.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    u16 flags;
    u8 layer;
} FbCmd;

#endif
