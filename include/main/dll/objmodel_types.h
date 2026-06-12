#ifndef MAIN_DLL_OBJMODEL_TYPES_H_
#define MAIN_DLL_OBJMODEL_TYPES_H_

#include "types.h"

typedef struct ObjModelRenderOpLite
{
    u8 pad00[0x43];
    s8 alpha;
} ObjModelRenderOpLite;

typedef struct ObjModelFileHeaderLite
{
    u8 pad00[0x38];
    ObjModelRenderOpLite* renderOps;
    u8 pad3c[0xf3 - 0x3c];
    u8 jointCount;
    u8 extraJointCount;
    u8 padf5[0xf8 - 0xf5];
    u8 renderOpCount;
} ObjModelFileHeaderLite;

typedef struct ObjModelInstanceLite
{
    ObjModelFileHeaderLite* file;
    u8 pad04[0x0c - 0x04];
    u8* jointMatrices[2];
    u8 pad14[0x18 - 0x14];
    u16 bufferFlags;
} ObjModelInstanceLite;

#endif
