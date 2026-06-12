#ifndef MAIN_DLL_SCMUSICTREESETUP_STRUCT_H_
#define MAIN_DLL_SCMUSICTREESETUP_STRUCT_H_

#include "types.h"

typedef struct SCMusicTreeSetup
{
    ObjPlacement base;
    u8 rotXByte;
    u8 rotZByte;
    u8 yawByte;
    u8 hearRadiusHalf;
    f32 scale;
    u8 pad20[0x23 - 0x20];
    u8 flags;
} SCMusicTreeSetup;

#endif
