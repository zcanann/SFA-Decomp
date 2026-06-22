#ifndef MAIN_DLL_WAVEANIMATOROBJECTDEF_STRUCT_H_
#define MAIN_DLL_WAVEANIMATOROBJECTDEF_STRUCT_H_

#include "types.h"

typedef struct WaveanimatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 originX;
    s16 originY;
    s8 spanX;
    s8 spanY;
    s16 modelVariant;
    s8 sinkDepthScale; /* 0x20: scales the sink depth (K * (u8)this) */
    s8 period;
    s8 gridN;
    u8 pad23[0x25 - 0x23];
    u8 sinkEnable; /* 0x25: gates the GameBit-driven sink behavior */
    u8 radius;
    u8 yOffset;
} WaveanimatorObjectDef;

#endif
