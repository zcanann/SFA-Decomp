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
    /*
     * 0x1E-0x1F overlay: groundanimator reads this region as a single s16
     * model-variant selector, while waveanimator reads the two bytes as
     * independent signed wave amplitudes (ampX@0x1E, ampY@0x1F).
     */
    union
    {
        s16 modelVariant;
        struct
        {
            s8 ampX; /* 0x1E */
            s8 ampY; /* 0x1F */
        };
    };
    s8 sinkDepthScale; /* 0x20: scales the sink depth (K * (u8)this) */
    s8 period;
    s8 gridN;
    u8 pad23[0x25 - 0x23];
    u8 sinkEnable; /* 0x25: gates the GameBit-driven sink behavior */
    u8 radius;
    u8 yOffset;
} WaveanimatorObjectDef;

#endif
