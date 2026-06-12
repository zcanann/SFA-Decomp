#ifndef MAIN_DLL_SCREENFX_TYPES_H_
#define MAIN_DLL_SCREENFX_TYPES_H_

#include "types.h"

typedef struct
{
    u32 flags;
    f32 x;
    f32 y;
    f32 z;
    u8* tex;
    u16 id;
    u8 state;
} ScreenFxPart;

typedef struct
{
    ScreenFxPart* parts; /* 0x00 */
    int target; /* 0x04 */
    u8 pad0[0x18]; /* 0x08 */
    f32 ax, ay, az; /* 0x20 */
    f32 bx, by, bz; /* 0x2c */
    f32 r; /* 0x38 */
    u32 c7; /* 0x3c */
    u32 c2; /* 0x40 */
    s16 b; /* 0x44 */
    s16 anim[7]; /* 0x46 */
    u32 flags; /* 0x54 */
    u8 v0, v1, v2, v3; /* 0x58 */
    u8 pad1; /* 0x5c */
    s8 count; /* 0x5d */
    u8 pad2[2]; /* 0x5e */
} ScreenFxHdr;

#endif
