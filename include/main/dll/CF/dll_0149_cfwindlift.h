#ifndef MAIN_DLL_CF_DLL_0149_CFWINDLIFT_H_
#define MAIN_DLL_CF_DLL_0149_CFWINDLIFT_H_

#include "global.h"

typedef struct WindliftPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 pullStrength; /* 0x1A: wind pull strength passed to fn_8019C784 */
    u8 pad1C[0x22 - 0x1C];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftPlacement;

typedef struct WindliftObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s8 unk18;
    s8 heightByte;    /* 0x19: lift height in gWindLiftHeightByteScale units (0 = default) */
    s16 pullStrength; /* 0x1A */
    s16 delay;
    s16 seqId;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftObjectDef;

typedef struct
{
    int riderObj;
    f32 f4;
    f32 speedDelta;
    f32 riseSpeed;
    u8 phaseFlags;
    u8 oscCounter;
    u8 pad12[2];
    int linkIndex;
} WindLiftSlot;

#endif /* MAIN_DLL_CF_DLL_0149_CFWINDLIFT_H_ */
