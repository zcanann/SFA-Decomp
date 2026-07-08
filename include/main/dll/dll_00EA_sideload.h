#ifndef MAIN_DLL_DLL_00EA_SIDELOAD_H_
#define MAIN_DLL_DLL_00EA_SIDELOAD_H_

#include "global.h"

typedef struct SideloadPlacement
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 armGameBit; /* 0x18: arming game bit */
    u8 yawByte;     /* 0x1A: spawn yaw, shifted << 8 into the child's s16 rotation */
    u8 pad1B[0x3C - 0x1B];
    s16 unk3C;
    u8 pad3E[0x48 - 0x3E];
    void* unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0x98 - 0x71];
    f32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
    f32 unkB8;
    f32 unkBC;
    f32 unkC0;
    u8 padC4[0x2B1 - 0xC4];
    s8 unk2B1;
    u8 pad2B2[0x2B8 - 0x2B2];
} SideloadPlacement;

void sideload_update(int self);

#endif /* MAIN_DLL_DLL_00EA_SIDELOAD_H_ */
