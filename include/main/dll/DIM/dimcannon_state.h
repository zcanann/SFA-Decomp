#ifndef MAIN_DLL_DIM_DIMCANNON_STATE_H_
#define MAIN_DLL_DIM_DIMCANNON_STATE_H_

#include "global.h"

typedef struct DimCannonState {
    u8 pad0[0x4 - 0x0];
    s32 unk4;
    s32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 unk1B;
    u8 pad1C[0x88 - 0x1C];
    f32 unk88;
    f32 unk8C;
    f32 unk90;
    f32 unk94;
    f32 unk98;
    u8 pad9C[8];
    s16 aimYaw;     /* 0xa4 */
    s16 aimPitch;   /* 0xa6 */
    int unkA8;
    u8 fireState;   /* 0xac */
    u8 unkAD;
    u8 unkAE;
    u8 unkAF;
    s8 unkB0;
    u8 unkB1;
    u8 unkB2;
    u8 padB3;
} DimCannonState;

#endif
