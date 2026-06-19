#ifndef MAIN_DLL_APPLEONTREESTATE_STRUCT_H_
#define MAIN_DLL_APPLEONTREESTATE_STRUCT_H_

#include "types.h"

typedef struct AppleOnTreeState
{
    u8 unk00[8];
    f32 unk08;
    f32 unk0C;
    u8 unk10[0x24 - 0x10];
    f32 unk24;
    f32 unk28;
    f32 posY;
    f32 unk30;
    f32 unk34;
    u16 healthRestore;
    u8 unk3A;
    u8 pad3B;
    f32 unk3C;
    f32 unk40;
    f32 bounceVel;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad4E[2];
    f32 unk50;
    u8 pad54[6];
    u8 unk5A;
    u8 pad5B;
    s16 unk5C;
    s16 unk5E;
    f32 unk60;
} AppleOnTreeState;

#endif
