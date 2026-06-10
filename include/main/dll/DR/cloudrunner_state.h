#ifndef MAIN_DLL_DR_CLOUDRUNNER_STATE_H_
#define MAIN_DLL_DR_CLOUDRUNNER_STATE_H_

#include "global.h"
#include "main/dll/baddie_state.h"

typedef struct CloudRunnerState {
    BaddieState baddie;
    u8 pad35C[0x3c4 - 0x35c];
    f32 posX3C4;
    f32 posY3C4;
    f32 posZ3C4;
    f32 unk3D0;
    f32 unk3D4;
    f32 unk3D8;
    u8 pad3DC[0x464 - 0x3dc];
    u8 bool464;
    u8 pad465[0xad5 - 0x465];
    u8 flagsAD5;
    u8 padAD6[0xae8 - 0xad6];
    f32 unkAE8;
    f32 unkAEC;
    f32 unkAF0;
    f32 posXAF4;
    f32 posYAF4;
    f32 posZAF4;
    u8 padB00[4];
    int unkB04;
    u8 padB08[0xb50 - 0xb08];
    f32 unkB50;
    u8 padB54[0xbae - 0xb54];
    s16 unkBAE;
    s16 timerBB0;
    u8 unkBB2;
    u8 padBB3;
    u8 unkBB4;
    u8 padBB5;
    u8 flagsBB6;
    u8 unkBB7;
    u8 unkBB8;
    u8 padBB9;
    s16 angleBBA;
    s16 unkBBC;
    s16 angleBBE;
    u8 flagsBC0; /* ByteFlags */
    u8 flagsBC1; /* ByteFlags */
    u8 padBC2;
    s8 unkBC3;
    s8 unkBC4;
    u8 padBC5[3];
} CloudRunnerState;

#endif
