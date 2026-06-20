#ifndef MAIN_DLL_DLL19_STATE_H_
#define MAIN_DLL_DLL19_STATE_H_

#include "global.h"

typedef struct Dll19State
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    u8 pad24[0x30 - 0x24];
    u32 unk30;
    u8 pad34[0x8C - 0x34];
    f32 unk8C;
    u8 pad90[0x94 - 0x90];
    f32 unk94;
    u8 pad98[0x261 - 0x98];
    u8 unk261;
    u8 pad262[0x298 - 0x262];
    f32 unk298;
    u8 pad29C[0x2B8 - 0x29C];
    f32 unk2B8;
    u8 pad2BC[0x334 - 0x2BC];
    s16 unk334;
    u8 pad336[0x354 - 0x336];
    s8 progressNumerator;
    u8 pad355[0x3F4 - 0x355];
    s16 unk3F4;
    u8 pad3F6[0x400 - 0x3F6];
    u16 flags;
    u8 pad402[0x405 - 0x402];
    u8 unk405;
    u8 pad406[0x5F8 - 0x406];
    s32 unk5F8;
    s32 unk5FC;
    u8 movePhase;
    u8 pathInitialized;
    u8 pad602[0x604 - 0x602];
    s32 unk604;
    s32 unk608;
    s16 unk60C;
    s16 unk60E;
    u8 animChannelCount;
    u8 unk611;
    u8 pad612[0x614 - 0x612];
    f32 unk614;
    s32 unk618;
    u8 pad61C[0x620 - 0x61C];
} Dll19State;

#endif
