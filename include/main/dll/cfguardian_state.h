#ifndef MAIN_DLL_CFGUARDIAN_STATE_H_
#define MAIN_DLL_CFGUARDIAN_STATE_H_

#include "global.h"

typedef struct CfGuardianState {
    u8 pad0[0x2 - 0x0];
    u16 unk2;
    s32 unk4;
    s32 unk8;
    s32 unkC;
    s32 unk10;
    s32 unk14;
    s32 unk18;
    s32 unk1C;
    s32 unk20;
    s32 unk24;
    s32 unk28;
    u8 pad2C[0x7C - 0x2C];
    f32 unk7C;
    f32 speed80;
    u8 pad84[0x611 - 0x84];
    u8 flags611;
    u8 pad612[0x12];
    u8 audioBlock[0x30];  /* 0x624: objAudioFn block */
    u8 eyeBlock[0x38];    /* 0x654: characterDoEyeAnims block */
    int linkedObjs[6];    /* 0x68c: freed with the guardian */
    u8 pad6A4[0x18];
    u8 pathBlock[0x140];  /* 0x6bc: fn_8019AF64 path-flight block */
    f32 moveSpeed;        /* 0x7fc */
    u8 pad800[0x25e];
    u8 unkA5E;            /* bounce-velocity latch while landing */
    u8 padA5F[9];
    s16 homeYaw;          /* 0xa68: embedded steer-target header (fn_8019B1D8) */
    u8 padA6A[0xa];
    f32 homeX;            /* 0xa74: nearest rom-curve point after landing */
    f32 homeY;
    f32 homeZ;
    u8 questState;        /* 0xa80: 16-state quest progression */
    u8 padA81[0xf];
    int unkA90;
    int landingPhase;     /* 0xa94 */
    u8 chatterState;      /* 0xa98: 1 ready, 2 playing */
    s8 chatterAlt;
    s8 chatterPick;
    u8 flagsA9B;          /* 1 move-latched, 2 path-flying, 4 homing */
} CfGuardianState;

#endif
