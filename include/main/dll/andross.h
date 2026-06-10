#ifndef MAIN_DLL_ANDROSS_H_
#define MAIN_DLL_ANDROSS_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * AndrossState - andross.c's obj+0xB8 extra record (andross_getExtraSize =
 * 0xEC). Field widths mirror the deref widths observed in andross.c;
 * unobserved ranges are padded.
 */
typedef struct AndrossState {
    int unk0;
    int unk4;
    int unk8;
    int unkC;
    int unk10;
    int unk14;
    u8 unk18[0x20 - 0x18];
    s16 unk20;
    u8 unk22[0x23 - 0x22];
    u8 unk23;
    u8 unk24[0x43 - 0x24];
    s8 unk43;
    s16 unk44;
    u8 unk46[0x4C - 0x46];
    int unk4C;
    u8 unk50[0x58 - 0x50];
    f32 unk58;
    f32 unk5C;
    f32 unk60;
    f32 unk64;
    f32 unk68;
    f32 unk6C;
    f32 unk70;
    f32 unk74;
    f32 unk78;
    int unk7C;
    int unk80;
    int unk84;
    int unk88;
    int unk8C;
    int unk90;
    int unk94;
    s16 unk98;
    u8 unk9A[0x9C - 0x9A];
    f32 unk9C;
    s16 unkA0;
    s16 unkA2;
    s16 angleA4;
    s16 unkA6;
    f32 unkA8;
    u8 unkAC;
    u8 flagsAD;
    u8 unkAE;
    u8 unkAF;
    u8 unkB0;
    u8 unkB1[0xB5 - 0xB1];
    u8 unkB5;
    u8 unkB6;
    u8 unkB7;
    int unkB8;
    u8 unkBC;
    u8 unkBD[0xC0 - 0xBD];
    f32 posXC0;
    f32 posYC0;
    f32 posZC0;
    f32 posXCC;
    f32 posYCC;
    f32 posZCC;
    f32 unkD8;
    f32 unkDC;
    f32 unkE0;
    f32 unkE4;
    u8 unkE8;
    u8 unkE9[0xEC - 0xE9];
} AndrossState;

STATIC_ASSERT(sizeof(AndrossState) == 0xEC);
STATIC_ASSERT(offsetof(AndrossState, unk58) == 0x58);
STATIC_ASSERT(offsetof(AndrossState, unk98) == 0x98);

#endif /* MAIN_DLL_ANDROSS_H_ */
