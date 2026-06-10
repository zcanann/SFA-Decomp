#ifndef MAIN_DLL_CFPERCH_STATE_H_
#define MAIN_DLL_CFPERCH_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * CfperchState - the obj+0xB8 extra record for cfperch.c. Field widths
 * mirror the deref widths observed there; unobserved ranges are padded.
 * The span covers every observed access - the true allocation may be
 * larger.
 */
typedef struct CfperchState {
    s16 unk0;
    s16 unk2;
    u8 unk4[0x5 - 0x4];
    s8 unk5;
    u8 bool6;
    u8 unk7[0x9 - 0x7];
    u8 unk9;
    s16 unkA;
    s16 unkC;
    s16 randomTimer;
    s16 unk10;
    s16 unk12;
    int timer14;
    int unk18;
    s16 enableGameBit;
    u8 unk1E;
    u8 unk1F;
    u8 unk20;
    u8 unk21[0x28 - 0x21];
} CfperchState;

STATIC_ASSERT(offsetof(CfperchState, timer14) == 0x14);

#endif /* MAIN_DLL_CFPERCH_STATE_H_ */
