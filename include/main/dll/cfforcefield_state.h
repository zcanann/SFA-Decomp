#ifndef MAIN_DLL_CFFORCEFIELD_STATE_H_
#define MAIN_DLL_CFFORCEFIELD_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* cfforcefield_state_GENERATED
 * CfForcefieldState - the obj+0xB8 extra record observed in cfforcefield.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CfForcefieldState {
    u8 unk0[0xA - 0x0];
    s16 randomTimer;
    s16 countdown;
    s16 enableGameBit;
    u8 unk10[0x11 - 0x10];
    u8 unk11;
    u8 unk12;
    u8 unk13[0x14 - 0x13];
    s16 sfxIdA;
    s16 sfxIdB;
    u8 unk18[0x20 - 0x18];
    s16 unk20;
    u8 unk22[0x28 - 0x22];
    u8 unk28;
    u8 unk29[0x30 - 0x29];
} CfForcefieldState;

#endif /* MAIN_DLL_CFFORCEFIELD_STATE_H_ */
