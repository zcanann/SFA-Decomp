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
    s8 carryState;       /* 0x5 carry/throw state machine: 0 idle, 1 grabbed, 2 carried */
    u8 unk6;
    u8 unk7[0x9 - 0x7];
    u8 throwState;       /* 0x9 in-flight mode: 0 none, 1 thrown, 2 dropped */
    s16 disableTimer;    /* 0xA post-action hide/disable countdown (framesThisStep) */
    s16 leashRange;      /* 0xC carry leash range from placement origin (compared squared) */
    s16 randomTimer;
    s16 sfxId;
    s16 respawnTimer;    /* 0x12 respawn countdown; on expiry scatters contents + warps home */
    int unk14;
    int unk18;
    s16 enableGameBit;
    u8 subtype;          /* 0x1E object subtype, selects ambient sfx (0x6c/0x6d) */
    u8 unk1F;
    u8 unk20;
    u8 unk21[0x28 - 0x21];
} CfperchState;

STATIC_ASSERT(offsetof(CfperchState, unk14) == 0x14);

#endif /* MAIN_DLL_CFPERCH_STATE_H_ */
