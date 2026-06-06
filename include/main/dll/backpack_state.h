#ifndef MAIN_DLL_BACKPACK_STATE_H_
#define MAIN_DLL_BACKPACK_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * BackpackState - the obj+0xB8 extra record ("aux") for backpack.c.
 * Field widths mirror the deref widths observed there; unobserved ranges
 * are padded. The span covers every observed access - the true
 * allocation may be larger.
 */
typedef struct BackpackState {
    u8 unk0[0x268 - 0x0];
    u16 unk268;
    s16 unk26A;
    f32 unk26C;
    f32 unk270;
    u8 unk274[0x278 - 0x274];
    u8 unk278;
    u8 unk279;
    u8 unk27A;
    u8 unk27B[0x27C - 0x27B];
    s16 unk27C;
    s16 unk27E;
    u8 unk280[0x284 - 0x280];
    int *unk284;
    f32 unk288;
    f32 unk28C;
    f32 *unk290;
    f32 unk294;
    s16 unk298;
    s16 unk29A;
    f32 unk29C;
    f32 unk2A0;
    u8 unk2A4[0x2A8 - 0x2A4];
} BackpackState;

STATIC_ASSERT(offsetof(BackpackState, unk27C) == 0x27C);

#endif /* MAIN_DLL_BACKPACK_STATE_H_ */
