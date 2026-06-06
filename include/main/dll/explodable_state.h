#ifndef MAIN_DLL_EXPLODABLE_STATE_H_
#define MAIN_DLL_EXPLODABLE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * ExplodableState - the obj+0xB8 extra record for explodable.c. Field
 * widths mirror the deref widths observed there; unobserved ranges are
 * padded. The span covers every observed access - the true allocation
 * may be larger.
 */
typedef struct ExplodableState {
    u8 unk0[0x4 - 0x0];
    f32 unk4;
    s16 unk8;
    s16 unkA;
    u8 unkC[0x13 - 0xC];
    u8 unk13;
    s16 unk14;
    s16 unk16;
    s16 unk18;
    u8 unk1A[0x28 - 0x1A];
    u8 unk28;
    u8 unk29[0x30 - 0x29];
} ExplodableState;

STATIC_ASSERT(offsetof(ExplodableState, unk14) == 0x14);

#endif /* MAIN_DLL_EXPLODABLE_STATE_H_ */
