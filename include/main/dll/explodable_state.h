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
    f32 animTimer;
    s16 explodeTimer;
    s16 randomTimer;
    u8 unkC[0x13 - 0xC];
    u8 damageTaken;
    s16 hitSfxId;
    s16 explodeSfxId;
    s16 spinSpeed;
    u8 unk1A[0x28 - 0x1A];
    u8 damageThreshold;
    u8 unk29[0x30 - 0x29];
} ExplodableState;

STATIC_ASSERT(offsetof(ExplodableState, hitSfxId) == 0x14);

#endif /* MAIN_DLL_EXPLODABLE_STATE_H_ */
