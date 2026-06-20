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
    u16 distToTarget;
    s16 unk26A;
    f32 targetScale;
    f32 growRate; /* scale/frame while growing; reused as a seconds countdown in later phases */
    u8 unk274[0x278 - 0x274];
    u8 phase;
    u8 unk279;
    u8 flags;
    u8 unk27B[0x27C - 0x27B];
    s16 recoilVelX;
    s16 recoilVelZ;
    u8 unk280[0x284 - 0x280];
    int *targetObj;
    f32 anchorPosX;
    f32 anchorPosZ;
    f32 *targetPos;
    f32 unk294;
    s16 unk298;
    s16 unk29A;
    f32 unk29C;
    f32 phaseTimer;
    u8 unk2A4[0x2A8 - 0x2A4];
} BackpackState;

STATIC_ASSERT(sizeof(BackpackState) == 0x2A8);
STATIC_ASSERT(offsetof(BackpackState, distToTarget) == 0x268);
STATIC_ASSERT(offsetof(BackpackState, unk26A) == 0x26A);
STATIC_ASSERT(offsetof(BackpackState, targetScale) == 0x26C);
STATIC_ASSERT(offsetof(BackpackState, growRate) == 0x270);
STATIC_ASSERT(offsetof(BackpackState, phase) == 0x278);
STATIC_ASSERT(offsetof(BackpackState, unk279) == 0x279);
STATIC_ASSERT(offsetof(BackpackState, flags) == 0x27A);
STATIC_ASSERT(offsetof(BackpackState, recoilVelX) == 0x27C);
STATIC_ASSERT(offsetof(BackpackState, targetObj) == 0x284);
STATIC_ASSERT(offsetof(BackpackState, anchorPosX) == 0x288);
STATIC_ASSERT(offsetof(BackpackState, anchorPosZ) == 0x28C);
STATIC_ASSERT(offsetof(BackpackState, targetPos) == 0x290);
STATIC_ASSERT(offsetof(BackpackState, unk294) == 0x294);
STATIC_ASSERT(offsetof(BackpackState, unk298) == 0x298);
STATIC_ASSERT(offsetof(BackpackState, unk29A) == 0x29A);
STATIC_ASSERT(offsetof(BackpackState, unk29C) == 0x29C);
STATIC_ASSERT(offsetof(BackpackState, phaseTimer) == 0x2A0);

#endif /* MAIN_DLL_BACKPACK_STATE_H_ */
