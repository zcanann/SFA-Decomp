#ifndef MAIN_DLL_DR_DRPICKUP_H_
#define MAIN_DLL_DR_DRPICKUP_H_

#include "ghidra_import.h"
#include "global.h"

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct PickupFlags {
    u8 b7 : 1;  /* 0x80 (sign bit) */
    u8 b6 : 1;  /* 0x40 */
    u8 b5 : 1;  /* 0x20 */
    u8 b4 : 1;  /* 0x10 */
    u8 b3 : 1;  /* 0x08 */
    u8 b2 : 1;  /* 0x04 */
    u8 b1 : 1;  /* 0x02 */
    u8 b0 : 1;  /* 0x01 */
} PickupFlags;

/*
 * DRpickup per-object state (the obj+0xB8 extra block) as seen from
 * fn_801EC1AC. Only the pure-constant-offset scalar fields touched there
 * are named; the matrix bases at 0x6C/0x12C and the address-taken sites
 * are kept raw, so the head region is padded. Extent past 0x588 unknown.
 */
typedef struct DRPickupState {
    u8 unk0[0x40C - 0x0]; /* incl. matrices at 0x6C/0x12C (address-taken, raw) */
    s16 angle40C; /* chased toward angle40E with overflow normalization */
    s16 angle40E; /* integrated from angVel414 * timeDelta */
    u32 angAccum410; /* angular accumulator (overflow-normalized) */
    f32 angVel414; /* angular velocity */
    u8 unk418[0x428 - 0x418];
    PickupFlags flags; /* 0x428 */
    u8 unk429[0x430 - 0x429];
    f32 unk430; /* lerp toward unk538 when flags.b6 */
    u8 unk434[0x458 - 0x434];
    u32 flags458; /* bit 0x100 -> b6, 0x200 -> b4 */
    f32 unk45C;
    u8 unk460[0x47C - 0x460];
    f32 clampLimitX; /* 0x47C clamp limit for accumX */
    f32 clampLimitY; /* 0x480 clamp limit for accumY */
    f32 clampLimitZ; /* 0x484 clamp limit for accumZ */
    u8 unk488[0x494 - 0x488];
    f32 accumX; /* 0x494 accumulated vector x (also address-taken, raw) */
    f32 accumY; /* 0x498 */
    f32 accumZ; /* 0x49C */
    f32 localOffsetX; /* 0x4A0 local offset vector, fed to Matrix_TransformPoint */
    f32 localOffsetY; /* 0x4A4 */
    f32 localOffsetZ; /* 0x4A8 */
    u8 unk4AC[0x52C - 0x4AC];
    f32 unk52C;
    f32 unk530;
    f32 unk534; /* clamp limit for angVel414 */
    f32 unk538; /* target for unk430 */
    f32 unk53C;
    u8 unk540[0x550 - 0x540];
    f32 unk550;
    f32 unk554;
    f32 unk558;
    u8 unk55C[0x570 - 0x55C];
    f32 unk570;
    u8 unk574[0x584 - 0x574];
    f32 unk584;
    u8 unk588[4];
} DRPickupState;

STATIC_ASSERT(offsetof(DRPickupState, angle40C) == 0x40C);
STATIC_ASSERT(offsetof(DRPickupState, flags) == 0x428);
STATIC_ASSERT(offsetof(DRPickupState, flags458) == 0x458);
STATIC_ASSERT(offsetof(DRPickupState, accumX) == 0x494);
STATIC_ASSERT(offsetof(DRPickupState, unk584) == 0x584);

void fn_801EC1AC(int param_1,int param_2);

#endif /* MAIN_DLL_DR_DRPICKUP_H_ */
