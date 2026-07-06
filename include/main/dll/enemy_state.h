#ifndef MAIN_DLL_ENEMY_STATE_H_
#define MAIN_DLL_ENEMY_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * EnemyState - the obj+0xB8 extra record for the enemy_* family in
 * projswitch.c. Field widths mirror the deref widths observed there;
 * unobserved ranges are padded. The span covers every observed access -
 * the true allocation may be larger.
 */
typedef struct EnemyState {
    u8 unk0[0x4 - 0x0];
    u32 flags;
    u8 unk8[0x29C - 0x8];
    u8 *trackedObj;
    u8 unk2A0[0x2A8 - 0x2A0];
    f32 aggroRange; /* 0x2A8 engagement/aggro range (= setup[0x29]<<3): the enemy
                       only attacks once the target is within this, even though it
                       can SEE out to enemySightRange. live-confirmed. NOTE: the
                       shared BaddieState+0x2A8 is a generic per-type radius/distance
                       param (magicplant/seqobj: circular-motion radius; baskets:
                       per-state config) - hence the per-type struct view here. */
    f32 sightRange; /* 0x2AC patrol/detection range, clamped to enemySightRange
                       (the global sight extent) just like aggroRange; passed to
                       RomCurve initCurve as the wander-curve radius. */
    s16 unk2B0;
    u16 unk2B2;
    s16 unk2B4;
    s16 unk2B6;
    u8 unk2B8[0x2D8 - 0x2B8];
    f32 freezeRecoverTimer;
    u32 controlFlags;
    int initialFlags;
    u32 flags2E4;
    int flags2E8;
    s16 unk2EC;
    u8 unk2EE[0x2F2 - 0x2EE];
    u8 curveIndex; /* 0x2F2: selector index -> *outIdx */
    u8 curveParamA; /* 0x2F3: byte scaled by 1/lbl_803E257C -> *outA */
    u8 curveParamB; /* 0x2F4: byte -> *outB */
    u8 unk2F5[0x2F8 - 0x2F5];
    s16 unk2F8;
    u8 unk2FA[0x2FC - 0x2FA];
    f32 health; /* 0x2FC: placement.healthByte / const, the enemy's HP */
    f32 animDeltaScale;
    f32 unk304;
    f32 unk308;
    f32 particleScale;
    f32 unk310;
    u8 unk314[0x324 - 0x314];
    f32 unk324;
    f32 unk328;
    f32 unk32C;
    f32 unk330;
    f32 intervalTimer;
    s16 phaseAngle;
    u8 unk33A[0x340 - 0x33A];
    int lastHitObject;
    u8 unk344[0x368 - 0x344];
    int modelLight;
    int tailSimHandle;
    u8 unk370[0x374 - 0x370];
} EnemyState;

STATIC_ASSERT(offsetof(EnemyState, aggroRange) == 0x2A8);

#endif /* MAIN_DLL_ENEMY_STATE_H_ */
