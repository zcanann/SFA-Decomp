#ifndef MAIN_DLL_DR_DRSHACKLE_H_
#define MAIN_DLL_DR_DRSHACKLE_H_

#include "ghidra_import.h"
#include "main/checkpoint_route.h"

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct ShackleFlags {
    u8 unused7 : 1;       /* 0x80 (sign bit) */
    u8 unused6 : 1;       /* 0x40 */
    u8 unused5 : 1;       /* 0x20 */
    u8 unused4 : 1;       /* 0x10 */
    u8 active : 1;        /* 0x08 */
    u8 unused2 : 1;       /* 0x04 */
    u8 unused1 : 1;       /* 0x02 */
    u8 positionAnchored : 1; /* 0x01 */
} ShackleFlags;

/* Large per-shackle swing/attachment state block (the `state` byte base passed
 * to drshackle_updateSwingBlend / drshackle_updateAttachedPosition). Field
 * widths verified against the target asm; gaps are spelled as pads. */
typedef struct ShackleSwingState {
    u8 pad00[0x0C];
    f32 anchorX;               /* 0x0C: route-anchor world position */
    f32 anchorY;               /* 0x10 */
    f32 anchorZ;               /* 0x14 */
    u8 pad18[0x28 - 0x18];
    CheckpointRouteState collider; /* 0x28: route/collider state */
    u8 pad_collider_end[0x5D - (0x28 + sizeof(CheckpointRouteState))];
    u8 colliderMode;           /* 0x5D: route-advance collider mode */
    u8 pad5E[0x178 - 0x5E];
    u8 attachment[0x3E4 - 0x178]; /* 0x178: path-control attachment block */
    f32 distanceFade;          /* 0x3E4: nonzero enables distance-based blend */
    u8 pad3E8[0x40C - 0x3E8];
    s16 yaw;                   /* 0x40C: current swing yaw */
    s16 targetYaw;             /* 0x40E: target swing yaw */
    u8 pad410[0x428 - 0x410];
    ShackleFlags flags;        /* 0x428 */
    u8 pad429[0x430 - 0x429];
    f32 swingAccel;            /* 0x430 */
    u8 floorAdjustFlag;        /* 0x434: nonzero skips floor snap */
    u8 pad435[0x44C - 0x435];
    s16 swingCommand;          /* 0x44C */
    u8 pad44E[0x458 - 0x44E];
    s32 swingReturn;           /* 0x458: return-direction code */
    f32 swingBlend;            /* 0x45C: per-frame swing-blend factor */
    u8 pad460[0x494 - 0x460];
    f32 unk494;                /* 0x494: zeroed on anchor */
    f32 unk498;                /* 0x498 */
    f32 lastPitch;             /* 0x49C */
} ShackleSwingState;

int drshackle_updateSwingBlend(int obj, int state);
int drshackle_updateAttachedPosition(int obj, int state);

#endif /* MAIN_DLL_DR_DRSHACKLE_H_ */
