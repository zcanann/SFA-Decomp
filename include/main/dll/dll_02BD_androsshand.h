#ifndef MAIN_DLL_DLL_02BD_ANDROSSHAND_H_
#define MAIN_DLL_DLL_02BD_ANDROSSHAND_H_

#include "global.h"
#include "main/obj_placement.h"

/*
 * Per-object extra state for an Andross hand
 * (AndrossHand_getExtraSize == 0x2C).
 */
typedef struct AndrossHandState
{
    int androssObj;        /* 0x00: cached Andross body GameObject */
    int arwingObj;         /* 0x04: cached player Arwing GameObject */
    u8 pad08[0x14 - 0x08]; /* 0x08-0x13: unknown */
    f32 animSpeed;         /* 0x14 */
    f32 zSpringOffset;     /* 0x18 */
    f32 zSpringVelocity;   /* 0x1C */
    s16 shotTimer;         /* 0x20 */
    u8 sideFlag;           /* 0x22: setup[0x1B], left/right hand select */
    s8 handState;          /* 0x23: read signed, written via *(u8*)& */
    s8 prevState;          /* 0x24: read signed, written via *(u8*)& */
    u8 health;             /* 0x25 */
    u8 hitCooldown;        /* 0x26 */
    u8 startupDelay;       /* 0x27 */
    u8 damageTextureState; /* 0x28: 0 clean, 1 hit-flash, 2 destroyed */
    u8 soundGate;          /* 0x29: one-shot gate for per-move sfx */
    u8 pad2A[2];
} AndrossHandState;

/* Spawn-setup buffer for an Andross-hand shot: ObjPlacement head (pos/color)
 * plus the class-specific yaw/pitch/flag bytes the parent seeds at +0x18. */
typedef struct AndrossHandShotSetup
{
    ObjPlacement head; /* 0x00: pos/color/mapId */
    u8 flag18;         /* 0x18 */
    u8 pitch;          /* 0x19 */
    u8 yaw;            /* 0x1a */
} AndrossHandShotSetup;

STATIC_ASSERT(offsetof(AndrossHandState, animSpeed) == 0x14);
STATIC_ASSERT(offsetof(AndrossHandState, shotTimer) == 0x20);
STATIC_ASSERT(offsetof(AndrossHandState, handState) == 0x23);
STATIC_ASSERT(offsetof(AndrossHandState, soundGate) == 0x29);
STATIC_ASSERT(sizeof(AndrossHandState) == 0x2C);

#endif /* MAIN_DLL_DLL_02BD_ANDROSSHAND_H_ */
