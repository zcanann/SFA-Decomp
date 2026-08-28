#ifndef MAIN_CARRYABLE_STATE_H_
#define MAIN_CARRYABLE_STATE_H_

#include "global.h"

typedef enum CarryableCarryState {
    CARRY_STATE_RESTING = 0,
    CARRY_STATE_GRABBED = 1,
    CARRY_STATE_PUTDOWN = 2
} CarryableCarryState;

typedef enum CarryableStateFlags {
    CARRYABLE_FLAG_JUST_GRABBED = 0x01,
    CARRYABLE_FLAG_GRAVITY_DISABLED = 0x02,
    CARRYABLE_FLAG_DROP_DISABLED = 0x04,
    CARRYABLE_FLAG_SUPPRESS_POS_SAVE = 0x08
} CarryableStateFlags;

typedef struct CarryableState {
    s16 unk00;
    s16 unk02;
    u8 unk04;
    s8 carryState;
    u8 isHeld;
    u8 flags;
    u8 surfaceType;
    u8 unk09;
} CarryableState;

STATIC_ASSERT(offsetof(CarryableState, unk00) == 0x00);
STATIC_ASSERT(offsetof(CarryableState, unk02) == 0x02);
STATIC_ASSERT(offsetof(CarryableState, unk04) == 0x04);
STATIC_ASSERT(offsetof(CarryableState, carryState) == 0x05);
STATIC_ASSERT(offsetof(CarryableState, isHeld) == 0x06);
STATIC_ASSERT(offsetof(CarryableState, flags) == 0x07);
STATIC_ASSERT(offsetof(CarryableState, surfaceType) == 0x08);
STATIC_ASSERT(offsetof(CarryableState, unk09) == 0x09);
STATIC_ASSERT(sizeof(CarryableState) == 0x0A);

#endif /* MAIN_CARRYABLE_STATE_H_ */
