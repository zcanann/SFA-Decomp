#ifndef MAIN_DLL_CFPRISONGUARDSTATE_STRUCT_H_
#define MAIN_DLL_CFPRISONGUARDSTATE_STRUCT_H_

#include "types.h"

typedef struct CfPrisonGuardState
{
    u8 pad00[0x30];
    f32 alarmRamp; /* particle ramp advanced while above threshold */
    s16 stateTimer;
    s8 capturedLatch; /* last GameBit 0x50 value */
    s8 guardState; /* 0 idle .. 7 forced-chase */
    u8 flags; /* 1 spawn-pulse pending, 2 freed-check, 4 alarm raised */
    u8 flags39; /* 0x80 cleared every update */
    u8 pad3A[2];
} CfPrisonGuardState;

#endif
