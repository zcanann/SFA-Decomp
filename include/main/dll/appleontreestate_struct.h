#ifndef MAIN_DLL_APPLEONTREESTATE_STRUCT_H_
#define MAIN_DLL_APPLEONTREESTATE_STRUCT_H_

#include "types.h"

typedef struct AppleOnTreeState
{
    u8 unk00[4];
    f32 phaseDuration;
    f32 elapsedTime;
    f32 flightTime;
    f32 growThreshold;
    u8 unk14[0x20 - 0x14];
    f32 fadeThreshold;
    f32 unk24;
    f32 velY;
    f32 posY;
    f32 dropHeight;
    f32 splashPosY;
    u16 healthRestore;
    u8 animState;
    u8 pad3B;
    f32 unk3C;
    f32 gravity;
    f32 bounceVel;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad4E[2];
    f32 totalFlightTime;
    u8 pad54[6];
    u8 flags;
    u8 pad5B;
    s16 unk5C;
    s16 unk5E;
    f32 unk60;
} AppleOnTreeState;

#endif
