#ifndef MAIN_DLL_BARRELGENER_STATE_H_
#define MAIN_DLL_BARRELGENER_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct GameObject GameObject;

typedef struct BarrelGeneratorState {
    GameObject *queuedObject;
    u8 releaseAnimPlaying;
    u8 pad05[3];
    f32 releaseTimer;
    u8 releaseBeepPlayed;
    u8 pad0D[3];
} BarrelGeneratorState;

STATIC_ASSERT(offsetof(BarrelGeneratorState, queuedObject) == 0x0);
STATIC_ASSERT(offsetof(BarrelGeneratorState, releaseAnimPlaying) == 0x4);
STATIC_ASSERT(offsetof(BarrelGeneratorState, releaseTimer) == 0x8);
STATIC_ASSERT(offsetof(BarrelGeneratorState, releaseBeepPlayed) == 0xC);
STATIC_ASSERT(sizeof(BarrelGeneratorState) == 0x10);

#endif
