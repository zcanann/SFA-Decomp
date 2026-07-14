#ifndef MAIN_DLL_BOULDER_H_
#define MAIN_DLL_BOULDER_H_

#include "global.h"
#include "main/game_object.h"

typedef struct BoulderShakeRec
{
    u8 pad0[0x04 - 0x00];
    f32 histX0;
    f32 histX1;
    f32 histX2;
    f32 histX3;
    f32 histY0;
    f32 histY1;
    f32 histY2;
    f32 histY3;
    f32 histZ0;
    f32 histZ1;
    f32 histZ2;
    f32 histZ3;
    f32 liveX;
    f32 liveY;
    f32 liveZ;
    u8 pad40[0x44 - 0x40];
    f32 amplitude;
} BoulderShakeRec;

STATIC_ASSERT(offsetof(BoulderShakeRec, histX0) == 0x04);
STATIC_ASSERT(offsetof(BoulderShakeRec, histY0) == 0x14);
STATIC_ASSERT(offsetof(BoulderShakeRec, histZ0) == 0x24);
STATIC_ASSERT(offsetof(BoulderShakeRec, liveX) == 0x34);
STATIC_ASSERT(offsetof(BoulderShakeRec, amplitude) == 0x44);

void fn_801F4ECC(GameObject* obj, BoulderShakeRec* record);

#endif /* MAIN_DLL_BOULDER_H_ */
