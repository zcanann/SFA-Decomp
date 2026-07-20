#ifndef MAIN_DLL_DLL_00CC_CHUKCHUK_H_
#define MAIN_DLL_DLL_00CC_CHUKCHUK_H_

#include "main/object_descriptor.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct ChukChukPlacement
{
    ObjPlacement base;
    s16 gameBit;
    u8 pad1A[0x22 - 0x1A];
    s16 unk22;
    u8 pad24[0x27 - 0x24];
    u8 aimHeightY;
    s8 arcHalfAngleScale;
    u8 triggerDistanceScale;
    s8 rotX;
    u8 pad2B[0x2F - 0x2B];
    u8 attackChance;
    u8 pad30[0x32 - 0x30];
    u8 hitsLeft;
    u8 pad33[0x38 - 0x33];
} ChukChukPlacement;

STATIC_ASSERT(offsetof(ChukChukPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(ChukChukPlacement, unk22) == 0x22);
STATIC_ASSERT(offsetof(ChukChukPlacement, aimHeightY) == 0x27);
STATIC_ASSERT(offsetof(ChukChukPlacement, arcHalfAngleScale) == 0x28);
STATIC_ASSERT(offsetof(ChukChukPlacement, triggerDistanceScale) == 0x29);
STATIC_ASSERT(offsetof(ChukChukPlacement, rotX) == 0x2A);
STATIC_ASSERT(offsetof(ChukChukPlacement, attackChance) == 0x2F);
STATIC_ASSERT(offsetof(ChukChukPlacement, hitsLeft) == 0x32);
STATIC_ASSERT(sizeof(ChukChukPlacement) == 0x38);

void chukChuk_spawnAimedIceBall(GameObject* obj);
extern ObjectDescriptor11WithPadding gChukChukObjDescriptor;

#endif
