#ifndef MAIN_DLL_DLL_0101_TRICKYGUARD_H_
#define MAIN_DLL_DLL_0101_TRICKYGUARD_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct TrickyGuardPlacement
{
    ObjPlacement base;
    u8 rotXByte; /* 0x18: high byte of anim.rotX */
    u8 pad19;
    s16 armingGameBit; /* 0x1A: -1 = always armed */
    u8 pad1C[0x20 - 0x1C];
} TrickyGuardPlacement;

STATIC_ASSERT(sizeof(TrickyGuardPlacement) == 0x20);
STATIC_ASSERT(offsetof(TrickyGuardPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(TrickyGuardPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(TrickyGuardPlacement, armingGameBit) == 0x1A);

void TrickyGuard_update(GameObject* obj);
void TrickyGuard_init(GameObject* obj, TrickyGuardPlacement* placement);

extern ObjectDescriptor gTrickyGuardObjDescriptor;

#endif /* MAIN_DLL_DLL_0101_TRICKYGUARD_H_ */
