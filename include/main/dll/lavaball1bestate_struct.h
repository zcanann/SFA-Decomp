#ifndef MAIN_DLL_LAVABALL1BESTATE_STRUCT_H_
#define MAIN_DLL_LAVABALL1BESTATE_STRUCT_H_

#include "global.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;

typedef struct Lavaball1beState
{
    GameObject* targetObj; /* 0x00: ObjList_FindObjectById(linkedObjectId) */
    ModelLightStruct* light; /* 0x04 */
    f32 floorY; /* 0x08: spawn height; falling below it re-arms */
    int linkedObjectId; /* 0x0C */
    u8 statusFlags; /* 0x10: 8 = updated, 0x10 = inactive, 0x20 = falling */
    u8 explosionCooldown; /* 0x11 */
    u8 pad12[2];
} Lavaball1beState;

STATIC_ASSERT(offsetof(Lavaball1beState, targetObj) == 0x00);
STATIC_ASSERT(offsetof(Lavaball1beState, light) == 0x04);
STATIC_ASSERT(offsetof(Lavaball1beState, floorY) == 0x08);
STATIC_ASSERT(offsetof(Lavaball1beState, linkedObjectId) == 0x0C);
STATIC_ASSERT(offsetof(Lavaball1beState, statusFlags) == 0x10);
STATIC_ASSERT(offsetof(Lavaball1beState, explosionCooldown) == 0x11);
STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

#endif
