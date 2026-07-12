#ifndef MAIN_DLL_LAVABALL1BESTATE_STRUCT_H_
#define MAIN_DLL_LAVABALL1BESTATE_STRUCT_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ModelLightStruct ModelLightStruct;

typedef struct Lavaball1beState
{
    GameObject* targetObj; /* 0x00: ObjList_FindObjectById(linkedId) */
    ModelLightStruct* light; /* 0x04 */
    f32 floorY; /* 0x08: spawn height; falling below it re-arms */
    int linkedId; /* 0x0c */
    u8 flags; /* 0x10: 8 = ticked, 0x10 = dormant, 0x20 = whistle sfx */
    u8 explodeCooldown; /* 0x11 */
    u8 pad12[2];
} Lavaball1beState;

#endif
