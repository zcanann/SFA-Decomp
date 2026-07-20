#ifndef MAIN_DLL_DLL_011E_MAGICCAVEBOTTOM_H_
#define MAIN_DLL_DLL_011E_MAGICCAVEBOTTOM_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct MagicCaveBottomSetup
{
    ObjPlacement base;
    u8 pad18[2];
    u8 rotation;
    u8 sequenceBank;
    u8 pad1C[4];
} MagicCaveBottomSetup;

typedef struct MagicCaveBottomState
{
    u8 phase;
} MagicCaveBottomState;

STATIC_ASSERT(sizeof(MagicCaveBottomSetup) == 0x20);
STATIC_ASSERT(offsetof(MagicCaveBottomSetup, rotation) == 0x1a);
STATIC_ASSERT(offsetof(MagicCaveBottomSetup, sequenceBank) == 0x1b);
STATIC_ASSERT(sizeof(MagicCaveBottomState) == 1);

int MagicCaveBottom_getExtraSize(void);
void MagicCaveBottom_free(GameObject* obj);
void MagicCaveBottom_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_011E_MAGICCAVEBOTTOM_H_ */
