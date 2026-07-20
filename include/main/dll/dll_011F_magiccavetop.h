#ifndef MAIN_DLL_DLL_011F_MAGICCAVETOP_H_
#define MAIN_DLL_DLL_011F_MAGICCAVETOP_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct MagicCaveTopSetup
{
    ObjPlacement base;
    u8 outerRange;
    u8 innerRange;
    u8 objectGroup;
    u8 mapAct;
    s16 visibleGameBit;
    u8 lockDirId;
    u8 mapId;
    s8 warpMapId;
    s8 warpGameBitValue;
    u8 skipMapLoad;
    u8 rotation;
    s16 textureSwapGameBit;
    u8 pad26[2];
} MagicCaveTopSetup;

typedef struct MagicCaveTopState
{
    u8 phase;
    u8 flags;
    u8 rumbleState;
    u8 pad03;
    f32 fadeTimer;
    f32 rumbleTimer;
} MagicCaveTopState;

STATIC_ASSERT(sizeof(MagicCaveTopSetup) == 0x28);
STATIC_ASSERT(offsetof(MagicCaveTopSetup, outerRange) == 0x18);
STATIC_ASSERT(offsetof(MagicCaveTopSetup, visibleGameBit) == 0x1c);
STATIC_ASSERT(offsetof(MagicCaveTopSetup, rotation) == 0x23);
STATIC_ASSERT(offsetof(MagicCaveTopSetup, textureSwapGameBit) == 0x24);
STATIC_ASSERT(sizeof(MagicCaveTopState) == 0xc);
STATIC_ASSERT(offsetof(MagicCaveTopState, fadeTimer) == 0x4);
STATIC_ASSERT(offsetof(MagicCaveTopState, rumbleTimer) == 0x8);

int MagicCaveTop_getExtraSize(void);
void MagicCaveTop_free(GameObject* obj);
void MagicCaveTop_update(GameObject* obj);
void MagicCaveTop_init(GameObject* obj, MagicCaveTopSetup* setup);

#endif /* MAIN_DLL_DLL_011F_MAGICCAVETOP_H_ */
