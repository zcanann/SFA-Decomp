#ifndef MAIN_DLL_SP_SPSHOPKEEPER_H_
#define MAIN_DLL_SP_SPSHOPKEEPER_H_

#include "ghidra_import.h"

typedef struct ShopkeeperLevelControlState {
    s32 flags;
    u8 earlySceneDelay;
    u8 unk5;
    u8 thornTailState;
    u8 unk7;
    u8 unk8[0xa];
    s16 mapOverride;
} ShopkeeperLevelControlState;

void SH_LevelControl_doThornTailEvents(int obj, ShopkeeperLevelControlState *state);
void SH_LevelControl_doEarlyScenes(int obj, ShopkeeperLevelControlState *state);

#endif /* MAIN_DLL_SP_SPSHOPKEEPER_H_ */
