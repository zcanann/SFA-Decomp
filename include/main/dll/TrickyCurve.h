#ifndef MAIN_DLL_TRICKYCURVE_H_
#define MAIN_DLL_TRICKYCURVE_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

void TrickyCurve_updateBurstTrigger(GameObject* obj);
void TrickyCurve_updateBoundsTrigger(int param_1);
void TrickyCurve_updateEffectRingTrigger(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6,
                                         u64 param_7, u64 param_8);
void TrickyCurve_updateEffectHandleRing(GameObject* obj);
int sfxplayer_ensureEffectHandlePair(GameObject* obj, u8 ringIndex);
int TrickyCurve_activateEffectHandleRing(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void FUN_80207c10(int obj);
void TrickyCurve_updateState(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                             u64 param_8, int param_9);

#endif /* MAIN_DLL_TRICKYCURVE_H_ */
