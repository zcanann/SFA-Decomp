#ifndef MAIN_DLL_TRICKYCURVE_H_
#define MAIN_DLL_TRICKYCURVE_H_

#include "ghidra_import.h"

void TrickyCurve_updateBurstTrigger(void);
void TrickyCurve_updateBoundsTrigger(int param_1);
void TrickyCurve_updateEffectRingTrigger(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                         undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                         undefined8 param_7,undefined8 param_8);
void TrickyCurve_updateEffectHandleRing(int obj);
int sfxplayer_ensureEffectHandlePair(int obj, u8 ringIndex);
int TrickyCurve_activateEffectHandleRing(int obj, int unused, u8 *eventData);
void FUN_80207c10(void);
void TrickyCurve_updateState(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                             undefined8 param_4,undefined8 param_5,undefined8 param_6,
                             undefined8 param_7,undefined8 param_8,int param_9);

#endif /* MAIN_DLL_TRICKYCURVE_H_ */
