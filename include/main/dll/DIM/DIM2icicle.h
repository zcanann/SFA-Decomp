#ifndef MAIN_DLL_DIM_DIM2ICICLE_H_
#define MAIN_DLL_DIM_DIM2ICICLE_H_

#include "main/dll/DIM/dll_01E0_dimboss.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"

extern PartFxSpawnParams gDim2IcicleDustFxSource;

void DIM2icicle_updateBossSequenceEffects(DIMbossObject *obj, DIMbossRuntime *runtime);
void DIM2icicle_updateDarkIceMinesWarpAndEffects(DIMbossObject *obj, DIMbossRuntime *runtime);
void DIM2icicle_updateHitResponse();
void DIM2icicle_updateCombatState(DIMbossObject *obj, ObjAnimUpdateState *animUpdate,
                                  DIMbossRuntime *runtime, DIMbossRuntime *updateRuntime);

#endif /* MAIN_DLL_DIM_DIM2ICICLE_H_ */
