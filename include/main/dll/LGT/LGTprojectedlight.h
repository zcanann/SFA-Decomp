#ifndef MAIN_DLL_LGT_LGTPROJECTEDLIGHT_H_
#define MAIN_DLL_LGT_LGTPROJECTEDLIGHT_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

void FUN_801f456c(int param_1);
void FUN_801f4b64(int param_1);
void FUN_801f4bb8(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void WM_LevelControl_update(GameObject* obj);
int WM_GeneralScales_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_LGT_LGTPROJECTEDLIGHT_H_ */
