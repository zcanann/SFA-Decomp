#ifndef MAIN_DLL_LGT_LGTPROJECTEDLIGHT_H_
#define MAIN_DLL_LGT_LGTPROJECTEDLIGHT_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

void WM_LevelControl_update(GameObject* obj);
int WM_GeneralScales_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_LGT_LGTPROJECTEDLIGHT_H_ */
