#ifndef MAIN_DLL_DLL_01A0_NWGEYSER_H_
#define MAIN_DLL_DLL_01A0_NWGEYSER_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

f32* NW_mammoth_getSpawnPosition(GameObject* obj);
void nw_geyser_free(GameObject* obj);
void nw_geyser_init(GameObject* obj);
void nw_geyser_update(GameObject* obj);
int NW_geyser_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int nw_mammoth_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_DLL_01A0_NWGEYSER_H_ */
