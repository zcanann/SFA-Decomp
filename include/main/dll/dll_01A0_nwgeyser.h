#ifndef MAIN_DLL_PED_H_
#define MAIN_DLL_PED_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

f32* fn_801CDE70(GameObject* obj);
void nw_geyser_free(int* obj);
void nw_geyser_init(GameObject* obj);
void nw_geyser_update(GameObject* obj);
int NW_geyser_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int nw_mammoth_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_PED_H_ */
