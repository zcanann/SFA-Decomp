#ifndef MAIN_DLL_DLL_1D1_H_
#define MAIN_DLL_DLL_1D1_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

int TreeBird_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int treebird_getExtraSize(void);
void treebird_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void treebird_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_1D1_H_ */
