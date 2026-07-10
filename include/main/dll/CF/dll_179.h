#ifndef MAIN_DLL_CF_DLL_179_H_
#define MAIN_DLL_CF_DLL_179_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

void CFCrate_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
int CFCrate_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void CFCrate_hitDetect(void);

#endif /* MAIN_DLL_CF_DLL_179_H_ */
