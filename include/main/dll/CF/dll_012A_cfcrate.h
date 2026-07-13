#ifndef MAIN_DLL_CF_DLL_012A_CFCRATE_H_
#define MAIN_DLL_CF_DLL_012A_CFCRATE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

int CFCrate_getExtraSize(void);
int CFCrate_getObjectTypeId(void);
void CFCrate_free(int obj);
void CFCrate_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
int CFCrate_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void CFCrate_hitDetect(void);
void CFCrate_update(GameObject* obj);
void CFCrate_init(GameObject* obj, int aux);
void CFCrate_release(void);
void CFCrate_initialise(void);

#endif /* MAIN_DLL_CF_DLL_012A_CFCRATE_H_ */
