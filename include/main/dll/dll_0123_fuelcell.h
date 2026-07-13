#ifndef MAIN_DLL_DLL_0123_FUELCELL_H_
#define MAIN_DLL_DLL_0123_FUELCELL_H_

#include "main/game_object.h"
#include "types.h"

int FuelCell_SeqFn(int* obj);
void fuelcell_modelMtxFn(u8* model);
int FuelCell_getExtraSize(void);
void FuelCell_free(GameObject* obj);
void FuelCell_render(int* obj, int p2, int p3, int p4, int p5);
void FuelCell_update(GameObject* obj);
void FuelCell_init(GameObject* obj);

#endif /* MAIN_DLL_DLL_0123_FUELCELL_H_ */
