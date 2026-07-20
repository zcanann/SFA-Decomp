#ifndef MAIN_DLL_DLL_14D_H_
#define MAIN_DLL_DLL_14D_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDll14DObjDescriptor;

int dll_FD_getExtraSize(void);
int dll_FD_getObjectTypeId(void);
void dll_FD_free(void);
void dll_FD_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_FD_hitDetect(GameObject* obj);
void dll_FD_update(u16 *param_1);
void dll_FD_init(int *obj);
void magicPlantDropGem(int obj, void *setup, void *state);

#endif /* MAIN_DLL_DLL_14D_H_ */
