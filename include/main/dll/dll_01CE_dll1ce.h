#ifndef MAIN_DLL_DLL_01CE_DLL1CE_H_
#define MAIN_DLL_DLL_01CE_DLL1CE_H_

#include "main/game_object.h"
#include "main/dll/dll1ceplacement_struct.h"

int dll_1CE_getExtraSize(void);
int dll_1CE_getObjectTypeId(void);
void dll_1CE_free(void);
void dll_1CE_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_1CE_hitDetect(void);
void dll_1CE_update(GameObject* obj);
void dll_1CE_init(GameObject* obj, Dll1CEPlacement* placement);
void dll_1CE_release(void);
void dll_1CE_initialise(void);

extern void* gDll1CEResource;

#endif /* MAIN_DLL_DLL_01CE_DLL1CE_H_ */
