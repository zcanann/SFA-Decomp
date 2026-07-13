#ifndef MAIN_DLL_DLL_019D_DLL19D_H_
#define MAIN_DLL_DLL_019D_DLL19D_H_

#include "ghidra_import.h"
#include "main/game_object.h"

int dll_19D_getExtraSize(void);
int dll_19D_getObjectTypeId(void);
void dll_19D_free(GameObject* obj);
void dll_19D_render(void);
void dll_19D_hitDetect(GameObject* obj);
void dll_19D_update(GameObject* obj);
void dll_19D_init(GameObject* obj);
void dll_19D_release(void);
void dll_19D_initialise(void);

#endif /* MAIN_DLL_DLL_019D_DLL19D_H_ */
