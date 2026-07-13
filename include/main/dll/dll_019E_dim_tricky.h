#ifndef MAIN_DLL_DLL_019E_DIM_TRICKY_H_
#define MAIN_DLL_DLL_019E_DIM_TRICKY_H_

#include "ghidra_import.h"
#include "main/game_object.h"

typedef struct Dll19ESetup Dll19ESetup;

int dll_19E_getExtraSize(void);
int dll_19E_getObjectTypeId(void);
void dll_19E_free(GameObject* obj);
void dll_19E_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_19E_hitDetect(void);
void dll_19E_update(void* obj);
void dll_19E_init(u8* obj, Dll19ESetup* setup);
void dll_19E_release(void);
void dll_19E_initialise(void);

#endif /* MAIN_DLL_DLL_019E_DIM_TRICKY_H_ */
