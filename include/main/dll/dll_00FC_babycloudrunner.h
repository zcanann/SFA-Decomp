#ifndef MAIN_DLL_DLL_00FC_BABYCLOUDRUNNER_H_
#define MAIN_DLL_DLL_00FC_BABYCLOUDRUNNER_H_

#include "main/game_object.h"
#include "ghidra_import.h"

void dll_FC_update(GameObject* obj);
void dll_FC_init(GameObject* obj, int objDef);
int dll_FC_getExtraSize_ret_8(void);
int dll_FC_getObjectTypeId(void);
void dll_FC_free_nop(void);
void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_FC_release_nop(void);
void dll_FC_initialise_nop(void);
void dll_FC_hitDetect(int* obj);
void dll_FD_hitDetect(GameObject* obj);
void dll_FD_free(void);
void dll_FD_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
int dll_FD_getExtraSize(void);

#endif /* MAIN_DLL_DLL_00FC_BABYCLOUDRUNNER_H_ */
