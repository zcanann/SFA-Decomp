#ifndef MAIN_DLL_STAFFACTION_H_
#define MAIN_DLL_STAFFACTION_H_

#include "main/game_object.h"
#include "ghidra_import.h"

void dll_D3_initialise(void);
void dll_D3_release_nop(void);
void dll_D3_init(GameObject* obj, int def, int flag);
void dll_D3_update(int* obj);
void dll_D3_hitDetect_nop(void);
void dll_D3_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_D3_free(int obj);
int dll_D3_getObjectTypeId(void);
int dll_D3_getExtraSize_ret_1188(void);

/* extern-cleanup: defining-file public prototypes */
void fn_80167550(GameObject* obj, GameObject* otherObj);

#endif /* MAIN_DLL_STAFFACTION_H_ */
