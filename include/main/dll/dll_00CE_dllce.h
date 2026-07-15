#ifndef MAIN_DLL_DLL_00CE_DLLCE_H_
#define MAIN_DLL_DLL_00CE_DLLCE_H_

#include "main/game_object.h"

void fn_8015ED1C(int obj, int state, int target);
void fn_8015EB6C(GameObject* obj, int state, int target);
void dll_CE_func0B(GameObject* obj, int v);
s16 dll_CE_setScale(int* obj);
int dll_CE_getExtraSize_ret_1052(void);
int dll_CE_getObjectTypeId(void);
void dll_CE_free(int* obj);
void dll_CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_CE_hitDetect_nop(void);
void dll_CE_update(GameObject* obj, int unusedA, int unusedB);
void dll_CE_init(GameObject* obj, u8* def, int flags);
void dll_CE_release_nop(void);
void dll_CE_initialise(void);

#endif
