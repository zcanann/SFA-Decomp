#ifndef MAIN_DLL_DLL_01FF_DLL1FF_H_
#define MAIN_DLL_DLL_01FF_DLL1FF_H_

#include "types.h"

int dll_1FF_getExtraSize_ret_8(void);
int dll_1FF_getObjectTypeId(int* obj);
void dll_1FF_free_nop(void);
void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);
void dll_1FF_hitDetect_nop(void);
void dll_1FF_update(int obj);
void dll_1FF_init(s16* obj, s8* setup);
void dll_1FF_release_nop(void);
void dll_1FF_initialise_nop(void);

#endif /* MAIN_DLL_DLL_01FF_DLL1FF_H_ */
