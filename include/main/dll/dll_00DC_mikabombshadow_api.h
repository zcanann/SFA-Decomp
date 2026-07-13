#ifndef MAIN_DLL_DLL_00DC_MIKABOMBSHADOW_API_H_
#define MAIN_DLL_DLL_00DC_MIKABOMBSHADOW_API_H_

#include "types.h"

void MikaBombShadow_free(void);
int MikaBombShadow_getExtraSize(void);
int MikaBombShadow_getObjectTypeId(void);
void MikaBombShadow_hitDetect(void);
void MikaBombShadow_init(int* obj);
void MikaBombShadow_initialise(void);
void MikaBombShadow_release(void);
void MikaBombShadow_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void MikaBombShadow_update(int* obj);

#endif /* MAIN_DLL_DLL_00DC_MIKABOMBSHADOW_API_H_ */
