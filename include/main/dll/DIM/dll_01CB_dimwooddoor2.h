#ifndef MAIN_DLL_DIM_DLL_01CB_DIMWOODDOOR2_H_
#define MAIN_DLL_DIM_DLL_01CB_DIMWOODDOOR2_H_

#include "types.h"

int dimwooddoor2_getExtraSize(void);
int dimwooddoor2_getObjectTypeId(void);
void dimwooddoor2_free(void);
void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimwooddoor2_hitDetect(void);
void dimwooddoor2_update(int* obj);
void dimwooddoor2_init(u8* obj, u8* params);
void dimwooddoor2_release(void);
void dimwooddoor2_initialise(void);

#endif
