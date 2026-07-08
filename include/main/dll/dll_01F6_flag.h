#ifndef MAIN_DLL_DLL_01F6_FLAG_H_
#define MAIN_DLL_DLL_01F6_FLAG_H_

#include "global.h"

int Flag_getExtraSize(void);
int Flag_getObjectTypeId(void);
void Flag_free(void);
void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void Flag_hitDetect(void);
void Flag_update(int obj);
void Flag_init(int* obj, int* def);
void Flag_release(void);
void Flag_initialise(void);

#endif /* MAIN_DLL_DLL_01F6_FLAG_H_ */
