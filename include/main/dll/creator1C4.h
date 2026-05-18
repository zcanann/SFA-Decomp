#ifndef MAIN_DLL_CREATOR1C4_H_
#define MAIN_DLL_CREATOR1C4_H_

#include "ghidra_import.h"

void gpsh_shrine_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void gpsh_shrine_init(void);
void gpsh_shrine_release(void);
void gpsh_shrine_initialise(void);

int gpsh_objcreator_getExtraSize(void);
int gpsh_objcreator_func08(void);
void gpsh_objcreator_free(void);
void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void gpsh_objcreator_hitDetect(void);
void gpsh_objcreator_update(void);
void gpsh_objcreator_init(void);
void gpsh_objcreator_release(void);
void gpsh_objcreator_initialise(void);

#endif /* MAIN_DLL_CREATOR1C4_H_ */
