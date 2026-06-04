#ifndef MAIN_DLL_CREATOR1C4_H_
#define MAIN_DLL_CREATOR1C4_H_

#include "ghidra_import.h"

void gpsh_shrine_update(int obj);
void gpsh_shrine_init(int *obj, int *def);
void gpsh_shrine_release(void);
void gpsh_shrine_initialise(void);

int gpsh_objcreator_getExtraSize(void);
int gpsh_objcreator_getObjectTypeId(void);
void gpsh_objcreator_free(void);
void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void gpsh_objcreator_hitDetect(void);
void gpsh_objcreator_update(int *obj);
void gpsh_objcreator_init(int *obj, int *def);
void gpsh_objcreator_release(void);
void gpsh_objcreator_initialise(void);

#endif /* MAIN_DLL_CREATOR1C4_H_ */
