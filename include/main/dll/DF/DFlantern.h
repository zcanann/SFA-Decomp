#ifndef MAIN_DLL_DF_DFLANTERN_H_
#define MAIN_DLL_DF_DFLANTERN_H_

#include "ghidra_import.h"

void dfsh_door2speci_free(void);
void dfsh_door2speci_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void dfsh_door2speci_hitDetect(void);
void dfsh_door2speci_update(void);
void dfsh_door2speci_init(int obj,int def);
void dfsh_door2speci_release(void);
void dfsh_door2speci_initialise(void);
void fn_801C2914(int obj);
int dfsh_shrine_SeqFn(int obj,int unused,void *seq);
int dfsh_shrine_getExtraSize(void);
int dfsh_shrine_getObjectTypeId(void);
void dfsh_shrine_free(int obj);

#endif /* MAIN_DLL_DF_DFLANTERN_H_ */
