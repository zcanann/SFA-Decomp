#ifndef MAIN_DLL_LASER19F_H_
#define MAIN_DLL_LASER19F_H_

#include "ghidra_import.h"

int MMSH_Shrine_SeqFn(int objArg, undefined4 unused, int seqArg);
int mmsh_shrine_getExtraSize(void);
int mmsh_shrine_getObjectTypeId(void);
void mmsh_shrine_free(int param_1);
void mmsh_shrine_render(int obj, undefined4 a2, undefined4 a3, undefined4 a4, undefined4 a5,
                        char flag);
void mmsh_shrine_hitDetect(void);
void mmsh_shrine_update(int param_1);

#endif /* MAIN_DLL_LASER19F_H_ */
