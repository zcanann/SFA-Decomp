#ifndef MAIN_DLL_PED_H_
#define MAIN_DLL_PED_H_

#include "ghidra_import.h"

void treebird_init(int obj,int setup);
void FUN_801cdd1c(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_801cdf84(int param_1);
void FUN_801ce008(int param_1);
void nw_geyser_init(int obj);
void nw_geyser_update(int obj);
int fn_801CDE7C(int obj,int param_2,u8 *seqData);

#define nw_mammoth_SeqFn fn_801CDE7C

#endif /* MAIN_DLL_PED_H_ */
