#ifndef MAIN_DLL_PED_H_
#define MAIN_DLL_PED_H_

#include "ghidra_import.h"

void treebird_init(int obj,int setup);
int TreeBird_SeqFn(int obj, int unused, int data);
void nw_geyser_init(int obj);
void nw_geyser_update(int obj);
int NW_geyser_SeqFn(int *obj, int unused, void *events);
int fn_801CDE7C(int obj,int param_2,u8 *seqData);

#define nw_mammoth_SeqFn fn_801CDE7C

#endif /* MAIN_DLL_PED_H_ */
