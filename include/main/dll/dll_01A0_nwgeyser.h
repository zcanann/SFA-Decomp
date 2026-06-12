#ifndef MAIN_DLL_PED_H_
#define MAIN_DLL_PED_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void treebird_init(int obj,int setup);
int TreeBird_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void nw_geyser_init(int obj);
void nw_geyser_update(int obj);
int NW_geyser_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);
int fn_801CDE7C(int obj,int unused,ObjAnimUpdateState *animUpdate);

#define nw_mammoth_SeqFn fn_801CDE7C

#endif /* MAIN_DLL_PED_H_ */
