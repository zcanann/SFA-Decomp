#ifndef MAIN_DLL_PED_H_
#define MAIN_DLL_PED_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void treebird_init(struct GameObject* obj, int setup);
int TreeBird_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
void nw_geyser_init(struct GameObject* obj);
void nw_geyser_update(int obj);
int NW_geyser_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int nw_mammoth_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

#define nw_mammoth_SeqFn nw_mammoth_SeqFn

#endif /* MAIN_DLL_PED_H_ */
