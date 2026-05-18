#ifndef MAIN_DLL_ZBOMB_H_
#define MAIN_DLL_ZBOMB_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void dfptargetblock_update(int param_1);
void dfptargetblock_init(int param_1,int param_2);
void dfptargetblock_release(void);
void dfptargetblock_initialise(void);
extern ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor;

#endif /* MAIN_DLL_ZBOMB_H_ */
