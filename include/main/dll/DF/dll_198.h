#ifndef MAIN_DLL_DF_DLL_198_H_
#define MAIN_DLL_DF_DLL_198_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor20 gDFropenodeObjDescriptor;

void dfropenode_update(int obj);
void dfropenode_init(int obj, int objDef);
void dfropenode_release(void);
void dfropenode_initialise(void);
int DFSH_Door2Speci_SeqFn(int obj);
int dfsh_door2speci_getExtraSize(void);

#endif /* MAIN_DLL_DF_DLL_198_H_ */
