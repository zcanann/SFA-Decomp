#ifndef MAIN_DLL_DF_DLL_198_H_
#define MAIN_DLL_DF_DLL_198_H_

#include "ghidra_import.h"
#include "main/dll/DF/dfropenode.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor20 gDFropenodeObjDescriptor;

void dfropenode_update(DFropenodeObject *obj);
void dfropenode_init(DFropenodeObject *obj, u8 *objDef);
void dfropenode_release(void);
void dfropenode_initialise(void);
int DFSH_Door2Speci_SeqFn(struct GameObject *obj);
int DFSH_Door2Speci_getExtraSize(void);

#endif /* MAIN_DLL_DF_DLL_198_H_ */
