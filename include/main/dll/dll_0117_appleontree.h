#ifndef MAIN_DLL_CRACKANIM_H_
#define MAIN_DLL_CRACKANIM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDllFCObjDescriptor;

void AppleOnTree_update(int param_1);
void AppleOnTree_init(int obj, int def);


/* extern-cleanup: defining-file public prototypes */
void AppleOnTree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void AppleOnTree_free(int* obj);
u8 AppleOnTree_modelMtxFn(int* obj);

#endif /* MAIN_DLL_CRACKANIM_H_ */
