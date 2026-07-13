#ifndef MAIN_DLL_DLL_0141_LIGHTNING_H_
#define MAIN_DLL_DLL_0141_LIGHTNING_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define MMP_LIGHTNING_OBJGROUP 0x48

extern ObjectDescriptor gLightningObjDescriptor;

int lightning_getExtraSize(void);
void lightning_free(u8 *obj, int p2);
void lightning_render(u8 *obj);
void lightning_update(u8 *obj);
void lightning_init(u8 *obj, u8 *data);

#endif /* MAIN_DLL_DLL_0141_LIGHTNING_H_ */
