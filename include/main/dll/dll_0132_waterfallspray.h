#ifndef MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_
#define MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define WATERFALLSPRAY_ALT_SFX_DEF_MIN 0x4BE5C
#define WATERFALLSPRAY_ALT_SFX_DEF_END 0x4BE5E
#define WATERFALLSPRAY_DEFAULT_SFX_A 0x2AF
#define WATERFALLSPRAY_DEFAULT_SFX_B 0x2B2
#define WATERFALLSPRAY_ALT_SFX_A 0x489
#define WATERFALLSPRAY_ALT_SFX_B 0x48A

extern ObjectDescriptor gWaterFallSprayObjDescriptor;

void WaterFallSpray_free(u8 *obj);
void WaterFallSpray_init(u8 *obj, u8 *data);
void WaterFallSpray_render(void);
void WaterFallSpray_update(int *obj);
int WaterFallSpray_getExtraSize(void);
int WaterFallSpray_SeqFn(int *obj);

#endif /* MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_ */
