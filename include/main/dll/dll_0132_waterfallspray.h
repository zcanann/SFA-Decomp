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

struct GameObject;
struct WaterFallSprayPlacement;

void WaterFallSpray_free(struct GameObject *obj);
void WaterFallSpray_init(struct GameObject *obj, struct WaterFallSprayPlacement *data);
void WaterFallSpray_render(void);
void WaterFallSpray_update(struct GameObject *obj);
int WaterFallSpray_getExtraSize(void);
int WaterFallSpray_SeqFn(struct GameObject *obj);

#endif /* MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_ */
