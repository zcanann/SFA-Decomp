#ifndef MAIN_DLL_DLL_000E_PARTFX_H_
#define MAIN_DLL_DLL_000E_PARTFX_H_

#include "types.h"
#include "main/effect_interfaces.h"

void partfx_onMapSetup(void);
void partfx_initialise(void);
void partfx_updateFrameState(void);
void partfx_release(void);
int partfx_spawnObject(s16* sourceObj, u32 effectIdArg, PartFxSpawnParams* spawnParamsArg, u32 spawnFlags, u8 modelIdArg,
                       void* extraArgsArg);

#endif /* MAIN_DLL_DLL_000E_PARTFX_H_ */
