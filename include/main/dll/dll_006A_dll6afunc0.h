#ifndef MAIN_DLL_DLL_006A_DLL6AFUNC0_H_
#define MAIN_DLL_DLL_006A_DLL6AFUNC0_H_

#include "main/dll/partfx_interface.h"
#include "types.h"

typedef s16 (*Dll6ASpawnFn)(void* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int modelId,
                            void* extraArg);

typedef struct Dll6AInterface
{
    void* reserved;
    Dll6ASpawnFn spawn;
} Dll6AInterface;

STATIC_ASSERT(offsetof(Dll6AInterface, spawn) == 0x04);

s16 dll_6A_func03(void* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int modelId,
                  void* extraArg);
void dll_6A_func01_nop(void);
void dll_6A_func00_nop(void);

#endif /* MAIN_DLL_DLL_006A_DLL6AFUNC0_H_ */
