#ifndef MAIN_DLL_DLL_005B_MODGFXFUNC03_H_
#define MAIN_DLL_DLL_005B_MODGFXFUNC03_H_

#include "global.h"
#include "main/dll/partfx_interface.h"

typedef union ModgfxSpawnCountRange
{
    struct
    {
        s16 min;
        s16 max;
    };
    u32 packed;
} ModgfxSpawnCountRange;

typedef s16 (*ModgfxFunc03SpawnFn)(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                                   int modelId, ModgfxSpawnCountRange* countRange);

typedef struct ModgfxFunc03Interface
{
    void* reserved;
    ModgfxFunc03SpawnFn spawn;
} ModgfxFunc03Interface;

STATIC_ASSERT(sizeof(ModgfxSpawnCountRange) == 4);
STATIC_ASSERT(offsetof(ModgfxFunc03Interface, spawn) == 4);

s16 modgfx_func03(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, int modelId,
                  ModgfxSpawnCountRange* countRange);

#endif /* MAIN_DLL_DLL_005B_MODGFXFUNC03_H_ */
