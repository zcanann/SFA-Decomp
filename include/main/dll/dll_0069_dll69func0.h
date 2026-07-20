#ifndef MAIN_DLL_DLL_0069_DLL69FUNC0_H_
#define MAIN_DLL_DLL_0069_DLL69FUNC0_H_

#include "types.h"

struct GameObject;

typedef struct Dll69EffectParams
{
    int param0;
    int param1;
    int param2;
    int param3;
} Dll69EffectParams;

typedef s16 (*Dll69SpawnFn)(struct GameObject* sourceObj, int variant, void* posSource, u32 flags, int unused,
                            Dll69EffectParams* overrideParams);

typedef struct Dll69Interface
{
    void* reserved;
    Dll69SpawnFn spawn;
} Dll69Interface;

STATIC_ASSERT(offsetof(Dll69Interface, spawn) == 0x04);

void dll_69_func01_nop(void);
void dll_69_func00_nop(void);
s16 dll_69_func03(struct GameObject* sourceObj, int variant, void* posSource, u32 flags, int unused,
                  Dll69EffectParams* overrideParams);

#endif /* MAIN_DLL_DLL_0069_DLL69FUNC0_H_ */
