#ifndef MAIN_DLL_DLL_0069_DLL69FUNC0_H_
#define MAIN_DLL_DLL_0069_DLL69FUNC0_H_

#include "types.h"

typedef struct Dll69EffectParams
{
    int param0;
    int param1;
    int param2;
    int param3;
} Dll69EffectParams;

typedef void (*Dll69SpawnFn)(u8* sourceObj, int variant, void* posSource, u32 flags, int unused,
                             Dll69EffectParams* overrideParams);

typedef struct Dll69Interface
{
    void* reserved;
    Dll69SpawnFn spawn;
} Dll69Interface;

void dll_69_func01_nop(void);
void dll_69_func00_nop(void);
void dll_69_func03(u8* sourceObj, int variant, void* posSource, u32 flags, int unused,
                   Dll69EffectParams* overrideParams);

#endif /* MAIN_DLL_DLL_0069_DLL69FUNC0_H_ */
