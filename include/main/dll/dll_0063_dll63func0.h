#ifndef MAIN_DLL_DLL_0063_DLL63FUNC0_H_
#define MAIN_DLL_DLL_0063_DLL63FUNC0_H_

#include "ghidra_import.h"

typedef void (*Dll63SpawnFn)(u8* sourceObj, int variant, void* posSource, u32 flags, int unused,
                             void* unusedParams);

typedef struct Dll63Interface
{
    void* reserved;
    Dll63SpawnFn spawn;
} Dll63Interface;

void dll_63_func03(u8* sourceObj, int variant, void* posSource, u32 flags, int unused, void* unusedParams);
void dll_63_func01_nop(void);
void dll_63_func00_nop(void);

#endif /* MAIN_DLL_DLL_0063_DLL63FUNC0_H_ */
