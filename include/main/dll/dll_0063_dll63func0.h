#ifndef MAIN_DLL_DLL_0063_DLL63FUNC0_H_
#define MAIN_DLL_DLL_0063_DLL63FUNC0_H_

#include "types.h"

struct GameObject;

typedef s16 (*Dll63SpawnFn)(struct GameObject* sourceObj, int variant, void* posSource, u32 flags, int unused,
                            void* unusedParams);

typedef struct Dll63Interface
{
    void* reserved;
    Dll63SpawnFn spawn;
} Dll63Interface;

STATIC_ASSERT(offsetof(Dll63Interface, spawn) == 0x04);

s16 dll_63_func03(struct GameObject* sourceObj, int variant, void* posSource, u32 flags, int unused,
                  void* unusedParams);
void dll_63_func01_nop(void);
void dll_63_func00_nop(void);

#endif /* MAIN_DLL_DLL_0063_DLL63FUNC0_H_ */
