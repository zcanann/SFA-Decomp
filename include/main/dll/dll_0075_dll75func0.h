#ifndef MAIN_DLL_DLL_0075_DLL75FUNC0_H_
#define MAIN_DLL_DLL_0075_DLL75FUNC0_H_

#include "main/dll/partfx_interface.h"
#include "types.h"

struct GameObject;

typedef s16 (*Dll75SpawnFn)(struct GameObject* sourceObj, int variant, PartFxSpawnParams* posSource, u32 flags,
                            int owner, void* unused);

typedef struct Dll75Interface
{
    void* reserved;
    Dll75SpawnFn spawn;
} Dll75Interface;

STATIC_ASSERT(offsetof(Dll75Interface, spawn) == 0x04);

s16 dll_75_func03(struct GameObject* sourceObj, int variant, PartFxSpawnParams* posSource, u32 flags, int owner,
                  void* unused);
void dll_75_func01_nop(void);
void dll_75_func00_nop(void);

#endif /* MAIN_DLL_DLL_0075_DLL75FUNC0_H_ */
