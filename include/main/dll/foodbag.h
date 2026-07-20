#ifndef MAIN_DLL_FOODBAG_H_
#define MAIN_DLL_FOODBAG_H_

#include "ghidra_import.h"

struct GameObject;
struct PartFxSpawnParams;

typedef s16 (*Dll81SpawnFn)(int sourceObj, int variant, void* posSource, u32 flags, int owner, int unused);

typedef struct Dll81Interface
{
    u8 pad00[0x04];
    Dll81SpawnFn spawn;
} Dll81Interface;

typedef void (*Dll82SpawnFn)(struct GameObject* sourceObj, int variant, struct PartFxSpawnParams* spawnParams,
                             u32 spawnFlags, int modelId, void* extraArg);

typedef struct Dll82Interface
{
    void* reserved;
    Dll82SpawnFn spawn;
} Dll82Interface;

STATIC_ASSERT(offsetof(Dll82Interface, spawn) == 0x04);

typedef s16 (*Dll83SpawnFn)(void* sourceObj, int variant, struct PartFxSpawnParams* posSource, u32 flags,
                            int owner, void* unused);

typedef struct Dll83Interface
{
    void* reserved;
    Dll83SpawnFn spawn;
} Dll83Interface;

typedef s16 (*Dll84SpawnFn)(void* sourceObj, int variant, struct PartFxSpawnParams* posSource, u32 flags,
                            int owner, void* unused);

typedef struct Dll84Interface
{
    void* reserved;
    Dll84SpawnFn spawn;
} Dll84Interface;

STATIC_ASSERT(offsetof(Dll83Interface, spawn) == 0x04);
STATIC_ASSERT(offsetof(Dll84Interface, spawn) == 0x04);

void dll_81_func00_nop(void);
void dll_81_func01_nop(void);
s16 dll_81_func03(int sourceObj, int variant, void* posSource, u32 flags, int owner, int unused);
void dll_82_func00_nop(void);
void dll_82_func01_nop(void);
void dll_82_func03(struct GameObject* sourceObj, int variant, struct PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   int modelId, void* extraArg);
s16 dll_83_func03(void* sourceObj, int variant, struct PartFxSpawnParams* posSource, u32 flags, int owner,
                  void* unused);
s16 dll_84_func03(void* sourceObj, int variant, struct PartFxSpawnParams* posSource, u32 flags, int owner,
                  void* unused);
void dll_85_func03(int param_1,int param_2,int param_3,u32 param_4);
void dll_86_func00_nop(void);
void dll_86_func01_nop(void);
void dll_86_func03(int param_1,int param_2,int param_3,u32 param_4);
void dll_87_func00_nop(void);
void dll_87_func01_nop(void);
void dll_87_func03(int param_1,int param_2,int param_3,u32 param_4);
void dll_88_func00_nop(void);
void dll_88_func01_nop(void);
void dll_88_func03(int param_1,int param_2,int param_3,u32 param_4);
void dll_89_func00_nop(void);
void dll_89_func01_nop(void);
void dll_89_func03(int param_1,int param_2,int param_3,u32 param_4);
void dll_8A_func00_nop(void);
void dll_8A_func01_nop(void);
void dll_8A_func03(int param_1,int param_2,int param_3,u32 param_4);
void dll_8B_func00_nop(void);
void dll_8B_func01_nop(void);
void dll_8B_func03(int param_1,int param_2,int param_3,u32 param_4,u32 param_5,
                 f32 *param_6);
void dll_8C_func00_nop(void);
void dll_8C_func01_nop(void);
void dll_8C_func03(int param_1,int param_2,int param_3,u32 param_4);
#endif /* MAIN_DLL_FOODBAG_H_ */
