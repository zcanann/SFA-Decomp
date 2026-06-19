#ifndef MAIN_DLL_CANNON_H_
#define MAIN_DLL_CANNON_H_

#include "ghidra_import.h"
#include "main/objanim_internal.h"

typedef struct TrickyRuntime TrickyRuntime;
typedef struct TrickyGuardSpotObject TrickyGuardSpotObject;

typedef struct TrickyGuardSpotInterfaceVTable {
    void *pad00[10];
    void (*setGuardSpotAction)(ObjAnimComponent *tricky, TrickyGuardSpotObject *obj,
                               int action, int param);
    void *pad2C[4];
    void (*resetGuardSpotAction)(ObjAnimComponent *tricky);
    void *pad40;
    int (*isGuardSpotActionReady)(ObjAnimComponent *tricky);
} TrickyGuardSpotInterfaceVTable;

STATIC_ASSERT(offsetof(TrickyGuardSpotInterfaceVTable, setGuardSpotAction) == 0x28);
STATIC_ASSERT(offsetof(TrickyGuardSpotInterfaceVTable, resetGuardSpotAction) == 0x3C);
STATIC_ASSERT(offsetof(TrickyGuardSpotInterfaceVTable, isGuardSpotActionReady) == 0x44);

void trickyGuard(ObjAnimComponent *obj, TrickyRuntime *state);
u32 FUN_8013ffbc(int param_1);
void FUN_801400fc(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,u32 param_12,
                 u8 param_13,u32 param_14,u32 param_15,u32 param_16);

#endif /* MAIN_DLL_CANNON_H_ */
