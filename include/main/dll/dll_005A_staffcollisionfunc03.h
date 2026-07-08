#ifndef MAIN_DLL_DLL_005A_STAFFCOLLISIONFUNC03_H_
#define MAIN_DLL_DLL_005A_STAFFCOLLISIONFUNC03_H_

#include "global.h"
#include "main/effect_interfaces.h"

typedef struct
{
    s16 v[5];
} StaffFxVtx;

typedef struct
{
    StaffFxVtx vtx0[3];
    u8 pad1e[2];
    StaffFxVtx vtx1[4];
    s16 col[6];
    s16 hw[7];
    u8 pad62[2];
} StaffFxDesc;

void StaffCollision_func03(u8* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int modelId,
                           int* colorArgs);

#endif /* MAIN_DLL_DLL_005A_STAFFCOLLISIONFUNC03_H_ */
