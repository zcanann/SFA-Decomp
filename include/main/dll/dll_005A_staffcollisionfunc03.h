#ifndef MAIN_DLL_DLL_005A_STAFFCOLLISIONFUNC03_H_
#define MAIN_DLL_DLL_005A_STAFFCOLLISIONFUNC03_H_

#include "main/dll/partfx_interface.h"
#include "global.h"

typedef struct
{
    s16 v[5];
} StaffFxVtx;

typedef struct StaffCollisionColorArgs
{
    int count;
    int red;
    int green;
    int blue;
} StaffCollisionColorArgs;

typedef struct
{
    StaffFxVtx vtx0[3];
    u8 pad1e[2];
    StaffFxVtx vtx1[4];
    s16 col[6];
    s16 hw[7];
    u8 pad62[2];
} StaffFxDesc;

typedef void (*StaffCollisionSpawnFn)(u8* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                                      int modelId, StaffCollisionColorArgs* colorArgs);

typedef struct StaffCollisionInterface
{
    void* reserved;
    StaffCollisionSpawnFn spawn;
} StaffCollisionInterface;

STATIC_ASSERT(sizeof(StaffCollisionColorArgs) == 0x10);

void StaffCollision_func03(u8* sourceObj, int variant, PartFxSpawnParams* spawnParams, u32 spawnFlags, int modelId,
                           StaffCollisionColorArgs* colorArgs);

#endif /* MAIN_DLL_DLL_005A_STAFFCOLLISIONFUNC03_H_ */
