#ifndef MAIN_DLL_DLL_020B_FIREFLY_H_
#define MAIN_DLL_DLL_020B_FIREFLY_H_

#include "global.h"
#include "main/obj_placement.h"

typedef struct FireFlyActiveBits
{
    u8 active : 1; /* 0x6C & 0x80: lit and wandering */
} FireFlyActiveBits;

typedef struct FireFlyMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 variantParam; /* 0x1A: only 0x7F is read (arms the 3600-frame life timer) */
    u8 pad1C[0x20 - 0x1C];
    s16 requiredGameBit; /* 0x20: game bit gating activation (-1 = none) */
} FireFlyMapData;

STATIC_ASSERT(offsetof(FireFlyMapData, variantParam) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyMapData, requiredGameBit) == 0x20);

void FireFlyFn_801f4f88(int obj);
void firefly_free(struct GameObject* obj);
void firefly_update(int obj);
void firefly_init(int obj, int def);
int firefly_getExtraSize(void);
int firefly_getObjectTypeId(void);
void firefly_render(void);
void firefly_hitDetect(void);
void firefly_release(void);
void firefly_initialise(void);

#endif /* MAIN_DLL_DLL_020B_FIREFLY_H_ */
