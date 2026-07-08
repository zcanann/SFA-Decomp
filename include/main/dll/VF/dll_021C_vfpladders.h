#ifndef MAIN_DLL_VF_DLL_021C_VFPLADDERS_H_
#define MAIN_DLL_VF_DLL_021C_VFPLADDERS_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct VfpLaddersState
{
    s16 baseGameBit;    /* 0x00 */
    s16 triggerGameBit; /* 0x02 */
    s16 phase;          /* 0x04: VFPLADDERS_PHASE_* */
    s16 delayTimer;     /* 0x06 */
} VfpLaddersState;

typedef struct VfpLaddersSetup
{
    u8 pad00[0x0C];
    f32 baseY; /* 0x0C: placed height */
    u8 pad10[0x1E - 0x10];
    s16 baseGameBit;    /* 0x1E */
    s16 triggerGameBit; /* 0x20 */
} VfpLaddersSetup;

STATIC_ASSERT(sizeof(VfpLaddersState) == 0x08);
STATIC_ASSERT(offsetof(VfpLaddersState, baseGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpLaddersState, triggerGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpLaddersState, phase) == 0x04);
STATIC_ASSERT(offsetof(VfpLaddersState, delayTimer) == 0x06);
STATIC_ASSERT(offsetof(VfpLaddersSetup, baseY) == 0x0C);
STATIC_ASSERT(offsetof(VfpLaddersSetup, baseGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VfpLaddersSetup, triggerGameBit) == 0x20);

int vfpladders_SeqFn(void);
int VFP_Ladders_getExtraSize(void);
int VFP_Ladders_getObjectTypeId(void);
void VFP_Ladders_free(int obj);
void VFP_Ladders_render(void);
void VFP_Ladders_hitDetect(void);
void VFP_Ladders_update(int obj);
void VFP_Ladders_init(int* obj, u8* init);
void VFP_Ladders_release(void);
void VFP_Ladders_initialise(void);

#endif /* MAIN_DLL_VF_DLL_021C_VFPLADDERS_H_ */
