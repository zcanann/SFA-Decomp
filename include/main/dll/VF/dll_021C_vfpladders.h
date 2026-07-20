#ifndef MAIN_DLL_VF_DLL_021C_VFPLADDERS_H_
#define MAIN_DLL_VF_DLL_021C_VFPLADDERS_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

typedef struct VfpLaddersState
{
    s16 baseGameBit;    /* 0x00 */
    s16 triggerGameBit; /* 0x02 */
    s16 phase;          /* 0x04: VFPLADDERS_PHASE_* */
    s16 delayTimer;     /* 0x06 */
} VfpLaddersState;

typedef struct VfpLaddersSetup
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19[0x1E - 0x19];
    s16 baseGameBit;    /* 0x1E */
    s16 triggerGameBit; /* 0x20 */
} VfpLaddersSetup;

STATIC_ASSERT(sizeof(VfpLaddersState) == 0x08);
STATIC_ASSERT(offsetof(VfpLaddersState, baseGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpLaddersState, triggerGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpLaddersState, phase) == 0x04);
STATIC_ASSERT(offsetof(VfpLaddersState, delayTimer) == 0x06);
STATIC_ASSERT(offsetof(VfpLaddersSetup, base.posY) == 0x0C);
STATIC_ASSERT(offsetof(VfpLaddersSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(VfpLaddersSetup, baseGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VfpLaddersSetup, triggerGameBit) == 0x20);

int vfpladders_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int VFP_Ladders_getExtraSize(void);
int VFP_Ladders_getObjectTypeId(void);
void VFP_Ladders_free(GameObject* obj);
void VFP_Ladders_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void VFP_Ladders_hitDetect(GameObject* obj);
void VFP_Ladders_update(GameObject* obj);
void VFP_Ladders_init(GameObject* obj, VfpLaddersSetup* setup);
void VFP_Ladders_release(void);
void VFP_Ladders_initialise(void);

extern ObjectDescriptor gVFP_LaddersObjDescriptor;

#endif /* MAIN_DLL_VF_DLL_021C_VFPLADDERS_H_ */
