#ifndef MAIN_DLL_VF_DLL_021A_VFPSTATUEBALL_H_
#define MAIN_DLL_VF_DLL_021A_VFPSTATUEBALL_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct VfpStatueBallPlacement
{
    ObjPlacement base;
    u8 pad18[2];
    s16 variant;    /* 0x1A: 0..2, selects model and matched against the striker */
    s16 scale;      /* 0x1C: >1 scales the model's root motion up */
    s16 activationGameBit; /* 0x1E */
} VfpStatueBallPlacement;

typedef struct VfpStatueBallState
{
    s16 activationGameBit; /* 0x00 */
    s16 timer;          /* 0x02: decremented each tick, never tested */
    u8 pad04;
    u8 active;          /* 0x05 */
    u8 activateSfxPending; /* 0x06 */
    u8 previousActive;  /* 0x07 */
    u8 pad08;
    u8 burstEffectId;   /* 0x09 */
    u8 burstScale;      /* 0x0A */
    u8 burstChance;     /* 0x0B */
} VfpStatueBallState;

STATIC_ASSERT(sizeof(VfpStatueBallPlacement) == 0x20);
STATIC_ASSERT(sizeof(VfpStatueBallState) == 0xc);
STATIC_ASSERT(offsetof(VfpStatueBallPlacement, variant) == 0x1A);
STATIC_ASSERT(offsetof(VfpStatueBallPlacement, activationGameBit) == 0x1E);

int VFP_statueball_getExtraSize(void);
int VFP_statueball_getObjectTypeId(void);
void VFP_statueball_free(GameObject* obj);
void VFP_statueball_render(void);
void VFP_statueball_hitDetect(void);
void VFP_statueball_update(GameObject* obj);
void VFP_statueball_init(GameObject* obj, VfpStatueBallPlacement* placement);
void VFP_statueball_release(void);
void VFP_statueball_initialise(void);

extern ObjectDescriptor gVFP_statueballObjDescriptor;

#endif /* MAIN_DLL_VF_DLL_021A_VFPSTATUEBALL_H_ */
