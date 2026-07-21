#ifndef MAIN_DLL_DLL_013D_EXPLODEANIMATOR_H_
#define MAIN_DLL_DLL_013D_EXPLODEANIMATOR_H_

#include "types.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct ExplodeAnimatorState
{
    u8 reserved0[2];
    u8 flags; /* 0x02: bit 0 = already fired; skip further updates */
    u8 reserved3;
} ExplodeAnimatorState;

typedef struct ExplodeAnimatorPlacement
{
    ObjPlacement base; /* 0x00 */
    s16 posXMin;  /* 0x18 */
    s16 posYMin;  /* 0x1A */
    s16 posZMin;  /* 0x1C */
    s16 posXMax;  /* 0x1E */
    s16 posYMax;  /* 0x20 */
    s16 posZMax;  /* 0x22 */
    s16 effectId; /* 0x24: particle effect id passed to spawnObject */
    u8 pad26[0x28 - 0x26];
    s16 velXMax; /* 0x28 */
    s16 velYMax; /* 0x2A */
    u8 particleCount; /* 0x2C */
    u8 pad2D;
    s16 velXMin;        /* 0x2E */
    s16 velYMin;        /* 0x30 */
    s16 resultGameBit;  /* 0x32: set to 1 when triggered */
    s16 triggerGameBit; /* 0x34: gate bit; burst fires once this is set */
    u8 pad36[0x38 - 0x36];
} ExplodeAnimatorPlacement;

STATIC_ASSERT(offsetof(ExplodeAnimatorState, flags) == 0x2);
STATIC_ASSERT(sizeof(ExplodeAnimatorState) == 0x4);
STATIC_ASSERT(offsetof(ExplodeAnimatorPlacement, posXMin) == 0x18);
STATIC_ASSERT(offsetof(ExplodeAnimatorPlacement, effectId) == 0x24);
STATIC_ASSERT(offsetof(ExplodeAnimatorPlacement, particleCount) == 0x2c);
STATIC_ASSERT(offsetof(ExplodeAnimatorPlacement, resultGameBit) == 0x32);
STATIC_ASSERT(offsetof(ExplodeAnimatorPlacement, triggerGameBit) == 0x34);
STATIC_ASSERT(sizeof(ExplodeAnimatorPlacement) == 0x38);

int ExplodeAnimator_getExtraSize(void);
int ExplodeAnimator_getObjectTypeId(void);
void ExplodeAnimator_free(GameObject* obj);
void ExplodeAnimator_render(void);
void ExplodeAnimator_hitDetect(void);
void ExplodeAnimator_update(GameObject* obj);
void ExplodeAnimator_init(GameObject* obj, ExplodeAnimatorPlacement* placement);
void ExplodeAnimator_release(void);
void ExplodeAnimator_initialise(void);

extern ObjectDescriptor gExplodeAnimatorObjDescriptor;

#endif /* MAIN_DLL_DLL_013D_EXPLODEANIMATOR_H_ */
