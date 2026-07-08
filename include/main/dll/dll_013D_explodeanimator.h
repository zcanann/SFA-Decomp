#ifndef MAIN_DLL_DLL_013D_EXPLODEANIMATOR_H_
#define MAIN_DLL_DLL_013D_EXPLODEANIMATOR_H_

#include "types.h"

typedef struct ExplodeanimatorState
{
    u8 pad0[0x2 - 0x0];
    u8 flags; /* 0x02: bit 0 = already fired; skip further updates */
    u8 pad3[0x4 - 0x3];
} ExplodeanimatorState;

typedef struct ExplodeanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
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
    u8 pad2C[0x2E - 0x2C];
    s16 velXMin;        /* 0x2E */
    s16 velYMin;        /* 0x30 */
    s16 resultGameBit;  /* 0x32: set to 1 when triggered */
    s16 triggerGameBit; /* 0x34: gate bit; burst fires once this is set */
    u8 pad36[0x38 - 0x36];
} ExplodeanimatorPlacement;

int ExplodeAnimator_getExtraSize(void);
int ExplodeAnimator_getObjectTypeId(void);
void ExplodeAnimator_free(int obj);
void ExplodeAnimator_render(void);
void ExplodeAnimator_hitDetect(void);
void ExplodeAnimator_update(int* obj);
void ExplodeAnimator_init(int* obj, int* def);
void ExplodeAnimator_release(void);
void ExplodeAnimator_initialise(void);

#endif /* MAIN_DLL_DLL_013D_EXPLODEANIMATOR_H_ */
