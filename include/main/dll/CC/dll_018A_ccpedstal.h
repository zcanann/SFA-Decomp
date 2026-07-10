#ifndef MAIN_DLL_CC_DLL_018A_CCPEDSTAL_H_
#define MAIN_DLL_CC_DLL_018A_CCPEDSTAL_H_

#include "global.h"
#include "main/game_object.h"

/* ccpedstal extra block (extraSize 0x8): a think fn-pointer at +0, an
 * s16 GameBit id at +4, and a one-shot flag byte at +6 toggled by the
 * think routines and consumed by ccpedstal_update. */
typedef struct CcpedstalState
{
    void* think;
    s16 gameBit;
    u8 markFlags;
    u8 unk7;
} CcpedstalState;

STATIC_ASSERT(offsetof(CcpedstalState, gameBit) == 0x4);
STATIC_ASSERT(offsetof(CcpedstalState, markFlags) == 0x6);
STATIC_ASSERT(sizeof(CcpedstalState) == 0x8);

int ccpedstal_getExtraSize(void);
void ccpedstal_updateGameBitGate(GameObject* obj, u8* state2);
void ccpedstal_updateAltVariant(GameObject* obj, u8* state2);
void ccpedstal_update(int obj);
void ccpedstal_init(int* obj, u8* params);

#endif /* MAIN_DLL_CC_DLL_018A_CCPEDSTAL_H_ */
