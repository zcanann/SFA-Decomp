#ifndef MAIN_DLL_CC_DLL_018A_CCPEDSTAL_H_
#define MAIN_DLL_CC_DLL_018A_CCPEDSTAL_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct CcpedstalState CcpedstalState;
typedef void (*CcpedstalThinkFn)(GameObject* obj, CcpedstalState* state);

typedef struct CcpedstalPlacement
{
    union {
        ObjPlacement base;
        struct {
            u8 pad00[0x14];
            s32 variantId;
        };
    };
    u8 pad18[2];
    u8 yaw; /* 0x1A: yaw in 1/128 turns */
} CcpedstalPlacement;

STATIC_ASSERT(offsetof(CcpedstalPlacement, variantId) == 0x14);
STATIC_ASSERT(offsetof(CcpedstalPlacement, yaw) == 0x1A);

/* ccpedstal extra block (extraSize 0x8): a think fn-pointer at +0, an
 * s16 GameBit id at +4, and a one-shot flag byte at +6 toggled by the
 * think routines and consumed by ccpedstal_update. */
struct CcpedstalState
{
    CcpedstalThinkFn think;
    s16 gameBit;
    u8 markFlags;
    u8 unk7;
};

STATIC_ASSERT(offsetof(CcpedstalState, think) == 0x0);
STATIC_ASSERT(offsetof(CcpedstalState, gameBit) == 0x4);
STATIC_ASSERT(offsetof(CcpedstalState, markFlags) == 0x6);
STATIC_ASSERT(sizeof(CcpedstalState) == 0x8);

int ccpedstal_getExtraSize(void);
void ccpedstal_updateGameBitGate(GameObject* obj, CcpedstalState* state);
void ccpedstal_updateAltVariant(GameObject* obj, CcpedstalState* state);
void ccpedstal_update(GameObject* obj);
void ccpedstal_init(GameObject* obj, CcpedstalPlacement* placement);

extern ObjectDescriptor gCCpedstalObjDescriptor;

#endif /* MAIN_DLL_CC_DLL_018A_CCPEDSTAL_H_ */
