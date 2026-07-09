#ifndef MAIN_DLL_DLL_0159_BLASTED_H_
#define MAIN_DLL_DLL_0159_BLASTED_H_

#include "global.h"

typedef struct BlastedTargetSetup
{
    u8 pad00[0x1A];
    s16 pieceCount;
    s16 triggerId;
    s16 completedGameBit;
    s16 progressGameBit;
} BlastedTargetSetup;

typedef struct BlastedTargetState
{
    u32 destroyedHitObjects[3];
    int triggerFired;
    u8 pad10;
    u8 damageStep;
    u8 pad12[2];
} BlastedTargetState;

STATIC_ASSERT(offsetof(BlastedTargetSetup, pieceCount) == 0x1A);
STATIC_ASSERT(offsetof(BlastedTargetSetup, triggerId) == 0x1C);
STATIC_ASSERT(offsetof(BlastedTargetSetup, completedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BlastedTargetSetup, progressGameBit) == 0x20);
STATIC_ASSERT(offsetof(BlastedTargetState, triggerFired) == 0x0C);
STATIC_ASSERT(offsetof(BlastedTargetState, damageStep) == 0x11);
STATIC_ASSERT(sizeof(BlastedTargetState) == 0x14);

typedef struct BlastedState
{
    u8 pad0[0x10 - 0x0];
    u8 pieceCount;
    u8 gameBitLatchState;
    u8 pad12[0x6E4 - 0x12];
    u8 unk6E4;
    u8 pad6E5[0x6E8 - 0x6E5];
} BlastedState;

int fn_801A27B8(struct GameObject *obj, int id);
int blasted_getExtraSize(void);
int blasted_getObjectTypeId(void);
void blasted_free(void);
void blasted_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void blasted_hitDetect(void);
void blasted_update(int obj);
void blasted_init(int obj, int placement);
void blasted_release(void);
void blasted_initialise(void);

#endif /* MAIN_DLL_DLL_0159_BLASTED_H_ */
