#ifndef MAIN_DLL_SH_DLL_01AE_SHLEVELCONTROL_H_
#define MAIN_DLL_SH_DLL_01AE_SHLEVELCONTROL_H_

#include "types.h"

typedef struct GameObject GameObject;

typedef struct SCGameBitLatchState
{
    int activeMask;
} SCGameBitLatchState;

struct SCTotemLogPuzzleUpdateState;

int SH_LevelControl_SeqFn(void* obj, void* unused, struct SCTotemLogPuzzleUpdateState* updateState);
int SH_LevelControl_getExtraSize(void);
void SH_LevelControl_free(void);
void SH_LevelControl_update(GameObject* obj);
void SH_LevelControl_init(GameObject* obj);
void mapUnloadFn_801d7c94(void* obj, void* state);
void SCGameBitLatch_Update(SCGameBitLatchState* state, int mask, s16 clearIfSetBit, s16 clearIfClearBit, s16 latchBit,
                           int musicId);
void SCGameBitLatch_UpdateInverted(SCGameBitLatchState* state, int mask, s16 clearIfSetBit, s16 clearIfClearBit,
                                   s16 latchBit, int musicId);

#endif /* MAIN_DLL_SH_DLL_01AE_SHLEVELCONTROL_H_ */
