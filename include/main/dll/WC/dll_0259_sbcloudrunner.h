#ifndef MAIN_DLL_WC_WCLEVCONTROL_H_
#define MAIN_DLL_WC_WCLEVCONTROL_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

typedef struct SBCloudRunnerState SBCloudRunnerState;

void FUN_801ee7bc(short* param_1, int param_2, u32 param_3, u32 param_4, u32 param_5, u32 param_6, u32 param_7,
                  u32 param_8);
void FUN_801eeafc(u16* param_1, int param_2, u32 param_3, u32 param_4, u32 param_5, u32 param_6, u32 param_7,
                  u32 param_8);
void FUN_801ef3f8(u16* param_1, u32 param_2, int param_3, u32 param_4, u32 param_5, u32 param_6, u32 param_7,
                  u32 param_8);
void FUN_801ef980(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u16* param_9, u32 param_10, u32 param_11, u32 param_12, u32 param_13, u32 param_14,
                  u32 param_15, u32 param_16);
int SB_CloudRunner_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void SB_CloudRunner_UpdateSteer(s16* obj, u8* state);
void SB_CloudRunner_HandlePriorityHit(GameObject* obj, SBCloudRunnerState* state);

#endif /* MAIN_DLL_WC_WCLEVCONTROL_H_ */
