#ifndef MAIN_DLL_WC_SBCLOUDRUNNER_H_
#define MAIN_DLL_WC_SBCLOUDRUNNER_H_

#include "game/objects/object.h"
#include "types.h"
#include "main/objseq.h"

typedef struct SBCloudRunnerState SBCloudRunnerState;
typedef struct SBCloudRunnerRideState SBCloudRunnerRideState;

int SB_CloudRunner_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void SB_CloudRunner_UpdateSteer(GameObject* obj, SBCloudRunnerState* state);
void SB_CloudRunner_HandlePriorityHit(GameObject* obj, SBCloudRunnerState* state);
void SB_CloudRunner_SpawnFromPath(GameObject* path, u8* unusedState);
void SB_CloudRunner_UpdateCloudAction(GameObject* obj, SBCloudRunnerRideState* state);
void SB_CloudRunner_UpdateRideTilt(GameObject* obj, SBCloudRunnerRideState* state);

#endif /* MAIN_DLL_WC_SBCLOUDRUNNER_H_ */
