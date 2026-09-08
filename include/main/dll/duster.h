#ifndef MAIN_DLL_DUSTER_H_
#define MAIN_DLL_DUSTER_H_

#include "dlls/objects/201_Baddie.h"
#include "game/objects/object.h"
#include "main/dll/duster_api.h"

void rachnopUpdateApproach(GameObject* obj, void* state);
void rachnopUpdateAttack(GameObject* obj, void* state);
void rachnopUpdateIdle(GameObject* obj, void* state);
void spittingEbaUpdateIdle(GameObject* obj, int state);
void spittingEbaUpdateEngaged(GameObject* obj, int state);

void rachnopInit(GameObject* unused, void* state);
void spittingEbaSpawnPollen(GameObject* obj,int state);
void spittingEbaUpdateTimeOfDay(int obj,int state);
void spittingEbaInit(u32 unused,int state);
void wbInit(u32 unused,int state);

#endif /* MAIN_DLL_DUSTER_H_ */
