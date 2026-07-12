#ifndef MAIN_OBJECT_API_H_
#define MAIN_OBJECT_API_H_

#include "main/game_object.h"

GameObject* Obj_GetPlayerObject(void);
u8 Obj_IsLoadingLocked(void);
void Obj_SetActiveModelIndex(GameObject* obj, int idx);

#endif /* MAIN_OBJECT_API_H_ */
