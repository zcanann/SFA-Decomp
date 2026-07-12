#ifndef MAIN_OBJ_QUERY_H_
#define MAIN_OBJ_QUERY_H_

#include "main/game_object.h"

int Obj_IsObjectAlive(int obj);
int Obj_GetYawDeltaToObject(GameObject* obj, GameObject* target, f32* distanceOut);

#endif /* MAIN_OBJ_QUERY_H_ */
