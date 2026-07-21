#ifndef MAIN_OBJ_QUERY_H_
#define MAIN_OBJ_QUERY_H_

#include "main/game_object.h"

int Obj_IsObjectAlive(GameObject* obj);
#ifdef OBJ_YAW_DELTA_RETURNS_S16
s16 Obj_GetYawDeltaToObject(GameObject* obj, GameObject* target, f32* distanceOut);
#else
int Obj_GetYawDeltaToObject(GameObject* obj, GameObject* target, f32* distanceOut);
#endif

#endif /* MAIN_OBJ_QUERY_H_ */
