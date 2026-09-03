#ifndef MAIN_OBJ_QUERY_H_
#define MAIN_OBJ_QUERY_H_

#include "game/objects/object.h"

int Obj_IsObjectAlive(GameObject* obj);
s16 Obj_GetYawDeltaToObject(GameObject* obj, GameObject* target, f32* distanceOut);

#endif /* MAIN_OBJ_QUERY_H_ */
