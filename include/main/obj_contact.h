#ifndef MAIN_OBJ_CONTACT_H_
#define MAIN_OBJ_CONTACT_H_

#include "main/game_object.h"

typedef void (*ObjContactCallback)(GameObject* objA, GameObject* objB);

void ObjContact_DispatchCallbacks(GameObject* objA, GameObject* objB);
void ObjContact_RemoveObjectCallbacks(GameObject* obj);
int ObjContact_AddCallback(GameObject* obj, GameObject* otherObj, ObjContactCallback callback);

#endif /* MAIN_OBJ_CONTACT_H_ */
