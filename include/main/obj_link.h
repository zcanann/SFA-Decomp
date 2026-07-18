#ifndef MAIN_OBJ_LINK_H_
#define MAIN_OBJ_LINK_H_

#include "main/game_object.h"

void ObjLink_DetachChild(GameObject* parent, GameObject* child);
void ObjLink_AttachChild(GameObject* parent, GameObject* child, int linkMode);

#endif /* MAIN_OBJ_LINK_H_ */
