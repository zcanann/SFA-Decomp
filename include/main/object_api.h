#ifndef MAIN_OBJECT_API_H_
#define MAIN_OBJECT_API_H_

#include "main/game_object.h"

typedef struct ObjModel ObjModel;

GameObject* Obj_GetPlayerObject(void);
u8 Obj_IsLoadingLocked(void);
ObjModel* Obj_GetActiveModel(GameObject* obj);
void Obj_BuildWorldTransformMatrix(GameObject* obj, f32* mtx, int flags);
void Obj_SetActiveModelIndex(GameObject* obj, int idx);

#endif /* MAIN_OBJECT_API_H_ */
