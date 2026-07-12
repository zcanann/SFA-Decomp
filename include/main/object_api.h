#ifndef MAIN_OBJECT_API_H_
#define MAIN_OBJECT_API_H_

#include "main/game_object.h"

typedef struct ObjModel ObjModel;

GameObject* Obj_GetPlayerObject(void);
GameObject* ObjList_FindObjectById(u32 objectId);
u8 Obj_IsLoadingLocked(void);
ObjModel* Obj_GetActiveModel(GameObject* obj);
void Obj_BuildWorldTransformMatrix(GameObject* obj, f32* mtx, int flags);
void Obj_SetModelColorFadeRecursive(GameObject* obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf);
void Obj_SetModelColorOverrideRecursive(GameObject* obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled);
void Obj_Shatter(GameObject* obj);
void Obj_StartModelFadeIn(GameObject* obj, int frames);
void Obj_SetActiveModelIndex(GameObject* obj, int idx);

#endif /* MAIN_OBJECT_API_H_ */
