#ifndef MAIN_OBJ_LIST_H_
#define MAIN_OBJ_LIST_H_

#include "main/game_object.h"

void* ObjList_GetObjects(int* startIndex, int* objectCount);
GameObject* ObjList_FindNearestObjectByDefNo(GameObject* obj, int defNo, f32* maxDistanceSq);
int ObjList_ContainsObject(int obj);
int ObjList_PartitionForRender(int* objectCount);

#endif /* MAIN_OBJ_LIST_H_ */
