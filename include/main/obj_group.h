#ifndef MAIN_OBJ_GROUP_H_
#define MAIN_OBJ_GROUP_H_

#include "global.h"

int ObjGroup_ContainsObject(u32 obj, int group);
int ObjGroup_FindNearestObjectToPoint(int group, f32* point, f32* maxDistance);
int ObjGroup_FindNearestObjectForObject(int group, int obj, f32* maxDistance);
int ObjGroup_FindNearestObject(int group, int obj, f32* maxDistance);
u32* ObjGroup_GetObjects(int group, int* countOut);
void ObjGroup_RemoveObject(int obj, int group);
int ObjGroup_GetObjectGroup(u32 obj);
void ObjGroup_AddObject(int obj, int group);
void ObjGroup_ClearAll(void);

#endif /* MAIN_OBJ_GROUP_H_ */
