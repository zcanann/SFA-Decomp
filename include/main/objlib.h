#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "main/game_object.h"
#include "ghidra_import.h"

typedef struct ObjAnimBank ObjAnimBank;
typedef void (*ObjContactCallback)(int objA, int objB);

extern char sObjAddObjectTypeReachedMaxTypes[];
extern char sObjMsgOverflowInObjectWarning[];

u32 ObjGroup_ContainsObject(u32 obj, int group);
int ObjGroup_FindNearestObjectToPoint(int group, float* point, float* maxDistance);
int ObjGroup_FindNearestObjectForObject(int group, int obj, float* maxDistance);
int ObjGroup_FindNearestObject(int group, int obj, float* maxDistance);
u32* ObjGroup_GetObjects(int group, int* countOut);
void ObjGroup_RemoveObject(int obj, int group);
int ObjGroup_GetObjectGroup(u32 obj);
void ObjGroup_AddObject(int obj, int group);
void ObjGroup_ClearAll(void);
u32 ObjMsg_Peek(void* obj, u32* outMessage, u32* outSender, u32* outParam);
int ObjMsg_Pop(void* obj, u32* outMessage, u32* outSender, u32* outParam);
void ObjMsg_SendToNearbyObjects(int targetId, float radius, u32 flags, void* sender, u32 message, u32 param);
void ObjMsg_SendToObjects(int targetId, u32 flags, void* sender, u32 message, u32 param);
u32 ObjMsg_SendToObject(void* obj, u32 message, void* sender, u32 param);
void ObjMsg_AllocQueue(void* obj, int capacity);
int Obj_IsObjectAlive(int obj);
bool ObjTrigger_UpdateIdBlockFlag(int obj);
void ObjLink_DetachChild(GameObject* param_1, int param_2);
void ObjLink_AttachChild(int parent, int child, int linkMode);
void ObjContact_DispatchCallbacks(int objA, int objB);
void ObjContact_RemoveObjectCallbacks(int param_1);
int ObjContact_AddCallback(int obj, int otherObj, ObjContactCallback callback);
int ObjTrigger_IsSetById(int obj, int triggerId);
int ObjTrigger_IsSet(int obj);
void* ObjList_GetObjects(int* startIndex, int* objectCount);
GameObject* ObjList_FindNearestObjectByDefNo(GameObject* obj, int defNo, float* maxDistanceSq);
u32 ObjList_ContainsObject(int param_1);
void ObjPath_GetPointWorldPositionArray(GameObject* obj, int pointIndex, int count, float* positions);
void ObjPath_GetPointLocalPosition(GameObject* param_1, int param_2, float* param_3, float* param_4, float* param_5);
void ObjPath_GetPointLocalMtx(GameObject* param_1, int param_2, float* param_3);
u32 ObjPath_GetPointModelMtx(GameObject* param_1, int param_2);
void ObjPath_GetPointWorldPosition(GameObject* obj, int pointIndex, float* outX, float* outY, float* outZ,
                                   int useInputPosition);
int Obj_GetYawDeltaToObject(GameObject* obj, int target, float* distanceOut);
u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z);
void fn_80038988(int param_1, int param_2, u32 param_3);
void FUN_80038bb0(char param_1, int param_2);

int ObjHits_PollPriorityHitWithCooldown();

#endif /* MAIN_OBJLIB_H_ */
