#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/objhits.h"

typedef struct ObjAnimBank ObjAnimBank;
typedef void (*ObjContactCallback)(int objA,int objB);

extern char sObjAddObjectTypeReachedMaxTypes[];
extern char sObjMsgOverflowInObjectWarning[];

void ObjHitbox_SetStateIndex(int obj,int hitState,int stateIndex);
void ObjHitbox_SetSphereRadius(int obj,s16 radius);
void ObjHitbox_SetCapsuleBounds(int obj,s16 radius,s16 verticalMin,s16 verticalMax);
void ObjHits_SetHitVolumeMasks(int obj,int hitVolume,int hitType,int sourceMask);
int ObjHits_AllocObjectState(int obj,u32 arena);
void ObjHits_ResetWorkBuffers(void);
void ObjHits_InitWorkBuffers(void);
u32 ObjGroup_ContainsObject(u32 obj,int group);
int ObjGroup_FindNearestObjectToPoint(int group,float *point,float *maxDistance);
int ObjGroup_FindNearestObjectForObject(int group,u32 obj,float *maxDistance);
int ObjGroup_FindNearestObject(int group,u32 obj,float *maxDistance);
u32 *ObjGroup_GetObjects(int group,int *countOut);
void ObjGroup_RemoveObject(u32 obj,int group);
int ObjGroup_GetObjectGroup(u32 obj);
void ObjGroup_AddObject(u32 obj,int group);
void ObjGroup_ClearAll(void);
u32 ObjMsg_Peek(void *obj,u32 *outMessage,u32 *outSender,u32 *outParam);
u32 ObjMsg_Pop(void *obj,u32 *outMessage,u32 *outSender,u32 *outParam);
void ObjMsg_SendToNearbyObjects(int targetId,float radius,u32 flags,void *sender,u32 message,u32 param);
void ObjMsg_SendToObjects(int targetId,u32 flags,void *sender,u32 message,u32 param);
u32 ObjMsg_SendToObject(void *obj,u32 message,void *sender,u32 param);
void ObjMsg_AllocQueue(void *obj,int capacity);
u32 Obj_IsObjectAlive(u32 param_1);
bool ObjTrigger_UpdateIdBlockFlag(int obj);
void ObjLink_DetachChild(int param_1,int param_2);
void ObjLink_AttachChild(int param_1,int param_2,u16 param_3);
void ObjContact_DispatchCallbacks(int objA,int objB);
void ObjContact_RemoveObjectCallbacks(int param_1);
u32 ObjContact_AddCallback(int param_1,int param_2,ObjContactCallback callback);
u32 ObjTrigger_IsSetById(int obj,short triggerId);
u32 ObjTrigger_IsSet(int obj);
void *ObjList_GetObjects(int *startIndex,int *objectCount);
int ObjList_FindNearestObjectByDefNo(int obj,int defNo,float *maxDistanceSq);
u32 ObjList_ContainsObject(int param_1);
void ObjPath_GetPointWorldPositionArray(int obj,int pointIndex,int count,float *positions);
void ObjPath_GetPointLocalPosition(int param_1,int param_2,float *param_3,float *param_4,
                 float *param_5);
void ObjPath_GetPointLocalMtx(int param_1,int param_2,float *param_3);
void ObjPath_GetPointModelMtx(int param_1,int param_2);
void ObjPath_GetPointWorldPosition(int obj,int pointIndex,float *outX,float *outY,float *outZ,
                 int useInputPosition);
int Obj_GetYawDeltaToObject(u16 *param_1,int param_2,float *param_3);
u32 ObjHitRegion_FindContainingId(f32 x,f32 y,f32 z);
void fn_80038988(int param_1,int param_2,u32 param_3);
void FUN_80038bb0(char param_1,int param_2);

#endif /* MAIN_OBJLIB_H_ */
