#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/objhits.h"

typedef struct ObjAnimBank ObjAnimBank;
typedef void (*ObjContactCallback)(int objA,int objB);

extern char sObjAddObjectTypeReachedMaxTypes[];
extern char sObjMsgOverflowInObjectWarning[];

int ObjHitbox_AllocRotatedBounds(ushort *hitbox,uint arena);
void ObjHitbox_SetStateIndex(int obj,int hitbox,int stateIndex);
void ObjHits_SetTargetMask(int obj,undefined targetMask);
void ObjHitbox_SetSphereRadius(int obj,undefined2 radius);
void ObjHitbox_SetCapsuleBounds(int obj,undefined2 radius,short verticalMin,short verticalMax);
void ObjHits_ClearHitVolumes(int obj);
void ObjHits_SetHitVolumeMasks(int obj,int hitVolume,int hitType,int sourceMask);
void ObjHits_SetHitVolumeSlot(u32 obj,int hitVolume,int hitType,int sourceSlot);
void ObjHits_ClearSourceMask(int obj,int sourceMask);
void ObjHits_SetSourceMask(int obj,byte sourceMask);
void ObjHits_ClearFlags(int obj,int flags);
void ObjHits_SetFlags(int obj,int flags);
void ObjHits_MarkObjectPositionDirty(int obj);
void ObjHits_SyncObjectPositionIfDirty(u32 obj);
void ObjHits_DisableObject(u32 obj);
void ObjHits_EnableObject(u32 obj);
ushort ObjHits_IsObjectEnabled(int obj);
void ObjHits_SyncObjectPosition(u32 obj);
int ObjHits_AllocObjectState(int obj,uint arena);
void ObjHits_RefreshObjectState(int obj);
int ObjHits_RecordObjectHit(int obj,int hitObj,char priority,u8 hitVolume,u8 sphereIndex);
int ObjHits_RecordPositionHit(f32 hitPosX,f32 hitPosY,f32 hitPosZ,int obj,int hitObj,char priority,
                              u8 hitVolume,u8 sphereIndex);
void ObjHits_AddContactObject(int obj,int contactObj);
void ObjHits_ResetWorkBuffers(void);
void ObjHits_InitWorkBuffers(void);
uint ObjGroup_ContainsObject(uint obj,int group);
int ObjGroup_FindNearestObjectToPoint(int group,float *point,float *maxDistance);
int ObjGroup_FindNearestObjectForObject(int group,uint obj,float *maxDistance);
int ObjGroup_FindNearestObject(int group,uint obj,float *maxDistance);
undefined4 * ObjGroup_GetObjects(int group,int *countOut);
void ObjGroup_RemoveObject(uint obj,int group);
int ObjGroup_GetObjectGroup(uint obj);
void ObjGroup_AddObject(uint obj,int group);
void ObjGroup_ClearAll(void);
undefined4 ObjMsg_Peek(void *obj,uint *outMessage,uint *outSender,uint *outParam);
undefined4 ObjMsg_Pop(void *obj,uint *outMessage,uint *outSender,uint *outParam);
void ObjMsg_SendToNearbyObjects(int targetId,float radius,uint flags,void *sender,uint message,uint param);
void ObjMsg_SendToObjects(int targetId,uint flags,void *sender,uint message,uint param);
uint ObjMsg_SendToObject(void *obj,uint message,void *sender,uint param);
void ObjMsg_AllocQueue(void *obj,int capacity);
undefined4 Obj_IsObjectAlive(u32 param_1);
bool ObjTrigger_UpdateIdBlockFlag(int obj);
int ObjHits_PollPriorityHitWithCooldown(int obj,float *cooldown,undefined4 *outHitObject,float *outHitPos);
int ObjHits_PollPriorityHitEffectWithCooldown(int obj,uint hitFxMode,uint colorR,uint colorG,
                                              uint colorB,uint sfxId,float *cooldown);
void ObjLink_DetachChild(int param_1,int param_2);
void ObjLink_AttachChild(int param_1,int param_2,ushort param_3);
void ObjContact_DispatchCallbacks(int objA,int objB);
void ObjContact_RemoveObjectCallbacks(int param_1);
undefined4 ObjContact_AddCallback(int param_1,int param_2,ObjContactCallback callback);
undefined4 ObjTrigger_IsSetById(int obj,short triggerId);
undefined4 ObjTrigger_IsSet(int obj);
int *ObjList_GetObjects(int *startIndex,int *objectCount);
int ObjList_FindNearestObjectByDefNo(int obj,int defNo,float *maxDistanceSq);
undefined4 ObjList_ContainsObject(int param_1);
void ObjPath_GetPointWorldPositionArray(int obj,int pointIndex,int count,float *positions);
void ObjPath_GetPointLocalPosition(int param_1,int param_2,float *param_3,float *param_4,
                 float *param_5);
void ObjPath_GetPointLocalMtx(int param_1,int param_2,float *param_3);
void ObjPath_GetPointModelMtx(int param_1,int param_2);
void ObjPath_GetPointWorldPosition(int obj,int pointIndex,float *outX,float *outY,float *outZ,
                 int useInputPosition);
int Obj_GetYawDeltaToObject(ushort *param_1,int param_2,float *param_3);
uint fn_800386BC(f32 x,f32 y,f32 z);
void fn_80038988(int param_1,int param_2,uint param_3);
void FUN_80038bb0(char param_1,int param_2);

#endif /* MAIN_OBJLIB_H_ */
