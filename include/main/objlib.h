#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "ghidra_import.h"

typedef struct ObjAnimBank ObjAnimBank;
typedef struct ObjHitReactState ObjHitReactState;

void FUN_800356f0(int param_1);
int ObjHitbox_AllocRotatedBounds(ushort *param_1,uint param_2);
void ObjHitReact_LoadMoveEntries(int objAnim,ObjAnimBank *bank,int objType,
                                 ObjHitReactState *hitState,int moveId,int async);
uint ObjHitReact_InitState(int objType,ObjAnimBank *bank,ObjHitReactState *hitState,
                           uint entryArena,int objAnim);
void ObjHitbox_SetStateIndex(int param_1,int param_2,int param_3);
void ObjHits_SetTargetMask(int param_1,undefined param_2);
void ObjHitbox_SetSphereRadius(int param_1,undefined2 param_2);
void ObjHitbox_SetCapsuleBounds(int param_1,undefined2 param_2,short param_3,short param_4);
void ObjHits_ClearHitVolumes(int param_1);
void ObjHits_SetHitVolumeMasks(int param_1,int param_2,int param_3,int param_4);
void ObjHits_SetHitVolumeSlot(u32 param_1,int param_2,int param_3,int param_4);
void ObjHits_ClearSourceMask(int param_1,int param_2);
void ObjHits_SetSourceMask(int param_1,byte param_2);
void ObjHits_ClearFlags(int param_1,int param_2);
void ObjHits_SetFlags(int param_1,int param_2);
void ObjHits_MarkObjectPositionDirty(int param_1);
void ObjHits_SyncObjectPositionIfDirty(u32 param_1);
void ObjHits_DisableObject(u32 param_1);
void ObjHits_EnableObject(u32 param_1);
ushort ObjHits_IsObjectEnabled(int param_1);
void ObjHits_SyncObjectPosition(u32 param_1);
int ObjHits_AllocObjectState(int param_1,uint param_2);
void ObjHits_RefreshObjectState(int param_1);
undefined4 ObjHits_RecordObjectHit(int obj,int hitObj,char priority,undefined hitVolume,undefined sphereIndex);
undefined4
ObjHits_RecordPositionHit(double hitPosX,double hitPosY,double hitPosZ,int obj,int hitObj,char priority,
            undefined hitVolume,undefined sphereIndex);
void ObjHits_AddContactObject(int param_1,int param_2);
int ObjHits_GetPriorityHitWithPosition(int obj,undefined4 *outHitObject,int *outSphereIndex,
                uint *outHitVolume,float *outHitPosX,float *outHitPosY,float *outHitPosZ);
int ObjHits_GetPriorityHit(int obj,undefined4 *outHitObject,int *outSphereIndex,uint *outHitVolume);
void ObjHitReact_UpdateResetObjects(void);
void ObjHits_ResetWorkBuffers(void);
int *ObjHitReact_GetResetObjects(undefined4 *param_1);
void ObjHits_InitWorkBuffers(void);
uint ObjGroup_ContainsObject(int obj,int group);
void ObjGroup_FindNearestObjectToPoint(undefined4 param_1,undefined4 param_2,float *param_3);
void ObjGroup_FindNearestObjectForObject(undefined4 param_1,undefined4 param_2,float *param_3);
void ObjGroup_FindNearestObject(undefined4 param_1,undefined4 param_2,float *param_3);
undefined4 * ObjGroup_GetObjects(int group,int *countOut);
void ObjGroup_RemoveObject(int obj,int group);
int ObjGroup_GetObjectGroup(int obj);
void ObjGroup_AddObject(int obj,int group);
void ObjGroup_ClearAll(void);
undefined4 ObjMsg_Peek(void *obj,uint *outMessage,uint *outSender,uint *outParam);
undefined4 ObjMsg_Pop(void *obj,uint *outMessage,uint *outSender,uint *outParam);
void ObjMsg_SendToNearbyObjects(int targetId,float radius,uint flags,void *sender,uint message,uint param);
void ObjMsg_SendToObjects(int targetId,uint flags,void *sender,uint message,uint param);
uint ObjMsg_SendToObject(void *obj,uint message,void *sender,uint param);
void ObjMsg_AllocQueue(void *obj,int capacity);
undefined4 Obj_IsObjectAlive(u32 param_1);
bool FUN_80037d74(int param_1);
int ObjHits_PollPriorityHitWithCooldown(int obj,float *cooldown,undefined4 *outHitObject,float *outHitPos);
int ObjHits_PollPriorityHitEffectWithCooldown(int obj,uint hitFxMode,uint colorR,uint colorG,
                                              uint colorB,uint sfxId,float *cooldown);
void ObjLink_DetachChild(int param_1,int param_2);
void ObjLink_AttachChild(int param_1,int param_2,ushort param_3);
void ObjContact_DispatchCallbacks(void);
void ObjContact_RemoveObjectCallbacks(int param_1);
undefined4 ObjContact_AddCallback(int param_1,int param_2,undefined4 param_3);
undefined4 ObjTrigger_IsSetById(int obj,short triggerId);
undefined4 ObjTrigger_IsSet(int obj);
int ObjList_FindNearestObjectByDefNo(int obj,int defNo,float *maxDistanceSq);
undefined4 ObjList_ContainsObject(int param_1);
void ObjPath_GetPointWorldPositionArray(undefined4 param_1,undefined4 param_2,int param_3,float *param_4);
void ObjPath_GetPointLocalPosition(int param_1,int param_2,float *param_3,float *param_4,
                 float *param_5);
void ObjPath_GetPointLocalMtx(int param_1,int param_2,float *param_3);
void ObjPath_GetPointModelMtx(int param_1,int param_2);
void ObjPath_GetPointWorldPosition(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 *param_4,
                 float *param_5,int param_6);
int Obj_GetYawDeltaToObject(ushort *param_1,int param_2,float *param_3);
void FUN_80038b0c(void);
void FUN_80038bac(int param_1,int param_2,uint param_3);
void FUN_80038bb0(char param_1,int param_2);

#endif /* MAIN_OBJLIB_H_ */
