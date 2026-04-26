#ifndef MAIN_OBJLIB_H_
#define MAIN_OBJLIB_H_

#include "ghidra_import.h"

void FUN_800356f0(int param_1);
int ObjHitbox_AllocRotatedBounds(ushort *param_1,uint param_2);
void FUN_8003582c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 int param_14,undefined4 param_15,undefined4 param_16);
void FUN_8003597c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,int param_5);
void ObjHitbox_SetStateIndex(int param_1,int param_2,int param_3);
void ObjHits_SetTargetMask(int param_1,undefined param_2);
void FUN_80035b84(int param_1,undefined2 param_2);
void FUN_80035d58(int param_1,undefined2 param_2,short param_3,short param_4);
void ObjHits_ClearHitVolumes(int param_1);
void ObjHits_SetHitVolumeMasks(int param_1,undefined param_2,undefined param_3,int param_4);
void ObjHits_SetHitVolumeSlot(int param_1,undefined param_2,undefined param_3,int param_4);
void ObjHits_ClearSourceMask(int param_1,byte param_2);
void ObjHits_SetSourceMask(int param_1,byte param_2);
void ObjHits_ClearFlags(int param_1,ushort param_2);
void ObjHits_SetFlags(int param_1,ushort param_2);
void ObjHits_MarkObjectPositionDirty(int param_1);
void ObjHits_SyncObjectPositionIfDirty(int param_1);
void ObjHits_DisableObject(int param_1);
void ObjHits_EnableObject(int param_1);
ushort ObjHits_IsObjectEnabled(int param_1);
void ObjHits_SyncObjectPosition(int param_1);
int ObjHits_AllocObjectState(int param_1,uint param_2);
void ObjHits_RefreshObjectState(int param_1);
undefined4 ObjHits_RecordObjectHit(int param_1,int param_2,char param_3,undefined param_4,undefined param_5);
undefined4
ObjHits_RecordPositionHit(double param_1,double param_2,double param_3,int param_4,int param_5,char param_6,
            undefined param_7,undefined param_8);
void ObjHits_AddContactObject(int param_1,int param_2);
int ObjHits_GetPriorityHitWithPosition(int param_1,undefined4 *param_2,int *param_3,uint *param_4,undefined4 *param_5,
                undefined4 *param_6,undefined4 *param_7);
int ObjHits_GetPriorityHit(int param_1,undefined4 *param_2,int *param_3,uint *param_4);
void FUN_80036a98(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8);
void ObjHits_ResetWorkBuffers(void);
undefined4 ObjHitReact_GetResetObjects(undefined4 *param_1);
void ObjHits_InitWorkBuffers(void);
uint ObjGroup_ContainsObject(int param_1,int param_2);
void ObjGroup_FindNearestObjectToPoint(undefined4 param_1,undefined4 param_2,float *param_3);
void ObjGroup_FindNearestObjectForObject(undefined4 param_1,undefined4 param_2,float *param_3);
void ObjGroup_FindNearestObject(undefined4 param_1,undefined4 param_2,float *param_3);
undefined4 * ObjGroup_GetObjects(int param_1,int *param_2);
void ObjGroup_RemoveObject(int param_1,int param_2);
int ObjGroup_GetObjectGroup(int param_1);
void ObjGroup_AddObject(int param_1,int param_2);
void ObjGroup_ClearAll(void);
undefined4 ObjMsg_Peek(int param_1,int *param_2,int *param_3,int *param_4);
undefined4 ObjMsg_Pop(int param_1,uint *param_2,uint *param_3,uint *param_4);
void ObjMsg_SendToNearbyObjects(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
void ObjMsg_SendToObjects(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
uint ObjMsg_SendToObject(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,uint param_11,uint param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
void ObjMsg_AllocQueue(int param_1,int param_2);
undefined4 FUN_80037d50(int param_1);
bool FUN_80037d74(int param_1);
int ObjHits_PollPriorityHitWithCooldown(int param_1,float *param_2,undefined4 *param_3,float *param_4);
void FUN_80037fa8(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 uint param_6,float *param_7);
void ObjLink_DetachChild(int param_1,int param_2);
void ObjLink_AttachChild(int param_1,int param_2,ushort param_3);
void ObjContact_DispatchCallbacks(void);
void ObjContact_RemoveObjectCallbacks(int param_1);
undefined4 ObjContact_AddCallback(int param_1,int param_2,undefined4 param_3);
undefined4 ObjTrigger_IsSetById(int param_1,short param_2);
undefined4 ObjTrigger_IsSet(int param_1);
void ObjList_FindNearestObjectByDefNo(undefined4 param_1,undefined4 param_2,float *param_3);
undefined4 ObjList_ContainsObject(int param_1);
void ObjPath_GetPointWorldPositionArray(undefined4 param_1,undefined4 param_2,int param_3,float *param_4);
void ObjPath_GetPointLocalPosition(int param_1,int param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5);
void ObjPath_GetPointLocalMtx(int param_1,int param_2,float *param_3);
void ObjPath_GetPointModelMtx(int param_1,int param_2);
void ObjPath_GetPointWorldPosition(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 *param_4,
                 float *param_5,int param_6);
int Obj_GetYawDeltaToObject(ushort *param_1,int param_2,float *param_3);
void FUN_80038b0c(void);
void FUN_80038bac(int param_1,int param_2,uint param_3);
void FUN_80038bb0(char param_1,int param_2);

#endif /* MAIN_OBJLIB_H_ */
