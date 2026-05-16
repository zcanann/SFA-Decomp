#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objlib.h"

typedef struct ObjLibRegionList ObjLibRegionList;

extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern float sqrtf(float x);
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern ObjHitReactEffectHandle *Resource_Acquire(int resourceId,int mode);
extern int Sfx_PlayFromObject(int obj,int sfxId);
extern uint buttonGetDisabled(int index);
extern void buttonDisable(int index,uint flags);
extern u32 randomGetRange(int min,int max);
extern undefined4 FUN_80017640();
extern undefined4 FUN_80017700();
extern undefined4 FUN_80017704();
extern void setMatrixFromObjectTransposed(void *transform,float *mtx);
extern float vec3f_distanceSquared(float *posA,float *posB);
extern float Vec_distance(float *param_1,float *param_2);
extern void OSReport(const char *fmt, ...);
extern int FUN_80017730();
extern undefined4 FUN_8001774c();
extern uint roundUpTo4();
extern uint roundUpTo8(uint param_1);
extern uint FUN_800177dc();
extern void *mmAlloc(int size,int heap,int flags);
extern float *ObjModel_GetJointMatrix(int *model,int jointIndex);
extern void Obj_BuildWorldTransformMatrix(void *obj,float *mtx,int flags);
extern void mtx44Transpose(float *src,float *dst);
extern void mtxRotateByVec3s(float *mtx,void *transform);
extern undefined4 FUN_80017a50();
extern int *Obj_GetActiveModel(int obj);
extern void *Obj_GetPlayerObject(void);
extern void Obj_UpdateObject(ObjAnimComponent *obj,void *modelInstance);
extern int ObjList_GetObjects();
extern void ObjHitbox_UpdateRotatedBounds(short *param_1,int param_2);
extern undefined4 FUN_80045328();
extern void getTabEntry(void *dst,int fileId,int offset,int size);
extern void fileLoadToBufferOffset(int fileId,void *dst,int offset,int size);
extern void fn_80054F74(int obj,float *pos);
extern ObjLibRegionList **fn_8005AFA0(void);
extern int * fn_8005B11C();
extern void debugPrintf(const char *fmt, ...);
extern void PSMTXConcat(float *a,float *b,float *out);
extern undefined4 FUN_80247618();
extern float PSVECSquareDistance(float *a,float *b);
extern undefined8 FUN_80286834();
extern ulonglong FUN_80286838();
extern longlong FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern f32 fn_80293E80(f32 x);
extern f32 fn_802943F4(f32 x);
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949e8();
extern f32 sin(f32 x);
extern int fn_80295CD4(int obj);
extern int objGetAnimState80A(void *obj);

#define OBJGROUP_COUNT 0x54
#define OBJGROUP_OFFSET_CLEAR_COUNT (OBJGROUP_COUNT + 1)
#define OBJGROUP_MAX_OBJECTS 0x100

extern uint gObjGroupObjects[OBJGROUP_MAX_OBJECTS];
extern u8 gObjGroupOffsets[0x58];
typedef struct ObjContactCallbackEntry {
  int objA;
  int objB;
  ObjContactCallback callback;
} ObjContactCallbackEntry;

typedef struct ObjLibRegionEntry {
  s16 type;
  u8 wordCount;
  u8 pad03[5];
  f32 x;
  f32 y;
  f32 z;
  u8 pad14[4];
  u16 id;
  u16 halfX;
  u16 halfY;
  u16 halfZ;
  u8 yaw;
  u8 pitch;
} ObjLibRegionEntry;

struct ObjLibRegionList {
  u8 pad00[8];
  u16 entryBytes;
  u8 pad0A[0x16];
  ObjLibRegionEntry *entries;
};

extern ObjContactCallbackEntry lbl_80342D50[];
typedef struct ObjTriggerInterface {
  u8 pad00[0x1c];
  int (*isCurrentTriggerClear)(void);
  int (*isTriggerSet)(int eventId);
} ObjTriggerInterface;

extern ObjTriggerInterface **lbl_803DCA68;
extern void *lbl_803DCBC8[2];
extern void *lbl_803DCBD0[2];
extern void *lbl_803DCBD8;
extern undefined4 gObjHitsPriorityHitStates;
extern int gObjHitReactResetObjectCount;
extern int *gObjHitReactResetObjects;
extern u8 gObjGroupObjectCount;
extern int lbl_803DCBF8;
extern undefined4 DAT_803dd880;
extern f64 DOUBLE_803df5c0;
extern f64 DOUBLE_803df640;
extern f32 lbl_803DC074;
extern f32 gObjHitsPriorityHitTickDelta;
extern f32 lbl_803DE914;
extern f32 lbl_803DE968;
extern f32 lbl_803DE97C;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DF5E8;
extern f32 lbl_803DF5F0;
extern f32 lbl_803DE970;
extern f32 lbl_803DE974;
extern f32 lbl_803DE978;
extern f32 lbl_803DE980;
extern f32 lbl_803DE984;
extern f32 lbl_803DE998;
extern f32 lbl_803DE99C;
extern f32 lbl_803DE9A0;
extern f32 lbl_803DE9A4;
extern f32 lbl_803DE9A8;
extern f32 lbl_803DE9AC;
extern f32 lbl_803DE9B0;
extern f32 lbl_803DE9B4;
extern f32 lbl_803DE9B8;
extern f32 lbl_803DF5F4;
extern f32 lbl_803DF5F8;
extern f32 lbl_803DF5FC;
extern f32 lbl_803DF618;
extern f32 lbl_803DF61C;
extern f32 lbl_803DF620;
extern f32 lbl_803DF624;
extern f32 lbl_803DF628;
extern f32 lbl_803DF630;
extern f32 lbl_803DF634;
extern f32 lbl_803DF638;

#define gObjHitsResetObjectCount gObjHitReactResetObjectCount
#define gObjHitsResetObjects gObjHitReactResetObjects
extern char sObjMsgOverflowInObjectWarning[];
extern char sObjAddObjectTypeReachedMaxTypes[];

#define OBJMSG_QUEUE_OFFSET 0xdc
#define OBJMSG_SEND_INCLUDE_SENDER 0x1
#define OBJMSG_SEND_MATCH_ANY 0x2
#define OBJMSG_SEND_MATCH_OBJTYPE 0x4

#define OBJCONTACT_CALLBACK_CAPACITY 0x10
#define OBJCONTACT_CALLBACK_LAST_INDEX (OBJCONTACT_CALLBACK_CAPACITY - 1)
#define OBJCONTACT_OBJECT_REFCOUNT_OFFSET 0xe9
#define gObjContactCallbacks lbl_80342D50
#define gObjContactCallbackCount lbl_803DCBF8

#define OBJTRIGGER_FLAGS_OFFSET 0xaf
#define OBJTRIGGER_CURRENT_ENABLE_FLAG 0x01
#define OBJTRIGGER_CURRENT_BLOCK_FLAG 0x08
#define OBJTRIGGER_ID_ENABLE_FLAG 0x04
#define OBJTRIGGER_ID_BLOCK_FLAG 0x10
#define OBJTRIGGER_BUTTON_DISABLE_INDEX 0
#define OBJTRIGGER_BUTTON_DISABLE_FLAG 0x100
#define OBJTRIGGER_PLAYER_STATE_NONE -1
#define OBJTRIGGER_PLAYER_STATE_CLEAR 0x40

#define OBJLINK_PARENT_OFFSET 0xc4
#define OBJLINK_CHILD_LIST_OFFSET 0xc8
#define OBJLINK_CHILD_COUNT_OFFSET 0xeb
#define OBJLINK_CHILD_STATE_OFFSET 0xe5
#define OBJLINK_FLAGS_OFFSET 0xb0
#define OBJLINK_FLAGS_MODE_MASK 0x0007
#define OBJLINK_FLAGS_MODE_CLEAR_MASK 0xfff8
#define OBJLINK_FLAGS_DEAD 0x0040

#define OBJ_MODEL_INSTANCE_OFFSET 0x50
#define OBJ_MODEL_INSTANCE_HALFWORD_OFFSET (OBJ_MODEL_INSTANCE_OFFSET / 2)
#define OBJ_ACTIVE_MODEL_INDEX_OFFSET 0xad
#define OBJ_POSITION_X_OFFSET 0x0c
#define OBJ_POSITION_Y_OFFSET 0x10
#define OBJ_POSITION_Z_OFFSET 0x14

#define OBJ_MODEL_JOINT_COUNT_OFFSET 0xf3
#define OBJPATH_POINTS_OFFSET 0x2c
#define OBJPATH_POINT_COUNT_OFFSET 0x58
#define OBJPATH_ROOT_JOINT_INDEX -1
#define OBJLIB_UNIT_SCALE lbl_803DE97C

typedef struct ObjMsgEntry {
  uint message;
  uint sender;
  uint param;
} ObjMsgEntry;

typedef struct ObjMsgQueue {
  uint count;
  uint capacity;
  ObjMsgEntry entries[1];
} ObjMsgQueue;

typedef struct ObjMsgQueueSlotBase {
  uint count;
  uint capacity;
  ObjMsgEntry entry;
} ObjMsgQueueSlotBase;

typedef struct ObjPathPoint {
  f32 x;
  f32 y;
  f32 z;
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  s8 modelIndex[6];
} ObjPathPoint;

typedef struct ObjPathTransform {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  u8 pad06[2];
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} ObjPathTransform;

/*
 * --INFO--
 *
 * Function: ObjHitbox_AllocRotatedBounds
 * EN v1.0 Address: 0x800356F0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800357E8
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjHitbox_AllocRotatedBounds(ushort *param_1,uint param_2)
{
  uint uVar1;

  uVar1 = roundUpTo4(param_2);
  *(uint *)(param_1 + 0x2c) = uVar1;
  if (*(uint *)(param_1 + 0x2c) != 0) {
    *(undefined *)(*(uint *)(param_1 + 0x2c) + 0x10c) = 0;
    *(undefined *)(*(uint *)(param_1 + 0x2c) + 0x10d) = 10;
    *(undefined *)(*(uint *)(param_1 + 0x2c) + 0x10f) = 0;
    ObjHitbox_UpdateRotatedBounds((short *)param_1,1);
    ObjHitbox_UpdateRotatedBounds((short *)param_1,1);
  }
  return uVar1 + 0x110;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_LoadMoveEntries
 * EN v1.0 Address: 0x80035774
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8003586C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void ObjHitReact_LoadMoveEntries(int objAnim,ObjAnimBank *bank,int objType,
                                 ObjHitReactState *hitState,int moveId,int async)
{
  ObjHitReactMoveEntry *moveEntry;
  ObjHitReactMoveEntry *moveEntryTable;
  s16 firstEntryOffset;

  moveEntryTable = ((ObjAnimDef *)((ObjAnimComponent *)objAnim)->modelInstance)->hitReactMoveTable;
  hitState->activeEntryCount = 0;
  if (moveEntryTable != (ObjHitReactMoveEntry *)0x0) {
    for (moveEntry = moveEntryTable; moveEntry->moveId != -1; moveEntry++) {
      if (moveId == moveEntry->moveId) {
        firstEntryOffset = moveEntry->firstEntryIndex;
        hitState->activeEntryCount = moveEntry->entryCount;
        if (hitState->activeEntryCount > hitState->entryCapacity) {
          hitState->activeEntryCount = hitState->entryCapacity;
        }
        if (async == 0) {
          getTabEntry(hitState->entries,OBJHITREACT_ENTRY_TAB_FILE_ID,(int)firstEntryOffset,
                      (int)hitState->activeEntryCount);
          return;
        }
        fileLoadToBufferOffset(OBJHITREACT_ENTRY_TAB_FILE_ID,hitState->entries,
                               (int)firstEntryOffset,(int)hitState->activeEntryCount);
        return;
      }
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_InitState
 * EN v1.0 Address: 0x80035828
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80035920
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
uint ObjHitReact_InitState(int objType,ObjAnimBank *bank,ObjHitReactState *hitState,
                           uint entryArena,int objAnim)
{
  ObjHitReactEntry *entries;

  if (bank == (ObjAnimBank *)0x0) {
    return entryArena;
  }
  hitState->entryCapacity = OBJHITREACT_ENTRY_ARENA_BYTES;
  entries = (ObjHitReactEntry *)roundUpTo8(entryArena);
  hitState->entries = entries;
  entryArena = (uint)entries + hitState->entryCapacity;
  hitState->activeHitboxMode = OBJHITREACT_ACTIVE_HITBOX_MODE;
  if ((hitState->resetFlags & OBJHITREACT_RESET_MODE_MASK) != 0) {
    hitState->resetHitboxMode = OBJHITREACT_RESET_HITBOX_MODE;
  }
  ObjHitReact_LoadMoveEntries(objAnim,bank,objType,hitState,0,1);
  return entryArena;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetStateIndex
 * EN v1.0 Address: 0x800358D4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x800359CC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHitbox_SetStateIndex(int param_1,int param_2,int param_3)
{
  int iVar1;
  int *piVar2;
  int slotIndex;
  int slotOffset;
  int clearedState;

  iVar1 = (int)*(char *)(*(int *)(param_1 + 0x50) + 0x55);
  if (param_3 >= iVar1) {
    param_3 = iVar1 + -1;
  }
  else if (param_3 < 0) {
    param_3 = 0;
  }
  if (*(char *)(param_2 + 0xb0) == param_3) {
    return;
  }
  slotIndex = 0;
  slotOffset = (s16)slotIndex;
  clearedState = slotOffset;
  for (; (s16)slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT; slotIndex = slotIndex + 1) {
    piVar2 = (int *)(gObjHitsPriorityHitStates + slotOffset);
    if ((*piVar2 != 0) && ((u32)piVar2[2] == (u32)param_1)) {
      *piVar2 = clearedState;
    }
    slotOffset = slotOffset + OBJHITS_PRIORITY_WORK_SLOT_SIZE;
  }
  *(char *)(param_2 + 0xb0) = (char)param_3;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_SetTargetMask
 * EN v1.0 Address: 0x80035960
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035A58
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetTargetMask(int param_1,undefined param_2)
{
  if (*(u32 *)(param_1 + 0x54) == 0) {
    return;
  }
  *(undefined *)(*(int *)(param_1 + 0x54) + 0xb5) = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetSphereRadius
 * EN v1.0 Address: 0x80035974
 * EN v1.0 Size: 476b
 * EN v1.1 Address: 0x80035A6C
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHitbox_SetSphereRadius(int param_1,undefined2 param_2)
{
  float fVar1;
  uint iVar3;

  iVar3 = *(uint *)(param_1 + 0x54);
  if (iVar3 != 0) {
    if ((*(byte *)(iVar3 + 0x62) & 1) != 0) {
      *(undefined2 *)(iVar3 + 0x5a) = param_2;
      fVar1 = (float)(s32)*(short *)(iVar3 + 0x5a);
      *(float *)(iVar3 + 0xc) = fVar1 * fVar1;
      *(float *)(iVar3 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if ((float)(s32)*(short *)(iVar3 + 0x5a) > *(float *)(iVar3 + 0x28)) {
        *(float *)(iVar3 + 0x28) = (float)(s32)*(short *)(iVar3 + 0x5a);
      }
      *(float *)(iVar3 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if ((float)(s32)*(short *)(iVar3 + 0x5a) > *(float *)(iVar3 + 0x2c)) {
        *(float *)(iVar3 + 0x2c) = (float)(s32)*(short *)(iVar3 + 0x5a);
      }
    }
    if ((*(byte *)(iVar3 + 0xb6) & 1) != 0) {
      *(undefined2 *)(iVar3 + 100) = param_2;
      *(float *)(iVar3 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if ((float)(s32)*(short *)(iVar3 + 0x5a) > *(float *)(iVar3 + 0x30)) {
        *(float *)(iVar3 + 0x30) = (float)(s32)*(short *)(iVar3 + 100);
      }
      *(float *)(iVar3 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if ((float)(s32)*(short *)(iVar3 + 0x5a) > *(float *)(iVar3 + 0x34)) {
        *(float *)(iVar3 + 0x34) = (float)(s32)*(short *)(iVar3 + 100);
      }
    }
    *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x2c);
    if (*(float *)(iVar3 + 0x38) < *(float *)(iVar3 + 0x34)) {
      *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x34);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetCapsuleBounds
 * EN v1.0 Address: 0x80035B50
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x80035C48
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHitbox_SetCapsuleBounds(int param_1,undefined2 param_2,short param_3,short param_4)
{
  float fVar1;
  float fVar2;
  uint iVar3;
  s32 absVal;

  iVar3 = *(uint *)(param_1 + 0x54);
  if (iVar3 != 0) {
    if ((*(byte *)(iVar3 + 0x62) & 2) != 0) {
      *(short *)(iVar3 + 0x5c) = param_3;
      *(short *)(iVar3 + 0x5e) = param_4;
      *(undefined2 *)(iVar3 + 0x5a) = param_2;
      *(float *)(iVar3 + 0xc) =
          (float)(s32)*(short *)(iVar3 + 0x5a) * (float)(s32)*(short *)(iVar3 + 0x5a);
      *(undefined2 *)(iVar3 + 0x58) = 0x400;
      *(float *)(iVar3 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      absVal = (s32)param_3;
      if (absVal < 0) {
        absVal = -absVal;
      }
      fVar1 = (float)absVal;
      absVal = (s32)param_4;
      if (absVal < 0) {
        absVal = -absVal;
      }
      fVar2 = (float)absVal;
      if (fVar1 > fVar2) {
        fVar2 = fVar1;
      }
      if (fVar2 > *(float *)(iVar3 + 0x28)) {
        *(float *)(iVar3 + 0x28) = fVar2;
      }
      *(float *)(iVar3 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if ((float)(s32)*(short *)(iVar3 + 0x5a) > *(float *)(iVar3 + 0x2c)) {
        *(float *)(iVar3 + 0x2c) = (float)(s32)*(short *)(iVar3 + 0x5a);
      }
    }
    if ((*(byte *)(iVar3 + 0xb6) & 2) != 0) {
      *(short *)(iVar3 + 0x66) = param_3;
      *(short *)(iVar3 + 0x68) = param_4;
      *(undefined2 *)(iVar3 + 100) = param_2;
      *(float *)(iVar3 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      absVal = (s32)param_3;
      if (absVal < 0) {
        absVal = -absVal;
      }
      fVar1 = (float)absVal;
      absVal = (s32)param_4;
      if (absVal < 0) {
        absVal = -absVal;
      }
      fVar2 = (float)absVal;
      if (fVar1 > fVar2) {
        fVar2 = fVar1;
      }
      if (fVar2 > *(float *)(iVar3 + 0x30)) {
        *(float *)(iVar3 + 0x30) = fVar2;
      }
      *(float *)(iVar3 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if ((float)(s32)*(short *)(iVar3 + 0x5a) > *(float *)(iVar3 + 0x34)) {
        *(float *)(iVar3 + 0x34) = (float)(s32)*(short *)(iVar3 + 100);
      }
    }
    *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x2c);
    if (*(float *)(iVar3 + 0x34) > *(float *)(iVar3 + 0x38)) {
      *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x34);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_ClearHitVolumes
 * EN v1.0 Address: 0x80035DAC
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80035EA4
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ClearHitVolumes(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  *(undefined *)(iVar1 + 0x6e) = 0;
  *(undefined *)(iVar1 + 0x6f) = 0;
  *(undefined4 *)(iVar1 + 0x48) = 0;
  *(undefined4 *)(iVar1 + 0x4c) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetHitVolumeMasks
 * EN v1.0 Address: 0x80035DC8
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80035EC0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_SetHitVolumeMasks(int param_1,int param_2,int param_3,int param_4)
{
  int iVar1;

  iVar1 = *(int *)(param_1 + 0x54);
  *(s8 *)(iVar1 + 0x6e) = (s8)param_2;
  *(s8 *)(iVar1 + 0x6f) = (s8)param_3;
  if (param_4 == 0) {
    return;
  }
  *(int *)(iVar1 + 0x48) = param_4 << 4;
  *(int *)(iVar1 + 0x4c) = param_4 << 4;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_SetHitVolumeSlot
 * EN v1.0 Address: 0x80035DF4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80035EEC
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_SetHitVolumeSlot(u32 param_1,int param_2,int param_3,int param_4)
{
  int iVar1;
  u32 iVar2;

  iVar2 = *(u32 *)(param_1 + 0x54);
  if (iVar2 == 0) {
    return;
  }
  *(s8 *)(iVar2 + 0x6e) = (s8)param_2;
  *(s8 *)(iVar2 + 0x6f) = (s8)param_3;
  if (param_4 == -1) {
    return;
  }
  iVar1 = 1 << (param_4 + 4);
  *(int *)(iVar2 + 0x48) = iVar1;
  *(int *)(iVar2 + 0x4c) = iVar1;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_ClearSourceMask
 * EN v1.0 Address: 0x80035E30
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F28
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_ClearSourceMask(int param_1,int param_2)
{
  u8* p = (u8*)(*(int *)(param_1 + 0x54) + 0xb4);
  *p = (u8)(*p & ~param_2);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_SetSourceMask
 * EN v1.0 Address: 0x80035E48
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035F40
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetSourceMask(int param_1,byte param_2)
{
  *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) = *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) | param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ClearFlags
 * EN v1.0 Address: 0x80035E5C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F54
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_ClearFlags(int param_1,int param_2)
{
  s16* p = (s16*)(*(int *)(param_1 + 0x54) + 0x60);
  *p = (s16)(*p & ~param_2);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_SetFlags
 * EN v1.0 Address: 0x80035E74
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F6C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_SetFlags(int param_1,int param_2)
{
  s16* p = (s16*)(*(int *)(param_1 + 0x54) + 0x60);
  *p = (s16)(*p | param_2);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_MarkObjectPositionDirty
 * EN v1.0 Address: 0x80035E8C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F84
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_MarkObjectPositionDirty(int param_1)
{
  s16* p = (s16*)(*(int *)(param_1 + 0x54) + 0x60);
  *p = (s16)(*p | 0x40);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_SyncObjectPositionIfDirty
 * EN v1.0 Address: 0x80035EA4
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x80035F9C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_SyncObjectPositionIfDirty(u32 param_1)
{
  u32 iVar1;
  s16 flags;

  iVar1 = *(u32 *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  flags = *(s16 *)(iVar1 + 0x60);
  if ((flags & 0x40) == 0) {
    return;
  }
  *(s16 *)(iVar1 + 0x60) = (s16)(flags & ~0x40);
  *(f32 *)(iVar1 + 0x10) = *(f32 *)(param_1 + 0xc);
  *(f32 *)(iVar1 + 0x14) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(iVar1 + 0x18) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(iVar1 + 0x1c) = *(f32 *)(param_1 + 0x18);
  *(f32 *)(iVar1 + 0x20) = *(f32 *)(param_1 + 0x1c);
  *(f32 *)(iVar1 + 0x24) = *(f32 *)(param_1 + 0x20);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_DisableObject
 * EN v1.0 Address: 0x80035F00
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80035FF8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_DisableObject(u32 param_1)
{
  u32 iVar1;

  iVar1 = *(u32 *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  *(s16 *)(iVar1 + 0x60) = (s16)(*(s16 *)(iVar1 + 0x60) & ~1);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_EnableObject
 * EN v1.0 Address: 0x80035F20
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x80036018
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_EnableObject(u32 param_1)
{
  u32 iVar1;
  s16 flags;

  iVar1 = *(u32 *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  flags = *(s16 *)(iVar1 + 0x60);
  if ((flags & 1) != 0) {
    return;
  }
  *(s16 *)(iVar1 + 0x60) = (s16)(flags | 1);
  *(f32 *)(iVar1 + 0x10) = *(f32 *)(param_1 + 0xc);
  *(f32 *)(iVar1 + 0x14) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(iVar1 + 0x18) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(iVar1 + 0x1c) = *(f32 *)(param_1 + 0x18);
  *(f32 *)(iVar1 + 0x20) = *(f32 *)(param_1 + 0x1c);
  *(f32 *)(iVar1 + 0x24) = *(f32 *)(param_1 + 0x20);
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ObjHits_IsObjectEnabled
 * EN v1.0 Address: 0x80035F7C
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80036074
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort ObjHits_IsObjectEnabled(int param_1)
{
  return *(s16 *)(*(int *)(param_1 + 0x54) + 0x60) & 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SyncObjectPosition
 * EN v1.0 Address: 0x80035F8C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80036084
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SyncObjectPosition(u32 param_1)
{
  u32 iVar1;

  iVar1 = *(u32 *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  *(f32 *)(iVar1 + 0x10) = *(f32 *)(param_1 + 0xc);
  *(f32 *)(iVar1 + 0x14) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(iVar1 + 0x18) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(iVar1 + 0x1c) = *(f32 *)(param_1 + 0x18);
  *(f32 *)(iVar1 + 0x20) = *(f32 *)(param_1 + 0x1c);
  *(f32 *)(iVar1 + 0x24) = *(f32 *)(param_1 + 0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_AllocObjectState
 * EN v1.0 Address: 0x80035FCC
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800360C4
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjHits_AllocObjectState(int param_1,uint param_2)
{
  uint uVar1;
  int iVar2;

  uVar1 = roundUpTo4(param_2);
  *(uint *)(param_1 + 0x54) = uVar1;
  iVar2 = *(int *)(param_1 + 0x54);
  ObjHits_RefreshObjectState(param_1);
  *(undefined *)(iVar2 + 0xae) = 1;
  if ((*(byte *)(iVar2 + 0x62) & 0x30) != 0) {
    *(undefined *)(iVar2 + 0xaf) = 2;
  }
  return uVar1 + 0xb8;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_RefreshObjectState
 * EN v1.0 Address: 0x80036044
 * EN v1.0 Size: 1036b
 * EN v1.1 Address: 0x8003613C
 * EN v1.1 Size: 1036b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_RefreshObjectState(int param_1)
{
  float fVar1;
  short sVar3;
  short sVar4;
  uint iVar5;
  int *piVar6;

  iVar5 = *(uint *)(param_1 + 0x54);
  if (iVar5 != 0) {
    *(undefined2 *)(iVar5 + 0x60) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x4e);
    *(undefined *)(iVar5 + 0x62) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x65);
    if (((*(byte *)(iVar5 + 0x62) & 0x20) != 0) &&
       ((piVar6 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),
        (*(ushort *)(*piVar6 + 2) & 0x1000) == 0 || (piVar6[5] == 0)))) {
      *(byte *)(iVar5 + 0x62) = *(byte *)(iVar5 + 0x62) & 0xdf;
    }
    *(undefined *)(iVar5 + 0x6a) = *(undefined *)(*(int *)(param_1 + 0x50) + 99);
    *(undefined *)(iVar5 + 0x6b) = *(undefined *)(*(int *)(param_1 + 0x50) + 100);
    *(ushort *)(iVar5 + 0x5a) = (ushort)*(byte *)(*(int *)(param_1 + 0x50) + 0x62);
    *(undefined2 *)(iVar5 + 0x5c) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x68);
    *(undefined2 *)(iVar5 + 0x5e) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6a);
    *(undefined *)(iVar5 + 0xb0) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x60);
    *(undefined2 *)(iVar5 + 0x58) = 0x400;
    fVar1 = (float)(s32)*(short *)(iVar5 + 0x5a);
    *(float *)(iVar5 + 0xc) = fVar1 * fVar1;
    *(undefined *)(iVar5 + 0xb6) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x90);
    *(ushort *)(iVar5 + 100) = (ushort)*(byte *)(*(int *)(param_1 + 0x50) + 0x77);
    *(undefined2 *)(iVar5 + 0x66) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6c);
    *(undefined2 *)(iVar5 + 0x68) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6e);
    *(float *)(iVar5 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if ((*(byte *)(iVar5 + 0x62) & 2) == 0) {
      if ((*(byte *)(iVar5 + 0x62) & 1) != 0) {
        if ((float)(s32)*(short *)(iVar5 + 0x5a) > *(float *)(iVar5 + 0x28)) {
          *(float *)(iVar5 + 0x28) = (float)(s32)*(short *)(iVar5 + 0x5a);
        }
      }
    }
    else {
      sVar3 = *(short *)(iVar5 + 0x5c);
      if (sVar3 < 0) {
        sVar3 = -sVar3;
      }
      sVar4 = *(short *)(iVar5 + 0x5e);
      if (sVar4 < 0) {
        sVar4 = -sVar4;
      }
      if (sVar4 < sVar3) {
        sVar4 = sVar3;
      }
      if ((float)(s32)sVar4 > *(float *)(iVar5 + 0x28)) {
        *(float *)(iVar5 + 0x28) = (float)(s32)sVar4;
      }
    }
    *(float *)(iVar5 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if (((*(byte *)(iVar5 + 0x62) & 2) != 0) || ((*(byte *)(iVar5 + 0x62) & 1) != 0)) {
      if ((float)(s32)*(short *)(iVar5 + 0x5a) > *(float *)(iVar5 + 0x2c)) {
        *(float *)(iVar5 + 0x2c) = (float)(s32)*(short *)(iVar5 + 0x5a);
      }
    }
    *(float *)(iVar5 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if ((*(byte *)(iVar5 + 0xb6) & 2) == 0) {
      if ((*(byte *)(iVar5 + 0xb6) & 1) != 0) {
        if ((float)(s32)*(short *)(iVar5 + 100) > *(float *)(iVar5 + 0x30)) {
          *(float *)(iVar5 + 0x30) = (float)(s32)*(short *)(iVar5 + 100);
        }
      }
    }
    else {
      sVar3 = *(short *)(iVar5 + 0x66);
      if (sVar3 < 0) {
        sVar3 = -sVar3;
      }
      sVar4 = *(short *)(iVar5 + 0x68);
      if (sVar4 < 0) {
        sVar4 = -sVar4;
      }
      if (sVar4 < sVar3) {
        sVar4 = sVar3;
      }
      if ((float)(s32)sVar4 > *(float *)(iVar5 + 0x30)) {
        *(float *)(iVar5 + 0x30) = (float)(s32)sVar4;
      }
    }
    *(float *)(iVar5 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if (((*(byte *)(iVar5 + 0xb6) & 2) != 0) || ((*(byte *)(iVar5 + 0xb6) & 1) != 0)) {
      if ((float)(s32)*(short *)(iVar5 + 100) > *(float *)(iVar5 + 0x34)) {
        *(float *)(iVar5 + 0x34) = (float)(s32)*(short *)(iVar5 + 100);
      }
    }
    *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x2c);
    if (*(float *)(iVar5 + 0x38) < *(float *)(iVar5 + 0x34)) {
      *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x34);
    }
    *(undefined *)(iVar5 + 0xb4) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x70);
    *(undefined *)(iVar5 + 0xb5) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x67);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_RecordObjectHit
 * EN v1.0 Address: 0x80036450
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x80036548
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjHits_RecordObjectHit(int obj,int hitObj,char priority,u8 hitVolume,u8 sphereIndex)
{
  ObjHitsPriorityState *hitState;
  int hitSlot;
  
  if (priority == '\0') {
    return 0;
  }
  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) == 0) {
    return 0;
  }
  if ((hitObj != 0) && (*(int *)(hitObj + 0x54) != 0)) {
    (*(ObjHitsPriorityState **)(hitObj + 0x54))->lastHitObject = obj;
  }
  hitSlot = 0;
  while (hitSlot < hitState->priorityHitCount) {
    if (hitState->hitObjects[hitSlot] == hitObj) {
      if (hitState->priorities[hitSlot] > priority) {
        hitState->sphereIndices[hitSlot] = sphereIndex;
        hitState->priorities[hitSlot] = priority;
        hitState->hitVolumes[hitSlot] = hitVolume;
        hitState->hitPosX[hitSlot] = *(float *)(obj + 0xc);
        hitState->hitPosY[hitSlot] = *(float *)(obj + 0x10);
        hitState->hitPosZ[hitSlot] = *(float *)(obj + 0x14);
      }
      hitSlot = hitState->priorityHitCount + 1;
    }
    hitSlot = hitSlot + 1;
  }
  if ((hitSlot == hitState->priorityHitCount) &&
      (hitState->priorityHitCount < OBJHITS_PRIORITY_HIT_COUNT)) {
    hitState->sphereIndices[hitState->priorityHitCount] = sphereIndex;
    *(char *)((int)hitState->priorities + hitState->priorityHitCount) = priority;
    *(undefined *)((int)hitState->hitVolumes + hitState->priorityHitCount) = hitVolume;
    hitState->hitObjects[hitState->priorityHitCount] = hitObj;
    hitState->hitPosX[hitState->priorityHitCount] = *(float *)(obj + 0xc);
    hitState->hitPosY[hitState->priorityHitCount] = *(float *)(obj + 0x10);
    hitState->hitPosZ[hitState->priorityHitCount] = *(float *)(obj + 0x14);
    hitState->priorityHitCount = hitState->priorityHitCount + '\x01';
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_RecordPositionHit
 * EN v1.0 Address: 0x800365B8
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800366B0
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int
ObjHits_RecordPositionHit(f32 hitPosX,f32 hitPosY,f32 hitPosZ,int obj,int hitObj,char priority,
            u8 hitVolume,u8 sphereIndex)
{
  int hitObjectOffset;
  int hitSlot;
  ObjHitsPriorityState *hitState;
  
  if (priority == '\0') {
    return 0;
  }
  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) == 0) {
    return 0;
  }
  if ((hitObj != 0) && (*(int *)(hitObj + 0x54) != 0)) {
    (*(ObjHitsPriorityState **)(hitObj + 0x54))->lastHitObject = obj;
  }
  hitSlot = 0;
  while( true ) {
    hitObjectOffset = (int)hitState->priorityHitCount;
    if (hitObjectOffset <= hitSlot) break;
    hitObjectOffset = hitSlot * 4;
    if (hitState->hitObjects[hitSlot] == hitObj) {
      hitSlot = (int)hitState + hitSlot;
      if (priority < *(char *)(hitSlot + 0x75)) {
        *(undefined *)(hitSlot + 0x72) = sphereIndex;
        *(char *)(hitSlot + 0x75) = priority;
        *(undefined *)(hitSlot + 0x78) = hitVolume;
        *(float *)((int)hitState->hitPosX + hitObjectOffset) = hitPosX;
        *(float *)((int)hitState->hitPosY + hitObjectOffset) = hitPosY;
        *(float *)((int)hitState->hitPosZ + hitObjectOffset) = hitPosZ;
      }
      hitSlot = hitState->priorityHitCount + 1;
    }
    hitSlot = hitSlot + 1;
  }
  if ((hitSlot == hitObjectOffset) && (hitObjectOffset < OBJHITS_PRIORITY_HIT_COUNT)) {
    hitState->sphereIndices[hitObjectOffset] = sphereIndex;
    *(char *)((int)hitState->priorities + hitState->priorityHitCount) = priority;
    *(undefined *)((int)hitState->hitVolumes + hitState->priorityHitCount) = hitVolume;
    hitState->hitObjects[hitState->priorityHitCount] = hitObj;
    *(float *)((int)hitState->hitPosX + hitState->priorityHitCount * 4) = hitPosX;
    *(float *)((int)hitState->hitPosY + hitState->priorityHitCount * 4) = hitPosY;
    *(float *)((int)hitState->hitPosZ + hitState->priorityHitCount * 4) = hitPosZ;
    hitState->priorityHitCount = hitState->priorityHitCount + '\x01';
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_AddContactObject
 * EN v1.0 Address: 0x80036708
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80036800
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_AddContactObject(int param_1,int param_2)
{
  u8 cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;

  iVar4 = *(int *)(param_1 + 0x58);
  if ((u32)iVar4 == 0) {
    return;
  }
  iVar2 = (int)*(char *)(iVar4 + 0x10f);
  if (iVar2 >= 3) {
    return;
  }
  iVar3 = 0;
  for (iVar5 = 0; iVar5 < iVar2; iVar5++) {
    if ((u32)*(int *)(iVar4 + iVar3 + 0x100) == (u32)param_2) {
      return;
    }
    iVar3 = iVar3 + 4;
  }
  iVar2 = *(int *)(param_1 + 0x58);
  cVar1 = *(u8 *)(iVar4 + 0x10f);
  *(undefined *)(iVar4 + 0x10f) = cVar1 + 1;
  *(int *)(iVar2 + (s8)cVar1 * 4 + 0x100) = param_2;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_GetPriorityHitWithPosition
 * EN v1.0 Address: 0x80036770
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x80036868
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int ObjHits_GetPriorityHitWithPosition(int obj,undefined4 *outHitObject,int *outSphereIndex,
                uint *outHitVolume,float *outHitPosX,float *outHitPosY,float *outHitPosZ)
{
  u8 hitPriority;
  int hitCount;
  ObjHitsPriorityState *hitState;
  int hitSlot;
  u8 bestPriority;
  s8 bestHitSlot;

  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if (hitState == 0) {
    return 0;
  }
  hitCount = (int)hitState->priorityHitCount;
  if (hitCount != 0) {
    bestPriority = OBJHITS_PRIORITY_INVALID;
    bestHitSlot = -1;
    for (hitSlot = 0; hitSlot < hitCount; hitSlot++) {
      hitPriority = hitState->priorities[hitSlot];
      if ((s8)hitPriority < (s8)bestPriority) {
        bestPriority = hitPriority;
        bestHitSlot = (char)hitSlot;
      }
    }
    if (bestHitSlot != -1) {
      if (outHitObject != (undefined4 *)0x0) {
        *outHitObject = *(undefined4 *)((int)hitState->hitObjects + bestHitSlot * 4);
      }
      if (outSphereIndex != (int *)0x0) {
        *outSphereIndex = (int)hitState->sphereIndices[bestHitSlot];
      }
      if (outHitVolume != (uint *)0x0) {
        *outHitVolume = (uint)hitState->hitVolumes[bestHitSlot];
      }
      if (outHitPosX != (float *)0x0) {
        *outHitPosX = *(float *)((int)hitState->hitPosX + bestHitSlot * 4);
        *outHitPosY = *(float *)((int)hitState->hitPosY + bestHitSlot * 4);
        *outHitPosZ = *(float *)((int)hitState->hitPosZ + bestHitSlot * 4);
      }
      return (int)(s8)bestPriority;
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHits_GetPriorityHit
 * EN v1.0 Address: 0x8003687C
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80036974
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int ObjHits_GetPriorityHit(int obj,undefined4 *outHitObject,int *outSphereIndex,uint *outHitVolume)
{
  u8 hitPriority;
  int hitCount;
  ObjHitsPriorityState *hitState;
  int hitSlot;
  u8 bestPriority;
  s8 bestHitSlot;

  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if (hitState == 0) {
    return 0;
  }
  hitCount = (int)hitState->priorityHitCount;
  if (hitCount != 0) {
    bestPriority = OBJHITS_PRIORITY_INVALID;
    bestHitSlot = -1;
    for (hitSlot = 0; hitSlot < hitCount; hitSlot++) {
      hitPriority = hitState->priorities[hitSlot];
      if ((s8)hitPriority < (s8)bestPriority) {
        bestPriority = hitPriority;
        bestHitSlot = (char)hitSlot;
      }
    }
    if (bestHitSlot != -1) {
      if (outHitObject != (undefined4 *)0x0) {
        *outHitObject = *(undefined4 *)((int)hitState->hitObjects + bestHitSlot * 4);
      }
      if (outSphereIndex != (int *)0x0) {
        *outSphereIndex = (int)hitState->sphereIndices[bestHitSlot];
      }
      if (outHitVolume != (uint *)0x0) {
        *outHitVolume = (uint)hitState->hitVolumes[bestHitSlot];
      }
      return (int)(s8)bestPriority;
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_UpdateResetObjects
 * EN v1.0 Address: 0x80036944
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80036A3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHitReact_UpdateResetObjects(void)
{
  ObjAnimComponent *obj;
  int objectIndex;
  int objectOffset;

  objectIndex = 0;
  objectOffset = 0;
  for (; objectIndex < gObjHitsResetObjectCount; objectIndex = objectIndex + 1) {
    obj = *(ObjAnimComponent **)((int)gObjHitsResetObjects + objectOffset);
    if (((*(uint *)((int)obj->modelInstance + 0x44) & 0x40) == 0) &&
       (obj->activeHitboxMode != 'd')) {
      Obj_UpdateObject(obj,obj->modelInstance);
    }
    objectOffset = objectOffset + 4;
  }
  objectOffset = 0;
  objectIndex = objectOffset;
  for (; objectOffset < gObjHitsResetObjectCount; objectOffset = objectOffset + 1) {
    ObjHitbox_UpdateRotatedBounds(*(short **)((int)gObjHitsResetObjects + objectIndex),1);
    objectIndex = objectIndex + 4;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_ResetWorkBuffers
 * EN v1.0 Address: 0x800369F0
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x80036AE8
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_ResetWorkBuffers(void)
{
  int clearedSlots;
  int slotOffset;
  int remainingSlots;

  clearedSlots = 0;
  slotOffset = 0;
  remainingSlots = OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_COUNT;
  do {
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x3c) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x78) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0xb4) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0xf0) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x12c) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x168) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x1a4) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x1e0) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x21c) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x258) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x294) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x2d0) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x30c) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x348) = 0;
    *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset + 0x384) = 0;
    slotOffset += OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SIZE;
    clearedSlots += OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SLOTS;
    remainingSlots--;
  } while (remainingSlots != 0);
  remainingSlots = OBJHITS_PRIORITY_WORK_SLOT_COUNT - clearedSlots;
  slotOffset = clearedSlots * OBJHITS_PRIORITY_WORK_SLOT_SIZE;
  if (clearedSlots < OBJHITS_PRIORITY_WORK_SLOT_COUNT) {
    do {
      *(undefined4 *)(gObjHitsPriorityHitStates + slotOffset) = 0;
      slotOffset += OBJHITS_PRIORITY_WORK_SLOT_SIZE;
      remainingSlots--;
    } while (remainingSlots != 0);
  }
  gObjHitsResetObjectCount = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_GetResetObjects
 * EN v1.0 Address: 0x80036AFC
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80036BF4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int *ObjHitReact_GetResetObjects(int *outObjectCount)
{
  *outObjectCount = gObjHitsResetObjectCount;
  return gObjHitsResetObjects;
}

/*
 * --INFO--
 *
 * Function: ObjHits_InitWorkBuffers
 * EN v1.0 Address: 0x80036B0C
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80036C04
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_InitWorkBuffers(void)
{
  gObjHitsResetObjects = (int *)mmAlloc(OBJHITREACT_MAX_RESET_OBJECTS * sizeof(int),0xe,0);
  gObjHitsPriorityHitStates =
      (undefined4)mmAlloc(OBJHITS_PRIORITY_WORK_SLOT_COUNT * OBJHITS_PRIORITY_WORK_SLOT_SIZE,0xe,0);
  lbl_803DCBD8 = mmAlloc(0x1900,0xe,0);
  lbl_803DCBD0[0] = mmAlloc(0x400,0xe,0);
  lbl_803DCBD0[1] = mmAlloc(0x400,0xe,0);
  lbl_803DCBC8[0] = mmAlloc(0x400,0xe,0);
  lbl_803DCBC8[1] = mmAlloc(0x400,0xe,0);
  gObjHitsPriorityHitTickDelta = lbl_803DE914;
  gObjHitsActiveHitVolumeObjects[0] = 0;
  gObjHitsActiveHitVolumeObjects[1] = 0;
  gObjHitsActiveHitVolumeObjects[2] = 0;
  gObjHitsActiveHitVolumeObjects[3] = 0;
  gObjHitsActiveHitVolumeObjects[4] = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_ContainsObject
 * EN v1.0 Address: 0x80036C0C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80036D04
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
uint ObjGroup_ContainsObject(uint obj,int group)
{
  uint *entry;
  uint index;
  uint limit;
  uint limitXorIndex;
  int halfDiff;

  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    return 0;
  }
  index = (uint)gObjGroupOffsets[group];
  limit = (uint)gObjGroupOffsets[group + 1];
  for (entry = (uint *)gObjGroupObjects + index; ((int)index < (int)limit && (obj != *entry));
      entry = entry + 1, index = index + 1) {
  }
  limitXorIndex = limit ^ index;
  halfDiff = (int)limitXorIndex >> 1;
  limitXorIndex = limitXorIndex & limit;
  return (uint)(halfDiff - limitXorIndex) >> 0x1f;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObjectToPoint
 * EN v1.0 Address: 0x80036C80
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80036D78
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjGroup_FindNearestObjectToPoint(int group,float *point,float *maxDistance)
{
  uint nearest;
  uint index;
  uint limit;
  uint *entry;
  float distanceSq;
  float bestDistanceSq;
  
  nearest = 0;
  bestDistanceSq = *maxDistance * *maxDistance;
  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    return 0;
  }
  index = (uint)gObjGroupOffsets[group];
  limit = (uint)gObjGroupOffsets[group + 1];
  entry = (uint *)gObjGroupObjects + index;
  while ((int)index < (int)limit) {
    if (*entry != 0) {
      distanceSq = PSVECSquareDistance(point,(float *)(*entry + 0x18));
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        nearest = *entry;
      }
    }
    entry++;
    index++;
  }
  if (nearest != 0) {
    *maxDistance = sqrtf(bestDistanceSq);
  }
  return nearest;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObjectForObject
 * EN v1.0 Address: 0x80036D60
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80036E58
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjGroup_FindNearestObjectForObject(int group,uint obj,float *maxDistance)
{
  uint nearest;
  uint index;
  uint limit;
  uint *entry;
  float distanceSq;
  float bestDistanceSq;
  
  nearest = 0;
  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    return 0;
  }
  if (maxDistance != (float *)0x0) {
    bestDistanceSq = *maxDistance * *maxDistance;
  }
  else {
    bestDistanceSq = lbl_803DE968;
  }
  index = (uint)gObjGroupOffsets[group];
  limit = (uint)gObjGroupOffsets[group + 1];
  entry = (uint *)gObjGroupObjects + index;
  while ((int)index < (int)limit) {
    if (*entry != obj) {
      distanceSq = vec3f_distanceSquared((float *)(obj + 0x18),(float *)(*entry + 0x18));
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        nearest = *entry;
      }
    }
    entry++;
    index++;
  }
  if ((nearest != 0) && (maxDistance != (float *)0x0)) {
    *maxDistance = sqrtf(bestDistanceSq);
  }
  return nearest;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObject
 * EN v1.0 Address: 0x80036E58
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80036F50
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjGroup_FindNearestObject(int group,uint obj,float *maxDistance)
{
  uint nearest;
  uint index;
  uint limit;
  uint *entry;
  float distanceSq;
  float bestDistanceSq;
  
  nearest = 0;
  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    return 0;
  }
  if (maxDistance != (float *)0x0) {
    bestDistanceSq = *maxDistance * *maxDistance;
  }
  else {
    bestDistanceSq = lbl_803DE968;
  }
  index = (uint)gObjGroupOffsets[group];
  limit = (uint)gObjGroupOffsets[group + 1];
  entry = (uint *)gObjGroupObjects + index;
  while ((int)index < (int)limit) {
    if (*entry != obj) {
      distanceSq = vec3f_distanceSquared((float *)(obj + 0x18),(float *)(*entry + 0x18));
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        nearest = *entry;
      }
    }
    entry++;
    index++;
  }
  if ((nearest != 0) && (maxDistance != (float *)0x0)) {
    *maxDistance = sqrtf(bestDistanceSq);
  }
  return nearest;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_GetObjects
 * EN v1.0 Address: 0x80036F50
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80037048
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 * ObjGroup_GetObjects(int group,int *countOut)
{
  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    *countOut = 0;
    return (undefined4 *)0x0;
  }
  *countOut = (uint)gObjGroupOffsets[group + 1] - (uint)gObjGroupOffsets[group];
  return (undefined4 *)(gObjGroupObjects + gObjGroupOffsets[group]);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_RemoveObject
 * EN v1.0 Address: 0x80036FA4
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x8003709C
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjGroup_RemoveObject(uint obj,int group)
{
  u8 *offset;
  int count;
  int index;
  int limit;
  uint *entries;

  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    return;
  }
  offset = gObjGroupOffsets;
  index = (int)offset[group];
  offset += group;
  limit = (int)offset[1];
  entries = gObjGroupObjects + index;
  while ((index < limit) && (*entries != obj)) {
    entries++;
    index++;
  }
  if (limit <= index) {
    return;
  }
  count = (int)gObjGroupObjectCount - 1;
  gObjGroupObjectCount = count;
  entries = gObjGroupObjects + index;
  while (index < count) {
    *entries = entries[1];
    entries++;
    index++;
  }
  group++;
  offset = gObjGroupOffsets + group;
  while (group <= OBJGROUP_COUNT) {
    (*offset)--;
    offset++;
    group++;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_GetObjectGroup
 * EN v1.0 Address: 0x80037194
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8003728C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjGroup_GetObjectGroup(uint obj)
{
  int group;
  uint *entry;
  u8 *offset;
  int objectIndex;
  int objectCount;
  
  objectIndex = 0;
  entry = gObjGroupObjects;
  objectCount = (int)gObjGroupObjectCount;
  for (; objectIndex < objectCount; objectIndex++) {
    if (*entry == obj) {
      group = 0;
      offset = gObjGroupOffsets;
      while (((int)(uint)*offset <= objectIndex) && (group < OBJGROUP_OFFSET_CLEAR_COUNT)) {
        offset++;
        group++;
      }
      return group;
    }
    entry++;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_AddObject
 * EN v1.0 Address: 0x80037200
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x800372F8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjGroup_AddObject(uint obj,int group)
{
  u8 *offset;
  int count;
  int index;
  int insertIndex;
  int limit;
  uint *entries;

  if ((group < 0) || (group >= OBJGROUP_COUNT)) {
    return;
  }
  if ((int)(uint)gObjGroupObjectCount >= OBJGROUP_MAX_OBJECTS) {
    OSReport(sObjAddObjectTypeReachedMaxTypes);
    return;
  }
  offset = gObjGroupOffsets;
  insertIndex = (int)offset[group];
  offset += group;
  limit = (int)offset[1];
  entries = gObjGroupObjects + insertIndex;
  for (index = insertIndex; index < limit; index++) {
    if (*entries == obj) {
      return;
    }
    entries++;
  }
  if (limit != insertIndex) {
    insertIndex = limit - 1;
  }
  gObjGroupObjectCount = gObjGroupObjectCount + 1;
  count = (int)(uint)gObjGroupObjectCount - 1;
  entries = gObjGroupObjects + count;
  for (index = count; insertIndex < index; index--) {
    *entries = entries[-1];
    entries--;
  }
  gObjGroupObjects[insertIndex] = obj;
  group++;
  offset = gObjGroupOffsets + group;
  while (group <= OBJGROUP_COUNT) {
    *offset = *offset + 1;
    offset++;
    group++;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjGroup_ClearAll
 * EN v1.0 Address: 0x8003744C
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80037544
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void* memset(void* dst, int val, u32 n);
#pragma scheduling off
#pragma peephole off
void ObjGroup_ClearAll(void)
{
  memset(gObjGroupOffsets, 0, OBJGROUP_OFFSET_CLEAR_COUNT);
  gObjGroupObjectCount = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjMsg_Peek
 * EN v1.0 Address: 0x80037484
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8003757C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjMsg_Peek(void *obj,uint *outMessage,uint *outSender,uint *outParam)
{
  ObjMsgQueue *queue;
  
  if (obj == (void *)0x0) {
    return 0;
  }
  queue = *(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET);
  if ((queue != (ObjMsgQueue *)0x0) && (queue->count != 0)) {
    if (outMessage != (uint *)0x0) {
      *outMessage = queue->entries[0].message;
    }
    if (outSender != (uint *)0x0) {
      *outSender = queue->entries[0].sender;
    }
    if (outParam != (uint *)0x0) {
      *outParam = queue->entries[0].param;
    }
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_Pop
 * EN v1.0 Address: 0x800374EC
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x800375E4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 ObjMsg_Pop(void *obj,uint *outMessage,uint *outSender,uint *outParam)
{
  ObjMsgQueue *queue;
  ObjMsgQueueSlotBase *slot;
  uint i;

  if (obj == (void *)0x0) {
    return 0;
  }
  queue = *(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET);
  if ((queue != (ObjMsgQueue *)0x0) && (queue->count != 0)) {
    queue->count = queue->count - 1;
    if (outMessage != (uint *)0x0) {
      *outMessage = queue->entries[0].message;
    }
    if (outSender != (uint *)0x0) {
      *outSender = queue->entries[0].sender;
    }
    if (outParam != (uint *)0x0) {
      *outParam = queue->entries[0].param;
    }
    for (i = 0; i < queue->count; i = i + 1) {
      slot = (ObjMsgQueueSlotBase *)((byte *)queue + ((i + i + i) << 2));
      slot->entry.message = *(uint *)((byte *)slot + 0x14);
      slot->entry.sender = *(uint *)((byte *)slot + 0x18);
      slot->entry.param = *(uint *)((byte *)slot + 0x1c);
    }
    return 1;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToNearbyObjects
 * EN v1.0 Address: 0x8003759C
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80037694
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjMsg_SendToNearbyObjects(int targetId,float radius,uint flags,void *sender,uint message,uint param)
{
  int *objects;
  uint count;
  int maskedFlags;
  ObjMsgQueue *queue;
  ObjMsgQueueSlotBase *slot;
  int objectIndex;
  int objectCount;
  void *obj;

  objects = (int *)ObjList_GetObjects(&objectIndex,&objectCount);
  maskedFlags = flags & 0xffff;
  for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
    obj = (void *)objects[objectIndex];
    if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
        ((*(short *)((byte *)obj + 0x46) == (short)targetId ||
          ((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0))) &&
        ((Vec_distance((float *)((byte *)sender + 0x18),(float *)((byte *)obj + 0x18)) < radius &&
          (obj != (void *)0x0)) &&
         (queue = *(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET),
          queue != (ObjMsgQueue *)0x0))) {
      count = queue->count;
      if (count < queue->capacity) {
        slot = (ObjMsgQueueSlotBase *)((byte *)queue + ((count + count + count) << 2));
        slot->entry.message = message;
        slot->entry.sender = (uint)sender;
        slot->entry.param = param;
        queue->count = queue->count + 1;
      } else {
        debugPrintf(sObjMsgOverflowInObjectWarning,message,
                     (int)*(short *)((byte *)obj + 0x44),(int)*(short *)((byte *)obj + 0x46),
                     (int)*(short *)((byte *)sender + 0x46));
      }
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToObjects
 * EN v1.0 Address: 0x800376D8
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x800377D0
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjMsg_SendToObjects(int targetId,uint flags,void *sender,uint message,uint param)
{
  int *objects;
  uint count;
  int maskedFlags;
  ObjMsgQueue *queue;
  ObjMsgQueueSlotBase *slot;
  int objectIndex;
  int objectCount;
  void *obj;
  
  objects = (int *)ObjList_GetObjects(&objectIndex,&objectCount);
  maskedFlags = flags & 0xffff;
  if ((maskedFlags & OBJMSG_SEND_MATCH_OBJTYPE) != 0) {
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
      obj = (void *)objects[objectIndex];
      if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
          (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 ||
            (targetId == *(short *)((byte *)obj + 0x46)))) &&
          ((obj != (void *)0x0 &&
            (queue = *(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET),
             queue != (ObjMsgQueue *)0x0)))) {
        count = queue->count;
        if (count < queue->capacity) {
          slot = (ObjMsgQueueSlotBase *)((byte *)queue + ((count + count + count) << 2));
          slot->entry.message = message;
          slot->entry.sender = (uint)sender;
          slot->entry.param = param;
          queue->count = queue->count + 1;
        } else {
          debugPrintf(sObjMsgOverflowInObjectWarning,message,
                       (int)*(short *)((byte *)obj + 0x44),(int)*(short *)((byte *)obj + 0x46),
                       (int)*(short *)((byte *)sender + 0x46));
        }
      }
    }
  }
  else {
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
      obj = (void *)objects[objectIndex];
      if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
          (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 ||
            (targetId == *(short *)((byte *)obj + 0x44)))) &&
          ((obj != (void *)0x0 &&
            (queue = *(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET),
             queue != (ObjMsgQueue *)0x0)))) {
        count = queue->count;
        if (count < queue->capacity) {
          slot = (ObjMsgQueueSlotBase *)((byte *)queue + ((count + count + count) << 2));
          slot->entry.message = message;
          slot->entry.sender = (uint)sender;
          slot->entry.param = param;
          queue->count = queue->count + 1;
        } else {
          debugPrintf(sObjMsgOverflowInObjectWarning,message,
                       (int)*(short *)((byte *)obj + 0x44),(int)*(short *)((byte *)obj + 0x46),
                       (int)*(short *)((byte *)sender + 0x46));
        }
      }
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToObject
 * EN v1.0 Address: 0x800378C4
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x800379BC
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
uint ObjMsg_SendToObject(void *obj,uint message,void *sender,uint param)
{
  uint count;
  void *dstObj;
  void *senderObj;
  ObjMsgQueue *queue;
  ObjMsgQueueSlotBase *slot;

  dstObj = obj;
  senderObj = sender;
  if (dstObj == (void *)0x0) {
    return 0;
  }
  queue = *(ObjMsgQueue **)((byte *)dstObj + OBJMSG_QUEUE_OFFSET);
  if (queue != (ObjMsgQueue *)0x0) {
    count = queue->count;
    if (count < queue->capacity) {
      slot = (ObjMsgQueueSlotBase *)((byte *)queue + ((count + count + count) << 2));
      slot->entry.message = message;
      slot->entry.sender = (uint)senderObj;
      slot->entry.param = param;
      queue->count = queue->count + 1;
      return queue->count;
    }
    debugPrintf(sObjMsgOverflowInObjectWarning,message,
                 (int)*(short *)((byte *)dstObj + 0x44),(int)*(short *)((byte *)dstObj + 0x46),
                 (int)*(short *)((byte *)senderObj + 0x46));
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjMsg_AllocQueue
 * EN v1.0 Address: 0x80037964
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80037A5C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjMsg_AllocQueue(void *obj,int capacity)
{
  int queueBytes;
  ObjMsgQueue *queue;

  if (((capacity != 0) && (obj != (void *)0x0)) &&
      (*(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET) == (ObjMsgQueue *)0x0)) {
    queueBytes = (capacity * 3 + 2) * 4;
    queue = (ObjMsgQueue *)mmAlloc(queueBytes,0xe,0);
    queue->count = 0;
    queue->capacity = capacity;
    *(ObjMsgQueue **)((byte *)obj + OBJMSG_QUEUE_OFFSET) = queue;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Obj_IsObjectAlive
 * EN v1.0 Address: 0x800379DC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80037AD4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 Obj_IsObjectAlive(u32 param_1)
{
  undefined4 uVar1;

  uVar1 = 0;
  if ((param_1 != 0) && ((*(ushort *)(param_1 + OBJLINK_FLAGS_OFFSET) & OBJLINK_FLAGS_DEAD) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjTrigger_UpdateIdBlockFlag
 * EN v1.0 Address: 0x80037A04
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80037AFC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
bool ObjTrigger_UpdateIdBlockFlag(int param_1)
{
  int iVar1;
  byte flags;
  
  iVar1 = (int)Obj_GetPlayerObject();
  iVar1 = fn_80295CD4(iVar1);
  if (iVar1 != 0) {
    flags = *(byte *)(param_1 + OBJTRIGGER_FLAGS_OFFSET) | OBJTRIGGER_ID_BLOCK_FLAG;
    *(byte *)(param_1 + OBJTRIGGER_FLAGS_OFFSET) = flags;
    return false;
  }
  flags = *(byte *)(param_1 + OBJTRIGGER_FLAGS_OFFSET) & ~OBJTRIGGER_ID_BLOCK_FLAG;
  *(byte *)(param_1 + OBJTRIGGER_FLAGS_OFFSET) = flags;
  return true;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_PollPriorityHitWithCooldown
 * EN v1.0 Address: 0x80037A68
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x80037B60
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjHits_PollPriorityHitWithCooldown(int obj,float *cooldown,undefined4 *outHitObject,float *outHitPos)
{
  int collisionType;
  
  collisionType = 0;
  *cooldown = *cooldown - timeDelta;
  if (*cooldown <= lbl_803DE970) {
    if (outHitPos != (float *)0x0) {
      collisionType = ObjHits_GetPriorityHitWithPosition(obj,outHitObject,(int *)0x0,(uint *)0x0,outHitPos,
                           outHitPos + 1,outHitPos + 2);
      if (collisionType != 0) {
        fn_80054F74(obj,outHitPos);
      }
    }
    else {
      collisionType = ObjHits_GetPriorityHit(obj,outHitObject,(int *)0x0,(uint *)0x0);
    }
    if (collisionType != 0) {
      *cooldown = lbl_803DE974;
    }
  }
  return collisionType;
}
#pragma peephole reset
#pragma scheduling reset

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
/*
 * --INFO--
 *
 * Function: ObjHits_PollPriorityHitEffectWithCooldown
 * EN v1.0 Address: 0x80037B40
 * EN v1.0 Size: 368b
 * EN v1.1 Address: 0x80037C38
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_PollPriorityHitEffectWithCooldown(int obj,uint hitFxMode,uint colorR,uint colorG,
                                              uint colorB,uint sfxId,float *cooldown)
{
  int collisionType;
  ObjHitReactEffectHandle *effectHandle;
  float hitPos[3];
  ObjHitReactEffectPos effectPos;
  ObjHitReactEffectColorArgs effectArgs;
  u32 hitObject;

  *cooldown = *cooldown - timeDelta;
  collisionType = ObjHits_GetPriorityHitWithPosition(obj,(undefined4 *)&hitObject,(int *)0x0,
                                                     (uint *)0x0,&hitPos[0],&hitPos[1],&hitPos[2]);
  if ((*cooldown <= lbl_803DE970) && (collisionType != 0)) {
    *cooldown = lbl_803DE978;
    if ((collisionType != 0x1a) && (collisionType != 5)) {
      hitPos[0] = hitPos[0] + playerMapOffsetX;
      hitPos[2] = hitPos[2] + playerMapOffsetZ;
      effectPos.scale = OBJLIB_UNIT_SCALE;
      effectPos.z = 0;
      effectPos.y = 0;
      effectPos.x = 0;
      effectHandle = Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID,
                                      OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
      effectArgs.hitFxMode = hitFxMode & 0xff;
      effectArgs.colorR = colorR & 0xff;
      effectArgs.colorG = colorG & 0xff;
      effectArgs.colorB = colorB & 0xff;
      effectHandle->vtable->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE,OBJHITREACT_HIT_EFFECT_MODE,
                                  &effectPos,OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,
                                  OBJHITREACT_HIT_EFFECT_NO_SOURCE,
                                  &effectArgs);
      if ((((sfxId & 0xffff) != 0) && (hitObject != 0)) && (*(short *)(hitObject + 0x46) == 0x69)) {
        Sfx_PlayFromObject(obj,sfxId);
      }
    }
  }
  return collisionType;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjLink_DetachChild
 * EN v1.0 Address: 0x80037CB0
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80037DA8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjLink_DetachChild(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;

  iVar4 = 0;
  uVar1 = (uint)*(byte *)(param_1 + OBJLINK_CHILD_COUNT_OFFSET);
  for (iVar3 = param_1; (uVar1 != 0 && (*(int *)(iVar3 + OBJLINK_CHILD_LIST_OFFSET) != param_2)); iVar3 = iVar3 + 4) {
    iVar4 = iVar4 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar3 = param_1 + iVar4 * 4;
  for (; iVar2 = *(byte *)(param_1 + OBJLINK_CHILD_COUNT_OFFSET) - 1, iVar4 < iVar2; iVar4 = iVar4 + 1) {
    *(undefined4 *)(iVar3 + OBJLINK_CHILD_LIST_OFFSET) =
        *(undefined4 *)(iVar3 + OBJLINK_CHILD_LIST_OFFSET + sizeof(int));
    iVar3 = iVar3 + 4;
  }
  *(char *)(param_1 + OBJLINK_CHILD_COUNT_OFFSET) = (char)iVar2;
  *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + OBJLINK_CHILD_COUNT_OFFSET) * 4 +
                  OBJLINK_CHILD_LIST_OFFSET) = 0;
  *(undefined4 *)(param_2 + OBJLINK_PARENT_OFFSET) = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjLink_AttachChild
 * EN v1.0 Address: 0x80037D2C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80037E24
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjLink_AttachChild(int param_1,int param_2,ushort param_3)
{
  u8 bVar1;
  u8* base;

  bVar1 = *(u8 *)(param_1 + OBJLINK_CHILD_COUNT_OFFSET);
  *(u8 *)(param_1 + OBJLINK_CHILD_COUNT_OFFSET) = bVar1 + 1;
  base = (u8*)(param_1 + bVar1 * 4);
  *(int *)(base + OBJLINK_CHILD_LIST_OFFSET) = param_2;
  *(int *)(param_2 + OBJLINK_PARENT_OFFSET) = param_1;
  *(u16 *)(param_2 + OBJLINK_FLAGS_OFFSET) =
      (u16)(*(u16 *)(param_2 + OBJLINK_FLAGS_OFFSET) & OBJLINK_FLAGS_MODE_CLEAR_MASK);
  *(u16 *)(param_2 + OBJLINK_FLAGS_OFFSET) =
      (u16)(*(u16 *)(param_2 + OBJLINK_FLAGS_OFFSET) | param_3);
  *(u8 *)(param_2 + OBJLINK_CHILD_STATE_OFFSET) = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjContact_DispatchCallbacks
 * EN v1.0 Address: 0x80037D74
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80037E6C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjContact_DispatchCallbacks(int objA,int objB)
{
  bool bVar1;
  int objARefCount;
  int objBRefCount;
  ObjContactCallbackEntry *entry;
  int iVar5;

  objARefCount = *(u8 *)(objA + OBJCONTACT_OBJECT_REFCOUNT_OFFSET);
  objBRefCount = *(u8 *)(objB + OBJCONTACT_OBJECT_REFCOUNT_OFFSET);
  entry = gObjContactCallbacks;
  iVar5 = gObjContactCallbackCount;
  while (((objARefCount != 0 && (objBRefCount != 0)) &&
          (bVar1 = iVar5 != 0, iVar5 = iVar5 - 1, bVar1))) {
    if (((u32)entry->objA == (u32)objA) && ((u32)entry->objB == (u32)objB)) {
      objARefCount = objARefCount - 1;
      entry->callback(objA,objB);
    }
    if (((u32)entry->objA == (u32)objB) && ((u32)entry->objB == (u32)objA)) {
      objBRefCount = objBRefCount - 1;
      entry->callback(objB,objA);
    }
    entry++;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjContact_RemoveObjectCallbacks
 * EN v1.0 Address: 0x80037E44
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80037F3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjContact_RemoveObjectCallbacks(int param_1)
{
  ObjContactCallbackEntry *entry;
  ObjContactCallbackEntry *lastEntry;
  int obj;
  int refCount;
  int iVar3;
  int iVar4;

  entry = gObjContactCallbacks;
  iVar3 = gObjContactCallbackCount;
  while (iVar4 = iVar3 + -1, 0 < iVar3) {
    if (((u32)entry->objA == (u32)param_1) || ((u32)entry->objB == (u32)param_1)) {
      gObjContactCallbackCount = gObjContactCallbackCount + -1;
      iVar4 = iVar3 + -2;
      obj = entry->objA;
      refCount = *(u8 *)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET);
      *(u8 *)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) = refCount - 1;
      obj = entry->objB;
      refCount = *(u8 *)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET);
      *(u8 *)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) = refCount - 1;
      iVar3 = gObjContactCallbackCount;
      if ((gObjContactCallbackCount != OBJCONTACT_CALLBACK_LAST_INDEX) &&
          (gObjContactCallbackCount != 0)) {
        lastEntry = &gObjContactCallbacks[iVar3];
        entry->objA = lastEntry->objA;
        entry->objB = lastEntry->objB;
        entry->callback = lastEntry->callback;
      }
    }
    entry++;
    iVar3 = iVar4;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjContact_AddCallback
 * EN v1.0 Address: 0x80037EF0
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x80037FE8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjContact_AddCallback(int param_1,int param_2,ObjContactCallback callback)
{
  int count;
  ObjContactCallbackEntry *entry;
  int iVar3;

  if ((param_1 == 0) || (param_2 == 0)) {
    return 0;
  }
  entry = gObjContactCallbacks;
  count = gObjContactCallbackCount;
  iVar3 = count;
  if (count != 0) {
    do {
      if (((u32)entry->objA == (u32)param_1) && ((u32)entry->objB == (u32)param_2)) {
        return 0;
      }
      entry++;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (count >= OBJCONTACT_CALLBACK_CAPACITY) {
    return 0;
  }
  entry = &gObjContactCallbacks[count];
  entry->objA = param_1;
  entry->objB = param_2;
  entry->callback = callback;
  *(u8 *)(param_1 + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) =
      *(u8 *)(param_1 + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) + 1;
  *(u8 *)(param_2 + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) =
      *(u8 *)(param_2 + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) + 1;
  gObjContactCallbackCount = gObjContactCallbackCount + 1;
  return 1;
}

/*
 * --INFO--
 *
 * Function: ObjTrigger_IsSetById
 * EN v1.0 Address: 0x80037FA4
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8003809C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 ObjTrigger_IsSetById(int param_1,short param_2)
{
  int iVar1;
  int triggerFlags;
  int flagEnabled;
  int flagBlocked;

  triggerFlags = *(byte *)(param_1 + OBJTRIGGER_FLAGS_OFFSET);
  flagEnabled = triggerFlags & OBJTRIGGER_ID_ENABLE_FLAG;
  if (flagEnabled != 0) {
    flagBlocked = triggerFlags & OBJTRIGGER_ID_BLOCK_FLAG;
    if ((flagBlocked == 0) && (iVar1 = (*lbl_803DCA68)->isTriggerSet((int)param_2), iVar1 != 0)) {
      iVar1 = objGetAnimState80A(Obj_GetPlayerObject());
      if (iVar1 == OBJTRIGGER_PLAYER_STATE_NONE) {
        buttonDisable(OBJTRIGGER_BUTTON_DISABLE_INDEX,OBJTRIGGER_BUTTON_DISABLE_FLAG);
        return 1;
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjTrigger_IsSet
 * EN v1.0 Address: 0x80038024
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x8003811C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 ObjTrigger_IsSet(int param_1)
{
  uint flags;
  int iVar1;
  int triggerFlags;
  int flagEnabled;
  int flagBlocked;

  if (*(uint *)(*(int *)(param_1 + 0x50) + 0x40) == 0) {
    return 0;
  }
  flags = buttonGetDisabled(0);
  if ((flags & OBJTRIGGER_BUTTON_DISABLE_FLAG) == 0) {
    triggerFlags = *(byte *)(param_1 + OBJTRIGGER_FLAGS_OFFSET);
    flagEnabled = triggerFlags & OBJTRIGGER_CURRENT_ENABLE_FLAG;
    if (flagEnabled != 0) {
      flagBlocked = triggerFlags & OBJTRIGGER_CURRENT_BLOCK_FLAG;
      if ((flagBlocked == 0) && (iVar1 = (*lbl_803DCA68)->isCurrentTriggerClear(), iVar1 == 0)) {
        iVar1 = objGetAnimState80A(Obj_GetPlayerObject());
        if ((iVar1 == OBJTRIGGER_PLAYER_STATE_NONE) || (iVar1 == OBJTRIGGER_PLAYER_STATE_CLEAR)) {
          buttonDisable(OBJTRIGGER_BUTTON_DISABLE_INDEX,OBJTRIGGER_BUTTON_DISABLE_FLAG);
          return 1;
        }
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjList_FindNearestObjectByDefNo
 * EN v1.0 Address: 0x800380E0
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x800381D8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjList_FindNearestObjectByDefNo(int obj,int defNo,float *maxDistanceSq)
{
  int startIndex;
  int objectCount;
  float invalidDistance;
  float distanceSq;
  uint otherObj;
  int objectIndex;
  int *objects;
  int foundObj;

  objects = (int *)ObjList_GetObjects(&startIndex,&objectCount);
  foundObj = 0;
  *maxDistanceSq = *maxDistanceSq * *maxDistanceSq;
  if (defNo != -1) {
    objectIndex = startIndex;
    objects = objects + startIndex;
    while (objectIndex < objectCount) {
      otherObj = *objects;
      if (((defNo == *(s16 *)(otherObj + 0x46)) && (obj != otherObj)) &&
          (distanceSq = vec3f_distanceSquared((float *)(obj + 0x18),(float *)(otherObj + 0x18)),
           distanceSq < *maxDistanceSq)) {
        *maxDistanceSq = distanceSq;
        foundObj = *objects;
      }
      objects++;
      objectIndex++;
    }
  }
  else {
    objectIndex = startIndex;
    objects = objects + startIndex;
    invalidDistance = lbl_803DE970;
    while (objectIndex < objectCount) {
      distanceSq = vec3f_distanceSquared((float *)(obj + 0x18),(float *)(*objects + 0x18));
      if ((distanceSq != invalidDistance) && (distanceSq < *maxDistanceSq)) {
        *maxDistanceSq = distanceSq;
        foundObj = *objects;
      }
      objects++;
      objectIndex++;
    }
  }
  return foundObj;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjList_ContainsObject
 * EN v1.0 Address: 0x80038208
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80038300
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 ObjList_ContainsObject(int param_1)
{
  uint *entry;
  int i;
  int count;

  entry = (uint *)ObjList_GetObjects(&i, &count);
  i = 0;
  while (i < count) {
    if (*entry == (uint)param_1) {
      return 1;
    }
    entry = entry + 1;
    i = i + 1;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointWorldPositionArray
 * EN v1.0 Address: 0x80038280
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80038378
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjPath_GetPointWorldPositionArray(int obj,int pointIndex,int count,float *positions)
{
  int i;

  for (i = 0; i < count; i++) {
    ObjPath_GetPointWorldPosition(obj,pointIndex + i,positions,positions + 1,positions + 2,0);
    positions = positions + 3;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointLocalPosition
 * EN v1.0 Address: 0x800382F0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800383E8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjPath_GetPointLocalPosition(int param_1,int param_2,float *param_3,float *param_4,
                 float *param_5)
{
  *param_3 = ((ObjPathPoint *)(*(int *)(*(int *)(param_1 + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) +
                               param_2 * sizeof(ObjPathPoint)))->x;
  *param_4 = ((ObjPathPoint *)(*(int *)(*(int *)(param_1 + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) +
                               param_2 * sizeof(ObjPathPoint)))->y;
  *param_5 = ((ObjPathPoint *)(*(int *)(*(int *)(param_1 + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) +
                               param_2 * sizeof(ObjPathPoint)))->z;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointLocalMtx
 * EN v1.0 Address: 0x80038330
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80038428
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointLocalMtx(int param_1,int param_2,float *param_3)
{
  ObjPathPoint *pathPoints;
  ObjPathPoint *pathPoint;
  ObjPathTransform transform;

  pathPoints = (ObjPathPoint *)(*(int *)(*(int *)(param_1 + OBJ_MODEL_INSTANCE_OFFSET) +
                                         OBJPATH_POINTS_OFFSET));
  transform.x = pathPoints[param_2].x;
  pathPoint = &pathPoints[param_2];
  transform.y = pathPoint->y;
  transform.z = pathPoint->z;
  transform.rotX = pathPoint->rotX;
  transform.rotY = pathPoint->rotY;
  transform.rotZ = pathPoint->rotZ;
  transform.scale = OBJLIB_UNIT_SCALE;
  setMatrixFromObjectTransposed(&transform,param_3);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointModelMtx
 * EN v1.0 Address: 0x800383A0
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x80038498
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjPath_GetPointModelMtx(int param_1,int param_2)
{
  int *model;
  ObjPathPoint *pathPoint;
  int jointIndex;

  model = Obj_GetActiveModel(param_1);
  pathPoint = (ObjPathPoint *)(*(int *)(*(int *)(param_1 + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) +
                               param_2 * sizeof(ObjPathPoint));
  jointIndex = pathPoint->modelIndex[(int)*(char *)(param_1 + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
  if ((jointIndex >= 0) && (jointIndex < (int)(uint)*(byte *)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET))) {
    ObjModel_GetJointMatrix(model,jointIndex);
  }
  else {
    ObjModel_GetJointMatrix(model,0);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointWorldPosition
 * EN v1.0 Address: 0x8003842C
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x80038524
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjPath_GetPointWorldPosition(int obj,int pointIndex,float *outX,float *outY,float *outZ,
                 int useInputPosition)
{
  ObjPathPoint *pathPoint;
  int *model;
  float *jointMtx;
  int jointIndex;
  int pointOffset;
  ObjPathTransform transform;
  float rootMtx[12];
  float transposedMtx[12];
  float concatMtx[12];
  float rotMtx[16];

  if ((pointIndex < 0) ||
      ((int)(uint)*(u8 *)(*(int *)(obj + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINT_COUNT_OFFSET) <=
       pointIndex)) {
    *outX = *(float *)(obj + OBJ_POSITION_X_OFFSET);
    *outY = *(float *)(obj + OBJ_POSITION_Y_OFFSET);
    *outZ = *(float *)(obj + OBJ_POSITION_Z_OFFSET);
  }
  else {
    model = Obj_GetActiveModel(obj);
    pointOffset = pointIndex * sizeof(ObjPathPoint);
    pathPoint = (ObjPathPoint *)(*(int *)(*(int *)(obj + OBJ_MODEL_INSTANCE_OFFSET) +
                                          OBJPATH_POINTS_OFFSET) + pointOffset);
    jointIndex = pathPoint->modelIndex[(int)*(char *)(obj + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
    if ((jointIndex < OBJPATH_ROOT_JOINT_INDEX) ||
        ((int)(uint)*(u8 *)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET) <= jointIndex)) {
      *outX = *(float *)(obj + OBJ_POSITION_X_OFFSET);
      *outY = *(float *)(obj + OBJ_POSITION_Y_OFFSET);
      *outZ = *(float *)(obj + OBJ_POSITION_Z_OFFSET);
    }
    else {
      if (jointIndex == OBJPATH_ROOT_JOINT_INDEX) {
        Obj_BuildWorldTransformMatrix((void *)obj,rootMtx,0);
        jointMtx = rootMtx;
      }
      else {
        jointMtx = ObjModel_GetJointMatrix(model,jointIndex);
      }
      if (useInputPosition != 0) {
        transform.x = *outX;
        transform.y = *outY;
        transform.z = *outZ;
        transform.rotX = 0;
        transform.rotY = 0;
        transform.rotZ = 0;
      }
      else {
        transform.x = pathPoint->x;
        transform.y = pathPoint->y;
        transform.z = pathPoint->z;
        transform.rotX = pathPoint->rotX;
        transform.rotY = pathPoint->rotY;
        transform.rotZ = pathPoint->rotZ;
      }
      mtxRotateByVec3s(rotMtx,&transform);
      mtx44Transpose(rotMtx,transposedMtx);
      PSMTXConcat(jointMtx,transposedMtx,concatMtx);
      *outX = concatMtx[3] + playerMapOffsetX;
      *outY = concatMtx[7];
      *outZ = concatMtx[11] + playerMapOffsetZ;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Obj_GetYawDeltaToObject
 * EN v1.0 Address: 0x800385E8
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x800386E0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int Obj_GetYawDeltaToObject(ushort *param_1,int param_2,float *param_3)
{
  int iVar1;
  float dVar3;
  float dVar2;

  dVar3 = *(float *)(param_1 + 6) - *(float *)(param_2 + 0xc);
  dVar2 = *(float *)(param_1 + 10) - *(float *)(param_2 + 0x14);
  iVar1 = getAngle(dVar3, dVar2);
  if (param_3 != (float *)0x0) {
    *param_3 = sqrtf(dVar3 * dVar3 + dVar2 * dVar2);
  }
  iVar1 = (int)(short)iVar1 - (uint)(ushort)*(short *)param_1;
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  return (int)(short)iVar1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_800386BC
 * EN v1.0 Address: 0x800386BC
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x800387B4
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint fn_800386BC(f32 x,f32 y,f32 z)
{
  ObjLibRegionList **lists;
  ObjLibRegionList *list;
  ObjLibRegionEntry *entry;
  int hitId;
  int listIndex;
  int entryOffset;

  hitId = -1;
  lists = fn_8005AFA0();
  for (listIndex = 0; listIndex < 0x50; listIndex++) {
    list = lists[listIndex];
    if (list != 0) {
      entry = list->entries;
      entryOffset = 0;
      while (entryOffset < (int)(uint)list->entryBytes) {
        if (entry->type == 0x130) {
          f32 yawCos =
              fn_80293E80(lbl_803DE980 * (f32)-(s32)((uint)entry->yaw << 8) / lbl_803DE984);
          f32 yawSin = sin(lbl_803DE980 * (f32)-(s32)((uint)entry->yaw << 8) / lbl_803DE984);
          f32 pitchCos =
              fn_80293E80(lbl_803DE980 * (f32)-(s32)((uint)entry->pitch << 8) / lbl_803DE984);
          f32 pitchSin =
              sin(lbl_803DE980 * (f32)-(s32)((uint)entry->pitch << 8) / lbl_803DE984);
          f32 deltaX = x - entry->x;
          f32 deltaY = y - entry->y;
          f32 deltaZ = z - entry->z;
          f32 localX = deltaX * yawSin - deltaZ * yawCos;
          f32 yawZ = deltaX * yawCos + deltaZ * yawSin;
          f32 localY = deltaY * pitchSin - yawZ * pitchCos;
          f32 localZ = deltaY * pitchCos + yawZ * pitchSin;

          if (localX < lbl_803DE970) {
            localX = -localX;
          }
          if (localY < lbl_803DE970) {
            localY = -localY;
          }
          if (localZ < lbl_803DE970) {
            localZ = -localZ;
          }
          if ((localX <= (f32)(uint)entry->halfX) &&
              (localY <= (f32)(uint)entry->halfY) &&
              (localZ <= (f32)(uint)entry->halfZ)) {
            hitId = entry->id;
          }
        }
        entryOffset += (uint)entry->wordCount * 4;
        entry = (ObjLibRegionEntry *)((u8 *)entry + (uint)entry->wordCount * 4);
      }
    }
  }
  return (uint)hitId & 0xffff;
}

/*
 * --INFO--
 *
 * Function: fn_80038988
 * EN v1.0 Address: 0x80038988
 * EN v1.0 Size: 1428b
 * EN v1.1 Address: 0x80038A80
 * EN v1.1 Size: 1428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80038988(int obj,int blinkState,uint flags)
{
  u8 step;
  f32 leftScale;
  f32 rightScale;
  f32 phase;
  f32 wave;
  int joint;
  int model;
  int jointData;
  int jointDataOffset;
  int poseOffset;
  uint jointCount;
  s16 rotation;
  u8 state;

  step = (u8)(s32)(lbl_803DE998 * timeDelta);
  leftScale = lbl_803DE99C;
  rightScale = leftScale;
  state = *(u8 *)(blinkState + 0x2b);
  if (state == 3) {
    *(u8 *)(blinkState + 0x2c) = (u8)((f32)*(u8 *)(blinkState + 0x2c) + timeDelta);
    if ((s16)*(u8 *)(blinkState + 0x2d) - (s16)step < 0) {
      *(u8 *)(blinkState + 0x2b) = 0;
      step = *(u8 *)(blinkState + 0x2d);
    }
    *(u8 *)(blinkState + 0x2d) -= step;
  }
  else if (state < 3) {
    if (state == 1) {
      *(u8 *)(blinkState + 0x2c) = (u8)((f32)*(u8 *)(blinkState + 0x2c) + timeDelta);
      if (0xff < (uint)((s16)*(u8 *)(blinkState + 0x2d) + (s16)step)) {
        step = 0xff - *(u8 *)(blinkState + 0x2d);
        *(u8 *)(blinkState + 0x2b) = 2;
      }
      *(u8 *)(blinkState + 0x2d) += step;
    }
    else if (state == 0) {
      *(u8 *)(blinkState + 0x2c) = (u8)((f32)*(u8 *)(blinkState + 0x2c) + timeDelta);
      *(u8 *)(blinkState + 0x2d) = 0;
      if ((flags & 1) != 0) {
        if (randomGetRange(0,100) == 1) {
          state = *(u8 *)(blinkState + 0x2b);
          if (state == 3) {
            *(u8 *)(blinkState + 0x2b) = 1;
          }
          else if ((state < 3) && (state == 0)) {
            *(u8 *)(blinkState + 0x2b) = 1;
            *(u8 *)(blinkState + 0x2c) = 0;
            *(u8 *)(blinkState + 0x2d) = 0;
          }
        }
        else if (randomGetRange(0,0x4b) == 1) {
          if (randomGetRange(0,1) == 0) {
            *(u8 *)(blinkState + 0x2b) = 4;
          }
          else {
            *(u8 *)(blinkState + 0x2b) = 5;
          }
        }
      }
    }
    else {
      *(u8 *)(blinkState + 0x2c) = (u8)((f32)*(u8 *)(blinkState + 0x2c) + timeDelta);
      if (randomGetRange(0,100) == 1) {
        state = *(u8 *)(blinkState + 0x2b);
        if (state != 3) {
          if (state < 3) {
            if (state != 0) {
              *(u8 *)(blinkState + 0x2b) = 3;
            }
          }
          else if (state < 6) {
            *(u8 *)(blinkState + 0x2b) = 0;
          }
        }
      }
    }
  }
  else if (state == 5) {
    *(u8 *)(blinkState + 0x2c) =
        (u8)(lbl_803DE9A0 * timeDelta + (f32)*(u8 *)(blinkState + 0x2c));
    *(u8 *)(blinkState + 0x2d) = 0xff;
    leftScale = lbl_803DE9A4;
    if (randomGetRange(0,0x19) == 1) {
      state = *(u8 *)(blinkState + 0x2b);
      if (state != 3) {
        if (state < 3) {
          if (state != 0) {
            *(u8 *)(blinkState + 0x2b) = 3;
          }
        }
        else if (state < 6) {
          *(u8 *)(blinkState + 0x2b) = 0;
        }
      }
    }
  }
  else if (state < 5) {
    *(u8 *)(blinkState + 0x2c) =
        (u8)(lbl_803DE9A0 * timeDelta + (f32)*(u8 *)(blinkState + 0x2c));
    *(u8 *)(blinkState + 0x2d) = 0xff;
    rightScale = lbl_803DE9A4;
    if (randomGetRange(0,0x19) == 1) {
      state = *(u8 *)(blinkState + 0x2b);
      if (state != 3) {
        if (state < 3) {
          if (state != 0) {
            *(u8 *)(blinkState + 0x2b) = 3;
          }
        }
        else if (state < 6) {
          *(u8 *)(blinkState + 0x2b) = 0;
        }
      }
    }
  }

  phase = lbl_803DE9AC * (f32)*(u8 *)(blinkState + 0x2c);
  wave = (lbl_803DE9A8 * fn_802943F4(phase) * (f32)*(u8 *)(blinkState + 0x2d)) / lbl_803DE9B0;
  rotation = (s16)(s32)((lbl_803DE9B4 * (leftScale * wave)) / lbl_803DE9B8);
  joint = 0;
  model = *(int *)(obj + 0x50);
  if (model != 0) {
    jointDataOffset = 0;
    poseOffset = 0;
    jointCount = (uint)*(u8 *)(model + 0x5a);
    while (jointCount != 0) {
      jointData = *(int *)(model + 0x10);
      if ((*(s8 *)(jointData + *(s8 *)(obj + 0xad) + jointDataOffset + 1) != -1) &&
          (*(s8 *)(jointData + jointDataOffset) == 5)) {
        joint = *(int *)(obj + 0x6c) + poseOffset;
      }
      jointDataOffset += *(s8 *)(model + 0x55) + 1;
      poseOffset += 0x12;
      jointCount--;
    }
  }
  *(s16 *)(joint + 2) = rotation;

  rotation = (s16)(s32)((lbl_803DE9B4 * (rightScale * wave)) / lbl_803DE9B8);
  joint = 0;
  model = *(int *)(obj + 0x50);
  if (model != 0) {
    jointDataOffset = 0;
    poseOffset = 0;
    jointCount = (uint)*(u8 *)(model + 0x5a);
    while (jointCount != 0) {
      jointData = *(int *)(model + 0x10);
      if ((*(s8 *)(jointData + *(s8 *)(obj + 0xad) + jointDataOffset + 1) != -1) &&
          (*(s8 *)(jointData + jointDataOffset) == 4)) {
        joint = *(int *)(obj + 0x6c) + poseOffset;
      }
      jointDataOffset += *(s8 *)(model + 0x55) + 1;
      poseOffset += 0x12;
      jointCount--;
    }
  }
  *(s16 *)(joint + 2) = -rotation;
}

/*
 * --INFO--
 *
 * Function: FUN_80038bb0
 * EN v1.0 Address: 0x80038BB0
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80039014
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80038bb0(char param_1,int param_2)
{
  if (param_1 != '\0') {
    return;
  }
  DAT_803dd880 = (byte)(param_2 << 7) | DAT_803dd880 & 0x7f;
  return;
}

typedef struct ObjLibFlagByte {
    u8 highBit : 1;
    u8 rest : 7;
} ObjLibFlagByte;

extern ObjLibFlagByte lbl_803DCC00;
#pragma scheduling off
#pragma peephole off
void fn_80038F1C(int a, int b) {
    if ((int)(u8)a != 0) return;
    lbl_803DCC00.highBit = b;
}
#pragma peephole reset
#pragma scheduling reset
