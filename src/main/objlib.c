#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objlib.h"

extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern float sqrtf(float x);
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern ObjHitReactEffectHandle *Resource_Acquire(int resourceId,int mode);
extern int Sfx_PlayFromObject(int obj,int sfxId);
extern uint fn_80014B24(int index);
extern void buttonDisable(int index,uint flags);
extern undefined4 FUN_80017640();
extern undefined4 FUN_80017700();
extern undefined4 FUN_80017704();
extern void setMatrixFromObjectTransposed(void *transform,float *mtx);
extern float fn_800216D0(float *posA,float *posB);
extern float Vec_distance(float *param_1,float *param_2);
extern void OSReport(const char *fmt, ...);
extern int FUN_80017730();
extern undefined4 FUN_8001774c();
extern uint FUN_80017760();
extern uint fn_80022E24();
extern uint fn_80022E3C(uint param_1);
extern uint FUN_800177dc();
extern undefined4 FUN_80017830();
extern void *mmAlloc(int size,int heap,int flags);
extern float *ObjModel_GetJointMatrix(int *model,int jointIndex);
extern undefined4 FUN_80017a50();
extern int *Obj_GetActiveModel(int obj);
extern void *Obj_GetPlayerObject(void);
extern void Obj_UpdateObject(ObjAnimComponent *obj,void *modelInstance);
extern int ObjList_GetObjects();
extern void ObjHitbox_UpdateRotatedBounds(ushort *param_1,int param_2);
extern undefined4 FUN_80045328();
extern void getTabEntry(void *dst,int fileId,int offset,int size);
extern void fn_80048F48(int fileId,void *dst,int offset,int size);
extern undefined4 FUN_80053ab4();
extern int * fn_8005B11C();
extern void debugPrintf(const char *fmt, ...);
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
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949e8();
extern byte FUN_80294c20();
extern int fn_80296BA0(void *obj);

extern int gObjGroupObjects[0x100];
extern u8 gObjGroupOffsets[0x58];
extern int DAT_803439b0;
extern undefined4 DAT_803439b4;
extern undefined4 DAT_803439b8;
typedef struct ObjTriggerInterface {
  u8 pad00[0x1c];
  int (*isCurrentTriggerClear)(void);
  int (*isTriggerSet)(int eventId);
} ObjTriggerInterface;

extern ObjTriggerInterface **lbl_803DCA68;
extern void *lbl_803DCBC8[2];
extern void *lbl_803DCBD0[2];
extern void *lbl_803DCBD8;
extern undefined4 lbl_803DCBDC;
extern int gObjHitReactResetObjectCount;
extern int *gObjHitReactResetObjects;
extern u8 gObjGroupObjectCount;
extern undefined4 DAT_803dd878;
extern undefined4 DAT_803dd880;
extern f64 DOUBLE_803df5c0;
extern f64 DOUBLE_803df640;
extern f32 lbl_803DC074;
extern f32 lbl_803DCBE8;
extern f32 lbl_803DE914;
extern f32 lbl_803DE968;
extern f32 lbl_803DE97C;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DF5E8;
extern f32 lbl_803DF5F0;
extern f32 lbl_803DE970;
extern f32 lbl_803DE978;
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

typedef struct ObjHitsPriorityState {
  u8 pad00[0x50];
  int lastHitObject;
  u8 pad54[0xc];
  u16 flags;
  u8 pad62[0xf];
  s8 priorityHitCount;
  s8 sphereIndices[3];
  s8 priorities[3];
  u8 hitVolumes[3];
  u8 pad7b;
  int hitObjects[3];
  f32 hitPosX[3];
  f32 hitPosY[3];
  f32 hitPosZ[3];
} ObjHitsPriorityState;

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

  uVar1 = fn_80022E24(param_2);
  *(uint *)(param_1 + 0x2c) = uVar1;
  if (*(uint *)(param_1 + 0x2c) != 0) {
    *(undefined *)(*(uint *)(param_1 + 0x2c) + 0x10c) = 0;
    *(undefined *)(*(uint *)(param_1 + 0x2c) + 0x10d) = 10;
    *(undefined *)(*(uint *)(param_1 + 0x2c) + 0x10f) = 0;
    ObjHitbox_UpdateRotatedBounds(param_1,1);
    ObjHitbox_UpdateRotatedBounds(param_1,1);
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
  s16 *moveEntry;
  int iVar3;
  s16 *moveEntryTable;
  s16 firstEntryIndex;

  moveEntryTable = (s16 *)((ObjAnimDef *)((ObjAnimComponent *)objAnim)->modelInstance)->hitReactMoveTable;
  hitState->activeEntryCount = 0;
  if (moveEntryTable != (s16 *)0x0) {
    iVar3 = 0;
    for (moveEntry = moveEntryTable; *moveEntry != -1; moveEntry = moveEntry + 3, iVar3 = iVar3 + 3) {
      if (moveId == *moveEntry) {
        firstEntryIndex = moveEntryTable[iVar3 + 1];
        hitState->activeEntryCount = moveEntryTable[iVar3 + 2];
        if (hitState->activeEntryCount > hitState->entryCapacity) {
          hitState->activeEntryCount = hitState->entryCapacity;
        }
        if (async == 0) {
          getTabEntry(hitState->entries,0x41,(int)firstEntryIndex,(int)hitState->activeEntryCount);
          return;
        }
        fn_80048F48(0x41,hitState->entries,(int)firstEntryIndex,(int)hitState->activeEntryCount);
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
  hitState->entryCapacity = 300;
  entries = (ObjHitReactEntry *)fn_80022E3C(entryArena);
  hitState->entries = entries;
  entryArena = (uint)entries + hitState->entryCapacity;
  hitState->activeHitboxMode = 1;
  if ((hitState->resetFlags & 0x30) != 0) {
    hitState->resetHitboxMode = 2;
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
  for (; (s16)slotIndex < 0x32; slotIndex = slotIndex + 1) {
    piVar2 = (int *)(lbl_803DCBDC + slotOffset);
    if ((*piVar2 != 0) && ((u32)piVar2[2] == (u32)param_1)) {
      *piVar2 = clearedState;
    }
    slotOffset = slotOffset + 0x3c;
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

  uVar1 = fn_80022E24(param_2);
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
undefined4 ObjHits_RecordObjectHit(int obj,int hitObj,char priority,undefined hitVolume,undefined sphereIndex)
{
  int hitObjectSlot;
  ObjHitsPriorityState *hitState;
  int hitSlot;
  
  if (priority == '\0') {
    return 0;
  }
  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if ((hitState->flags & 1) == 0) {
    return 0;
  }
  if ((hitObj != 0) && (*(int *)(hitObj + 0x54) != 0)) {
    (*(ObjHitsPriorityState **)(hitObj + 0x54))->lastHitObject = obj;
  }
  hitSlot = 0;
  while( true ) {
    hitObjectSlot = (int)hitState->priorityHitCount;
    if (hitObjectSlot <= hitSlot) break;
    hitObjectSlot = hitSlot * 4;
    if (*(int *)((int)hitState->hitObjects + hitObjectSlot) == hitObj) {
      hitSlot = (int)hitState + hitSlot;
      if (priority < *(char *)(hitSlot + 0x75)) {
        *(undefined *)(hitSlot + 0x72) = sphereIndex;
        *(char *)(hitSlot + 0x75) = priority;
        *(undefined *)(hitSlot + 0x78) = hitVolume;
        *(undefined4 *)((int)hitState->hitPosX + hitObjectSlot) = *(undefined4 *)(obj + 0xc);
        *(undefined4 *)((int)hitState->hitPosY + hitObjectSlot) = *(undefined4 *)(obj + 0x10);
        *(undefined4 *)((int)hitState->hitPosZ + hitObjectSlot) = *(undefined4 *)(obj + 0x14);
      }
      hitSlot = hitState->priorityHitCount + 1;
    }
    hitSlot = hitSlot + 1;
  }
  if ((hitSlot == hitObjectSlot) && (hitObjectSlot < 3)) {
    *(undefined *)((int)hitState->sphereIndices + hitObjectSlot) = sphereIndex;
    *(char *)((int)hitState->priorities + hitState->priorityHitCount) = priority;
    *(undefined *)((int)hitState->hitVolumes + hitState->priorityHitCount) = hitVolume;
    *(int *)((int)hitState->hitObjects + hitState->priorityHitCount * 4) = hitObj;
    *(undefined4 *)((int)hitState->hitPosX + hitState->priorityHitCount * 4) = *(undefined4 *)(obj + 0xc);
    *(undefined4 *)((int)hitState->hitPosY + hitState->priorityHitCount * 4) = *(undefined4 *)(obj + 0x10);
    *(undefined4 *)((int)hitState->hitPosZ + hitState->priorityHitCount * 4) = *(undefined4 *)(obj + 0x14);
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
undefined4
ObjHits_RecordPositionHit(double hitPosX,double hitPosY,double hitPosZ,int obj,int hitObj,char priority,
            undefined hitVolume,undefined sphereIndex)
{
  int hitObjectSlot;
  int hitSlot;
  ObjHitsPriorityState *hitState;
  
  if (priority == '\0') {
    return 0;
  }
  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if ((hitState->flags & 1) == 0) {
    return 0;
  }
  if ((hitObj != 0) && (*(int *)(hitObj + 0x54) != 0)) {
    (*(ObjHitsPriorityState **)(hitObj + 0x54))->lastHitObject = obj;
  }
  hitSlot = 0;
  while( true ) {
    hitObjectSlot = (int)hitState->priorityHitCount;
    if (hitObjectSlot <= hitSlot) break;
    hitObjectSlot = hitSlot * 4;
    if (*(int *)((int)hitState->hitObjects + hitObjectSlot) == hitObj) {
      hitSlot = (int)hitState + hitSlot;
      if (priority < *(char *)(hitSlot + 0x75)) {
        *(undefined *)(hitSlot + 0x72) = sphereIndex;
        *(char *)(hitSlot + 0x75) = priority;
        *(undefined *)(hitSlot + 0x78) = hitVolume;
        *(float *)((int)hitState->hitPosX + hitObjectSlot) = (float)hitPosX;
        *(float *)((int)hitState->hitPosY + hitObjectSlot) = (float)hitPosY;
        *(float *)((int)hitState->hitPosZ + hitObjectSlot) = (float)hitPosZ;
      }
      hitSlot = hitState->priorityHitCount + 1;
    }
    hitSlot = hitSlot + 1;
  }
  if ((hitSlot == hitObjectSlot) && (hitObjectSlot < 3)) {
    *(undefined *)((int)hitState->sphereIndices + hitObjectSlot) = sphereIndex;
    *(char *)((int)hitState->priorities + hitState->priorityHitCount) = priority;
    *(undefined *)((int)hitState->hitVolumes + hitState->priorityHitCount) = hitVolume;
    *(int *)((int)hitState->hitObjects + hitState->priorityHitCount * 4) = hitObj;
    *(float *)((int)hitState->hitPosX + hitState->priorityHitCount * 4) = (float)hitPosX;
    *(float *)((int)hitState->hitPosY + hitState->priorityHitCount * 4) = (float)hitPosY;
    *(float *)((int)hitState->hitPosZ + hitState->priorityHitCount * 4) = (float)hitPosZ;
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
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;

  iVar4 = *(int *)(param_1 + 0x58);
  if (iVar4 == 0) {
    return;
  }
  iVar2 = (int)*(char *)(iVar4 + 0x10f);
  if (2 < iVar2) {
    return;
  }
  iVar3 = 0;
  if (0 < iVar2) {
    do {
      if (*(int *)(iVar4 + iVar3 + 0x100) == param_2) {
        return;
      }
      iVar3 = iVar3 + 4;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  iVar2 = *(int *)(param_1 + 0x58);
  cVar1 = *(char *)(iVar4 + 0x10f);
  *(char *)(iVar4 + 0x10f) = cVar1 + '\x01';
  *(int *)(iVar2 + cVar1 * 4 + 0x100) = param_2;
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
#pragma scheduling off
#pragma peephole off
int ObjHits_GetPriorityHitWithPosition(int obj,undefined4 *outHitObject,int *outSphereIndex,
                uint *outHitVolume,float *outHitPosX,float *outHitPosY,float *outHitPosZ)
{
  char hitPriority;
  int hitCount;
  ObjHitsPriorityState *hitState;
  int hitSlot;
  char bestPriority;
  char bestHitSlot;

  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if (hitState != 0) {
    hitCount = (int)hitState->priorityHitCount;
    if (hitCount != 0) {
      bestPriority = '\x7f';
      bestHitSlot = -1;
      for (hitSlot = 0; hitSlot < hitCount; hitSlot++) {
        hitPriority = hitState->priorities[hitSlot];
        if (hitPriority < bestPriority) {
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
        return (int)bestPriority;
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
#pragma scheduling off
#pragma peephole off
int ObjHits_GetPriorityHit(int obj,undefined4 *outHitObject,int *outSphereIndex,uint *outHitVolume)
{
  char hitPriority;
  int hitCount;
  ObjHitsPriorityState *hitState;
  int hitSlot;
  char bestPriority;
  char bestHitSlot;

  hitState = *(ObjHitsPriorityState **)(obj + 0x54);
  if (hitState == 0) {
    return 0;
  }
  hitCount = (int)hitState->priorityHitCount;
  if (hitCount != 0) {
    bestPriority = '\x7f';
    bestHitSlot = -1;
    for (hitSlot = 0; hitSlot < hitCount; hitSlot++) {
      hitPriority = hitState->priorities[hitSlot];
      if (hitPriority < bestPriority) {
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
      return (int)bestPriority;
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

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
  int iVar2;
  int iVar3;

  iVar3 = 0;
  for (iVar2 = 0; iVar2 < gObjHitsResetObjectCount; iVar2 = iVar2 + 1) {
    obj = *(ObjAnimComponent **)((int)gObjHitsResetObjects + iVar3);
    if (((*(uint *)((int)obj->modelInstance + 0x44) & 0x40) == 0) &&
       (obj->activeHitboxMode != 'd')) {
      Obj_UpdateObject(obj,obj->modelInstance);
    }
    iVar3 = iVar3 + 4;
  }
  iVar3 = 0;
  for (iVar2 = 0; iVar2 < gObjHitsResetObjectCount; iVar2 = iVar2 + 1) {
    ObjHitbox_UpdateRotatedBounds(*(ushort **)((int)gObjHitsResetObjects + iVar3),1);
    iVar3 = iVar3 + 4;
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
  int i;

  for (i = 0; i < OBJHITREACT_MAX_RESET_OBJECTS; i++) {
    *(undefined4 *)(lbl_803DCBDC + i * 0x3c) = 0;
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
int *ObjHitReact_GetResetObjects(undefined4 *param_1)
{
  *param_1 = gObjHitsResetObjectCount;
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
  int i;

  gObjHitsResetObjects = (int *)mmAlloc(OBJHITREACT_MAX_RESET_OBJECTS * sizeof(int),0xe,0);
  lbl_803DCBDC = (undefined4)mmAlloc(3000,0xe,0);
  lbl_803DCBD8 = mmAlloc(0x1900,0xe,0);
  lbl_803DCBD0[0] = mmAlloc(0x400,0xe,0);
  lbl_803DCBD0[1] = mmAlloc(0x400,0xe,0);
  lbl_803DCBC8[0] = mmAlloc(0x400,0xe,0);
  lbl_803DCBC8[1] = mmAlloc(0x400,0xe,0);
  lbl_803DCBE8 = lbl_803DE914;
  for (i = 0; i < 5; i++) {
    gObjHitsActiveHitVolumeObjects[i] = 0;
  }
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

  if ((group < 0) || (group >= 0x54)) {
    return 0;
  }
  index = (uint)gObjGroupOffsets[group];
  limit = (uint)gObjGroupOffsets[group + 1];
  for (entry = (uint *)gObjGroupObjects + index; ((int)index < (int)limit && (obj != *entry));
      entry = entry + 1, index = index + 1) {
  }
  return ((int)(limit ^ index) >> 1) - ((limit ^ index) & limit) >> 0x1f;
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
  if ((group < 0) || (group >= 0x54)) {
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
  if ((group < 0) || (group >= 0x54)) {
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
      distanceSq = fn_800216D0((float *)(obj + 0x18),(float *)(*entry + 0x18));
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
  if ((group < 0) || (group >= 0x54)) {
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
      distanceSq = fn_800216D0((float *)(obj + 0x18),(float *)(*entry + 0x18));
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
  if ((group < 0) || (group >= 0x54)) {
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
void ObjGroup_RemoveObject(int obj,int group)
{
  byte *bucketStarts;
  u8 *bucketEnds;
  int count;
  int index;
  int limit;
  int *entries;

  if ((group < 0) || (group >= 0x54)) {
    return;
  }
  bucketStarts = gObjGroupOffsets;
  bucketEnds = gObjGroupOffsets + 1;
  entries = gObjGroupObjects;
  index = (int)bucketStarts[group];
  limit = (int)bucketEnds[group];
  while ((index < limit) && (entries[index] != obj)) {
    index++;
  }
  if (limit <= index) {
    return;
  }
  count = (int)gObjGroupObjectCount - 1;
  gObjGroupObjectCount = count;
  while (index < count) {
    entries[index] = entries[index + 1];
    index++;
  }
  while (group < 0x54) {
    bucketEnds[group] = bucketEnds[group] - 1;
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
int ObjGroup_GetObjectGroup(int obj)
{
  uint remaining;
  int group;
  int *entry;
  byte *offset;
  int objectIndex;
  
  objectIndex = 0;
  entry = gObjGroupObjects;
  remaining = (uint)gObjGroupObjectCount;
  while( true ) {
    if (remaining == 0) {
      return 0;
    }
    if (*entry == obj) break;
    entry = entry + 1;
    objectIndex = objectIndex + 1;
    remaining = remaining - 1;
  }
  group = 0;
  offset = gObjGroupOffsets;
  while( true ) {
    if (objectIndex < (int)(uint)*offset) {
      return group;
    }
    if (group >= 0x55) break;
    offset = offset + 1;
    group = group + 1;
  }
  return group;
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
void ObjGroup_AddObject(int obj,int group)
{
  byte *bucketStarts;
  u8 *bucketEnds;
  int count;
  int index;
  int insertIndex;
  int limit;
  int *entries;

  if ((group < 0) || (group >= 0x54)) {
    return;
  }
  if ((int)(uint)gObjGroupObjectCount >= 0x100) {
    OSReport(sObjAddObjectTypeReachedMaxTypes);
    return;
  }
  bucketStarts = gObjGroupOffsets;
  entries = gObjGroupObjects;
  bucketEnds = gObjGroupOffsets + 1;
  insertIndex = (int)bucketStarts[group];
  limit = (int)bucketEnds[group];
  for (index = insertIndex; index < limit; index++) {
    if (entries[index] == obj) {
      return;
    }
  }
  if (limit != insertIndex) {
    insertIndex = limit - 1;
  }
  count = (int)gObjGroupObjectCount;
  gObjGroupObjectCount = count + 1;
  for (index = count; insertIndex < index; index--) {
    entries[index] = entries[index - 1];
  }
  entries[insertIndex] = obj;
  while (group < 0x54) {
    bucketEnds[group] = bucketEnds[group] + 1;
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
  memset(gObjGroupOffsets, 0, 0x55);
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
  queue = *(ObjMsgQueue **)((byte *)obj + 0xdc);
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
  uint i;
  ObjMsgQueue *queue;

  if (obj == (void *)0x0) {
    return 0;
  }
  queue = *(ObjMsgQueue **)((byte *)obj + 0xdc);
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
      queue->entries[i].message = queue->entries[i + 1].message;
      queue->entries[i].sender = queue->entries[i + 1].sender;
      queue->entries[i].param = queue->entries[i + 1].param;
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
    if (((obj != sender) || ((maskedFlags & 1) == 0)) &&
        ((*(short *)((byte *)obj + 0x46) == (short)targetId || ((maskedFlags & 2) != 0))) &&
        ((Vec_distance((float *)((byte *)sender + 0x18),(float *)((byte *)obj + 0x18)) < radius &&
          (obj != (void *)0x0)) &&
         (queue = *(ObjMsgQueue **)((byte *)obj + 0xdc), queue != (ObjMsgQueue *)0x0))) {
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
  if ((maskedFlags & 4) != 0) {
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
      obj = (void *)objects[objectIndex];
      if (((obj != sender) || ((maskedFlags & 1) == 0)) &&
          (((maskedFlags & 2) != 0 || (targetId == *(short *)((byte *)obj + 0x46)))) &&
          ((obj != (void *)0x0 &&
            (queue = *(ObjMsgQueue **)((byte *)obj + 0xdc), queue != (ObjMsgQueue *)0x0)))) {
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
      if (((obj != sender) || ((maskedFlags & 1) == 0)) &&
          (((maskedFlags & 2) != 0 || (targetId == *(short *)((byte *)obj + 0x44)))) &&
          ((obj != (void *)0x0 &&
            (queue = *(ObjMsgQueue **)((byte *)obj + 0xdc), queue != (ObjMsgQueue *)0x0)))) {
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
  queue = *(ObjMsgQueue **)((byte *)dstObj + 0xdc);
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
      (*(ObjMsgQueue **)((byte *)obj + 0xdc) == (ObjMsgQueue *)0x0)) {
    queueBytes = (capacity * 3 + 2) * 4;
    queue = (ObjMsgQueue *)FUN_80017830(queueBytes,0xe,0);
    queue->count = 0;
    queue->capacity = capacity;
    *(ObjMsgQueue **)((byte *)obj + 0xdc) = queue;
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
  if ((param_1 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x40) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80037d74
 * EN v1.0 Address: 0x80037D74
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80037AFC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80037d74(int param_1)
{
  int iVar1;
  byte bVar2;
  
  iVar1 = (int)Obj_GetPlayerObject();
  bVar2 = FUN_80294c20(iVar1);
  if (bVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  return bVar2 == 0;
}

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
int ObjHits_PollPriorityHitWithCooldown(int obj,float *cooldown,undefined4 *outHitObject,float *outHitPos)
{
  int collisionType;
  
  collisionType = 0;
  *cooldown = *cooldown - lbl_803DC074;
  if (*cooldown <= lbl_803DF5F0) {
    if (outHitPos == (float *)0x0) {
      collisionType = ObjHits_GetPriorityHit(obj,outHitObject,(int *)0x0,(uint *)0x0);
    }
    else {
      collisionType = ObjHits_GetPriorityHitWithPosition(obj,outHitObject,(int *)0x0,(uint *)0x0,outHitPos,
                           outHitPos + 1,outHitPos + 2);
      if (collisionType != 0) {
        FUN_80053ab4(obj,outHitPos);
      }
    }
    if (collisionType != 0) {
      *cooldown = lbl_803DF5F4;
    }
  }
  return collisionType;
}

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
  u32 effectArgs[4];
  u32 hitObject;

  *cooldown = *cooldown - timeDelta;
  collisionType = ObjHits_GetPriorityHitWithPosition(obj,(undefined4 *)&hitObject,(int *)0x0,
                                                     (uint *)0x0,&hitPos[0],&hitPos[1],&hitPos[2]);
  if ((*cooldown <= lbl_803DE970) && (collisionType != 0)) {
    *cooldown = lbl_803DE978;
    if ((collisionType != 0x1a) && (collisionType != 5)) {
      hitPos[0] = hitPos[0] + playerMapOffsetX;
      hitPos[2] = hitPos[2] + playerMapOffsetZ;
      effectPos.scale = lbl_803DE97C;
      effectPos.z = 0;
      effectPos.y = 0;
      effectPos.x = 0;
      effectHandle = Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID,1);
      effectArgs[0] = hitFxMode & 0xff;
      effectArgs[1] = colorR & 0xff;
      effectArgs[2] = colorG & 0xff;
      effectArgs[3] = colorB & 0xff;
      effectHandle->vtable->spawn(0,1,&effectPos,OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,0xffffffff,
                                  effectArgs);
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
  uVar1 = (uint)*(byte *)(param_1 + 0xeb);
  for (iVar3 = param_1; (uVar1 != 0 && (*(int *)(iVar3 + 200) != param_2)); iVar3 = iVar3 + 4) {
    iVar4 = iVar4 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar3 = param_1 + iVar4 * 4;
  for (; iVar2 = *(byte *)(param_1 + 0xeb) - 1, iVar4 < iVar2; iVar4 = iVar4 + 1) {
    *(undefined4 *)(iVar3 + 200) = *(undefined4 *)(iVar3 + 0xcc);
    iVar3 = iVar3 + 4;
  }
  *(char *)(param_1 + 0xeb) = (char)iVar2;
  *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0xeb) * 4 + 200) = 0;
  *(undefined4 *)(param_2 + 0xc4) = 0;
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

  bVar1 = *(u8 *)(param_1 + 0xeb);
  *(u8 *)(param_1 + 0xeb) = bVar1 + 1;
  base = (u8*)(param_1 + bVar1 * 4);
  *(int *)(base + 200) = param_2;
  *(int *)(param_2 + 0xc4) = param_1;
  *(u16 *)(param_2 + 0xb0) = (u16)(*(u16 *)(param_2 + 0xb0) & 0xfff8);
  *(u16 *)(param_2 + 0xb0) = (u16)(*(u16 *)(param_2 + 0xb0) | param_3);
  *(u8 *)(param_2 + 0xe5) = 0;
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
void ObjContact_DispatchCallbacks(void)
{
  bool bVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  undefined8 uVar8;

  uVar8 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  uVar7 = (uint)*(byte *)(iVar3 + 0xe9);
  uVar6 = (uint)*(byte *)(iVar4 + 0xe9);
  piVar2 = &DAT_803439b0;
  iVar5 = DAT_803dd878;
  while (((uVar7 != 0 && (uVar6 != 0)) && (bVar1 = iVar5 != 0, iVar5 = iVar5 + -1, bVar1))) {
    if ((*piVar2 == iVar3) && (piVar2[1] == iVar4)) {
      uVar7 = uVar7 - 1;
      (*(code *)piVar2[2])(iVar3,iVar4);
    }
    if ((*piVar2 == iVar4) && (piVar2[1] == iVar3)) {
      uVar6 = uVar6 - 1;
      (*(code *)piVar2[2])(iVar4,iVar3);
    }
    piVar2 = piVar2 + 3;
  }
  FUN_80286888();
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
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;

  piVar1 = &DAT_803439b0;
  iVar3 = DAT_803dd878;
  while (iVar4 = iVar3 + -1, 0 < iVar3) {
    if ((*piVar1 == param_1) || (piVar1[1] == param_1)) {
      DAT_803dd878 = DAT_803dd878 + -1;
      iVar4 = iVar3 + -2;
      *(char *)(*piVar1 + 0xe9) = *(char *)(*piVar1 + 0xe9) + -1;
      *(char *)(piVar1[1] + 0xe9) = *(char *)(piVar1[1] + 0xe9) + -1;
      iVar3 = DAT_803dd878;
      if ((DAT_803dd878 != 0xf) && (DAT_803dd878 != 0)) {
        iVar2 = (&DAT_803439b4)[DAT_803dd878 * 3];
        *piVar1 = (&DAT_803439b0)[DAT_803dd878 * 3];
        piVar1[1] = iVar2;
        piVar1[2] = (&DAT_803439b8)[iVar3 * 3];
      }
    }
    piVar1 = piVar1 + 3;
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
undefined4 ObjContact_AddCallback(int param_1,int param_2,undefined4 param_3)
{
  int iVar1;
  int *piVar2;
  int iVar3;

  iVar1 = DAT_803dd878;
  if ((param_1 == 0) || (param_2 == 0)) {
    return 0;
  }
  piVar2 = &DAT_803439b0;
  iVar3 = DAT_803dd878;
  if (DAT_803dd878 != 0) {
    do {
      if ((*piVar2 == param_1) && (piVar2[1] == param_2)) {
        return 0;
      }
      piVar2 = piVar2 + 3;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (0xf < DAT_803dd878) {
    return 0;
  }
  (&DAT_803439b0)[DAT_803dd878 * 3] = param_1;
  (&DAT_803439b4)[iVar1 * 3] = param_2;
  (&DAT_803439b8)[iVar1 * 3] = param_3;
  *(char *)(param_1 + 0xe9) = *(char *)(param_1 + 0xe9) + '\x01';
  *(char *)(param_2 + 0xe9) = *(char *)(param_2 + 0xe9) + '\x01';
  DAT_803dd878 = DAT_803dd878 + 1;
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

  triggerFlags = *(byte *)(param_1 + 0xaf);
  flagEnabled = triggerFlags & 4;
  if (flagEnabled != 0) {
    flagBlocked = triggerFlags & 0x10;
    if ((flagBlocked == 0) && (iVar1 = (*lbl_803DCA68)->isTriggerSet((int)param_2), iVar1 != 0)) {
      iVar1 = fn_80296BA0(Obj_GetPlayerObject());
      if (iVar1 == -1) {
        buttonDisable(0,0x100);
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
  flags = fn_80014B24(0);
  if ((flags & 0x100) == 0) {
    triggerFlags = *(byte *)(param_1 + 0xaf);
    flagEnabled = triggerFlags & 1;
    if (flagEnabled != 0) {
      flagBlocked = triggerFlags & 8;
      if ((flagBlocked == 0) && (iVar1 = (*lbl_803DCA68)->isCurrentTriggerClear(), iVar1 == 0)) {
        iVar1 = fn_80296BA0(Obj_GetPlayerObject());
        if ((iVar1 == -1) || (iVar1 == 0x40)) {
          buttonDisable(0,0x100);
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
          (distanceSq = fn_800216D0((float *)(obj + 0x18),(float *)(otherObj + 0x18)),
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
      distanceSq = fn_800216D0((float *)(obj + 0x18),(float *)(*objects + 0x18));
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
    ObjPath_GetPointWorldPosition(obj,pointIndex + i,positions,(undefined4 *)(positions + 1),
                                  positions + 2,0);
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
  *param_3 = ((ObjPathPoint *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) +
                               param_2 * sizeof(ObjPathPoint)))->x;
  *param_4 = ((ObjPathPoint *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) +
                               param_2 * sizeof(ObjPathPoint)))->y;
  *param_5 = ((ObjPathPoint *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) +
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
  ObjPathPoint *pathPoint;
  ObjPathTransform transform;

  pathPoint = (ObjPathPoint *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + param_2 * sizeof(ObjPathPoint));
  transform.x = pathPoint->x;
  transform.y = pathPoint->y;
  transform.z = pathPoint->z;
  transform.rotX = pathPoint->rotX;
  transform.rotY = pathPoint->rotY;
  transform.rotZ = pathPoint->rotZ;
  transform.scale = lbl_803DE97C;
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
  pathPoint = (ObjPathPoint *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) +
                               param_2 * sizeof(ObjPathPoint));
  jointIndex = pathPoint->modelIndex[(int)*(char *)(param_1 + 0xad)];
  if ((jointIndex >= 0) && (jointIndex < (int)(uint)*(byte *)(*model + 0xf3))) {
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
void ObjPath_GetPointWorldPosition(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 *param_4,
                 float *param_5,int param_6)
{
  ushort *puVar1;
  int *piVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  undefined2 local_118;
  undefined2 local_116;
  undefined2 local_114;
  float local_10c;
  undefined4 local_108;
  float local_104;
  float afStack_100 [16];
  float afStack_c0 [3];
  float local_b4;
  undefined4 local_a4;
  float local_94;
  float afStack_90 [12];
  float afStack_60 [24];
  
  uVar6 = FUN_80286838();
  puVar1 = (ushort *)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  if ((iVar5 < 0) || ((int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58) <= iVar5)) {
    *param_3 = *(float *)(puVar1 + 6);
    *param_4 = *(undefined4 *)(puVar1 + 8);
    *param_5 = *(float *)(puVar1 + 10);
  }
  else {
    piVar2 = Obj_GetActiveModel((int)puVar1);
    iVar5 = iVar5 * 0x18;
    iVar4 = (int)*(char *)(*(int *)(*(int *)(puVar1 + 0x28) + 0x2c) + iVar5 +
                           (int)*(char *)((int)puVar1 + 0xad) + 0x12);
    if ((iVar4 < -1) || ((int)(uint)*(byte *)(*piVar2 + 0xf3) <= iVar4)) {
      *param_3 = *(float *)(puVar1 + 6);
      *param_4 = *(undefined4 *)(puVar1 + 8);
      *param_5 = *(float *)(puVar1 + 10);
    }
    else {
      if (iVar4 == -1) {
        FUN_80017a50(puVar1,afStack_60,'\0');
        pfVar3 = afStack_60;
      }
      else {
        pfVar3 = ObjModel_GetJointMatrix(piVar2,iVar4);
      }
      if (param_6 == 0) {
        local_10c = *(float *)(*(int *)(*(int *)(puVar1 + 0x28) + 0x2c) + iVar5);
        iVar5 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c) + iVar5;
        local_108 = *(undefined4 *)(iVar5 + 4);
        local_104 = *(float *)(iVar5 + 8);
        local_118 = *(undefined2 *)(iVar5 + 0xc);
        local_116 = *(undefined2 *)(iVar5 + 0xe);
        local_114 = *(undefined2 *)(iVar5 + 0x10);
      }
      else {
        local_10c = *param_3;
        local_108 = *param_4;
        local_104 = *param_5;
        local_118 = 0;
        local_116 = 0;
        local_114 = 0;
      }
      FUN_8001774c(afStack_100,(int)&local_118);
      FUN_80017704(afStack_100,afStack_90);
      FUN_80247618(pfVar3,afStack_90,afStack_c0);
      *param_3 = local_b4 + playerMapOffsetX;
      *param_4 = local_a4;
      *param_5 = local_94 + playerMapOffsetZ;
    }
  }
  FUN_80286884();
  return;
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
 * Function: FUN_80038b0c
 * EN v1.0 Address: 0x80038B0C
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x800387B4
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80038b0c(void)
{
  byte *pbVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  int iVar6;
  
  FUN_8028683c();
  piVar2 = fn_8005B11C();
  iVar4 = 0;
  do {
    iVar6 = *piVar2;
    if (iVar6 != 0) {
      psVar5 = *(short **)(iVar6 + 0x20);
      for (iVar3 = 0; iVar3 < (int)(uint)*(ushort *)(iVar6 + 8); iVar3 = iVar3 + (uint)*pbVar1 * 4)
      {
        if (*psVar5 == 0x130) {
          FUN_80293f90();
          FUN_80294964();
          FUN_80293f90();
          FUN_80294964();
        }
        pbVar1 = (byte *)(psVar5 + 1);
        psVar5 = psVar5 + (uint)*pbVar1 * 2;
      }
    }
    piVar2 = piVar2 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 0x50);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80038bac
 * EN v1.0 Address: 0x80038BAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80038A80
 * EN v1.1 Size: 1428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80038bac(int param_1,int param_2,uint param_3)
{
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
