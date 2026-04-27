#include "ghidra_import.h"
#include "main/objlib.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern uint fn_80014B24(int index);
extern void fn_80014B3C(int index,uint flags);
extern undefined4 FUN_80017640();
extern undefined4 FUN_80017700();
extern undefined4 FUN_80017704();
extern double FUN_80017714();
extern float FUN_8001771c(float *param_1,float *param_2);
extern int FUN_80017730();
extern undefined4 FUN_8001774c();
extern uint FUN_80017760();
extern uint FUN_800177d4();
extern uint FUN_800177dc();
extern undefined4 FUN_80017830();
extern undefined4 FUN_80017970();
extern undefined4 FUN_80017a50();
extern undefined4 FUN_80017a54();
extern void *fn_8002B9EC(void);
extern undefined4 FUN_80017ac0();
extern int FUN_80017b00();
extern void ObjHitbox_UpdateRotatedBounds(ushort *param_1,int param_2);
extern undefined4 FUN_80045328();
extern undefined4 FUN_80053ab4();
extern int * fn_8005B11C();
extern undefined8 FUN_80135810();
extern undefined4 FUN_80247618();
extern double FUN_802480c0();
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

extern int gObjHitsActiveHitVolumeObjects[5];
extern int DAT_80343558;
extern byte DAT_80343958;
extern char DAT_80343959;
extern int DAT_803439b0;
extern undefined4 DAT_803439b4;
extern undefined4 DAT_803439b8;
typedef struct ObjTriggerInterface {
  u8 pad00[0x1c];
  int (*isCurrentTriggerClear)(void);
  int (*isTriggerSet)(int eventId);
} ObjTriggerInterface;

extern ObjTriggerInterface **lbl_803DCA68;
extern undefined4 DAT_803dd848;
extern undefined4 DAT_803dd850;
extern undefined4 DAT_803dd858;
extern undefined4 DAT_803dd85c;
extern undefined4 DAT_803dd860;
extern undefined4 DAT_803dd864;
extern undefined4 DAT_803dd870;
extern undefined4 DAT_803dd878;
extern undefined4 DAT_803dd880;
extern f64 DOUBLE_803df5c0;
extern f64 DOUBLE_803df640;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dd868;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803df594;
extern f32 FLOAT_803df5e8;
extern f32 FLOAT_803df5f0;
extern f32 FLOAT_803df5f4;
extern f32 FLOAT_803df5f8;
extern f32 FLOAT_803df5fc;
extern f32 FLOAT_803df618;
extern f32 FLOAT_803df61c;
extern f32 FLOAT_803df620;
extern f32 FLOAT_803df624;
extern f32 FLOAT_803df628;
extern f32 FLOAT_803df630;
extern f32 FLOAT_803df634;
extern f32 FLOAT_803df638;
extern int iRam803dd84c;
extern int iRam803dd854;
extern char s_objmsg___x___overflow_in_object___802cba20[];

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

/*
 * --INFO--
 *
 * Function: FUN_800356f0
 * EN v1.0 Address: 0x800356F0
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x80035728
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800356f0(int param_1)
{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined4 uStack_18;
  undefined4 auStack_14 [4];
  
  piVar2 = (int *)FUN_80017b00(&uStack_18,auStack_14);
  DAT_803dd860 = 0;
  if (0 < param_1) {
    do {
      puVar3 = *(undefined4 **)(*piVar2 + 0x54);
      if (((puVar3 != (undefined4 *)0x0) && ((*(ushort *)(puVar3 + 0x18) & 1) != 0)) &&
         ((*(byte *)((int)puVar3 + 0x62) & 8) != 0)) {
        if (DAT_803dd860 < 0x32) {
          iVar1 = DAT_803dd860 * 4;
          DAT_803dd860 = DAT_803dd860 + 1;
          *(int *)(DAT_803dd864 + iVar1) = *piVar2;
        }
        *puVar3 = 0;
        *(ushort *)(puVar3 + 0x18) = *(ushort *)(puVar3 + 0x18) & 0xfff7;
        *(undefined2 *)(puVar3 + 0x16) = 0x400;
      }
      piVar2 = piVar2 + 1;
      param_1 = param_1 + -1;
    } while (param_1 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHitbox_AllocRotatedBounds
 * EN v1.0 Address: 0x800357A8
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800357E8
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHitbox_AllocRotatedBounds(ushort *param_1,uint param_2)
{
  uint uVar1;
  
  uVar1 = FUN_800177d4(param_2);
  *(uint *)(param_1 + 0x2c) = uVar1;
  if (*(int *)(param_1 + 0x2c) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10c) = 0;
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10d) = 10;
    *(undefined *)(*(int *)(param_1 + 0x2c) + 0x10f) = 0;
    ObjHitbox_UpdateRotatedBounds(param_1,1);
    ObjHitbox_UpdateRotatedBounds(param_1,1);
  }
  return uVar1 + 0x110;
}

/*
 * --INFO--
 *
 * Function: ObjHitReact_LoadMoveEntries
 * EN v1.0 Address: 0x8003582C
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x8003586C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitReact_LoadMoveEntries(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                                 undefined8 param_5,undefined8 param_6,undefined8 param_7,
                                 undefined8 param_8,int param_9,undefined4 param_10,
                                 undefined4 param_11,int param_12,int param_13,int param_14,
                                 undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  
  psVar4 = *(short **)(*(int *)(param_9 + 0x50) + 0x24);
  *(undefined2 *)(param_12 + 4) = 0;
  if (psVar4 != (short *)0x0) {
    iVar3 = 0;
    for (psVar2 = psVar4; *psVar2 != -1; psVar2 = psVar2 + 3) {
      if (param_13 == *psVar2) {
        sVar1 = psVar4[iVar3 + 1];
        *(short *)(param_12 + 4) = psVar4[iVar3 + 2];
        if (*(short *)(param_12 + 6) < *(short *)(param_12 + 4)) {
          *(short *)(param_12 + 4) = *(short *)(param_12 + 6);
        }
        if (param_14 == 0) {
          FUN_80017640(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       *(undefined4 *)(param_12 + 8),0x41,(int)sVar1,(int)*(short *)(param_12 + 4),
                       param_13,0,param_15,param_16);
          return;
        }
        FUN_80045328(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x41,
                     *(undefined4 *)(param_12 + 8),(int)sVar1,(int)*(short *)(param_12 + 4),param_13
                     ,param_14,param_15,param_16);
        return;
      }
      iVar3 = iVar3 + 3;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHitReact_InitState
 * EN v1.0 Address: 0x8003597C
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x80035920
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitReact_InitState(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,int param_5)
{
  uint uVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar2;
  double in_f2;
  double in_f3;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar3;
  
  uVar3 = FUN_80286840();
  if ((int)uVar3 != 0) {
    *(undefined2 *)(param_3 + 6) = 300;
    uVar2 = extraout_f1;
    uVar1 = FUN_800177dc(param_4);
    *(uint *)(param_3 + 8) = uVar1;
    *(undefined *)(param_3 + 0xae) = 1;
    if ((*(byte *)(param_3 + 0x62) & 0x30) != 0) {
      *(undefined *)(param_3 + 0xaf) = 2;
    }
    ObjHitReact_LoadMoveEntries(uVar2,in_f2,in_f3,in_f4,in_f5,in_f6,in_f7,in_f8,param_5,(int)uVar3,
                                (int)((ulonglong)uVar3 >> 0x20),param_3,0,1,in_r9,in_r10);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetStateIndex
 * EN v1.0 Address: 0x80035AE4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x800359CC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitbox_SetStateIndex(int param_1,int param_2,int param_3)
{
  int iVar1;
  int *piVar2;
  short sVar3;
  
  iVar1 = (int)*(char *)(*(int *)(param_1 + 0x50) + 0x55);
  if (param_3 < iVar1) {
    if (param_3 < 0) {
      param_3 = 0;
    }
  }
  else {
    param_3 = iVar1 + -1;
  }
  if (*(char *)(param_2 + 0xb0) == param_3) {
    return;
  }
  iVar1 = 0;
  for (sVar3 = 0; sVar3 < 0x32; sVar3 = sVar3 + 1) {
    piVar2 = (int *)(DAT_803dd85c + iVar1);
    if ((*piVar2 != 0) && (piVar2[2] == param_1)) {
      *piVar2 = 0;
    }
    iVar1 = iVar1 + 0x3c;
  }
  *(char *)(param_2 + 0xb0) = (char)param_3;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetTargetMask
 * EN v1.0 Address: 0x80035B70
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
  if (*(int *)(param_1 + 0x54) == 0) {
    return;
  }
  *(undefined *)(*(int *)(param_1 + 0x54) + 0xb5) = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80035b84
 * EN v1.0 Address: 0x80035B84
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80035A6C
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80035b84(int param_1,undefined2 param_2)
{
  double dVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    if ((*(byte *)(iVar3 + 0x62) & 1) != 0) {
      *(undefined2 *)(iVar3 + 0x5a) = param_2;
      dVar1 = DOUBLE_803df5c0;
      uVar2 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      *(float *)(iVar3 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0) *
           (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      *(float *)(iVar3 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar2 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar3 + 0x28) < (float)((double)CONCAT44(0x43300000,uVar2) - dVar1)) {
        *(float *)(iVar3 + 0x28) = (float)((double)CONCAT44(0x43300000,uVar2) - dVar1);
      }
      *(float *)(iVar3 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar2 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar3 + 0x2c) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0))
      {
        *(float *)(iVar3 + 0x2c) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      }
    }
    if ((*(byte *)(iVar3 + 0xb6) & 1) != 0) {
      *(undefined2 *)(iVar3 + 100) = param_2;
      *(float *)(iVar3 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if (*(float *)(iVar3 + 0x30) <
          (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x5a) ^ 0x80000000) -
                 DOUBLE_803df5c0)) {
        *(float *)(iVar3 + 0x30) =
             (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 100) ^ 0x80000000) -
                    DOUBLE_803df5c0);
      }
      *(float *)(iVar3 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if (*(float *)(iVar3 + 0x34) <
          (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x5a) ^ 0x80000000) -
                 DOUBLE_803df5c0)) {
        *(float *)(iVar3 + 0x34) =
             (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 100) ^ 0x80000000) -
                    DOUBLE_803df5c0);
      }
    }
    *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(iVar3 + 0x2c);
    if (*(float *)(iVar3 + 0x38) < *(float *)(iVar3 + 0x34)) {
      *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x34);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80035d58
 * EN v1.0 Address: 0x80035D58
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x80035C48
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80035d58(int param_1,undefined2 param_2,short param_3,short param_4)
{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    if ((*(byte *)(iVar3 + 0x62) & 2) != 0) {
      *(short *)(iVar3 + 0x5c) = param_3;
      *(short *)(iVar3 + 0x5e) = param_4;
      *(undefined2 *)(iVar3 + 0x5a) = param_2;
      uVar4 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      *(float *)(iVar3 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803df5c0) *
           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803df5c0);
      *(undefined2 *)(iVar3 + 0x58) = 0x400;
      *(float *)(iVar3 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar4 = (uint)param_3;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df5c0);
      uVar4 = (uint)param_4;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar2 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df5c0);
      if (fVar2 < fVar1) {
        fVar2 = fVar1;
      }
      if (*(float *)(iVar3 + 0x28) < fVar2) {
        *(float *)(iVar3 + 0x28) = fVar2;
      }
      *(float *)(iVar3 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar4 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar3 + 0x2c) < (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803df5c0))
      {
        *(float *)(iVar3 + 0x2c) = (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803df5c0);
      }
    }
    if ((*(byte *)(iVar3 + 0xb6) & 2) != 0) {
      *(short *)(iVar3 + 0x66) = param_3;
      *(short *)(iVar3 + 0x68) = param_4;
      *(undefined2 *)(iVar3 + 100) = param_2;
      *(float *)(iVar3 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar4 = (uint)param_3;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df5c0);
      uVar4 = (uint)param_4;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar2 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df5c0);
      if (fVar2 < fVar1) {
        fVar2 = fVar1;
      }
      if (*(float *)(iVar3 + 0x30) < fVar2) {
        *(float *)(iVar3 + 0x30) = fVar2;
      }
      *(float *)(iVar3 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if (*(float *)(iVar3 + 0x34) <
          (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x5a) ^ 0x80000000) -
                 DOUBLE_803df5c0)) {
        *(float *)(iVar3 + 0x34) =
             (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 100) ^ 0x80000000) -
                    DOUBLE_803df5c0);
      }
    }
    *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(iVar3 + 0x2c);
    if (*(float *)(iVar3 + 0x38) < *(float *)(iVar3 + 0x34)) {
      *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x34);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ClearHitVolumes
 * EN v1.0 Address: 0x80035FA8
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
 * EN v1.0 Address: 0x80035FC4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80035EC0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetHitVolumeMasks(int param_1,undefined param_2,undefined param_3,int param_4)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  *(undefined *)(iVar1 + 0x6e) = param_2;
  *(undefined *)(iVar1 + 0x6f) = param_3;
  if (param_4 == 0) {
    return;
  }
  *(int *)(iVar1 + 0x48) = param_4 << 4;
  *(int *)(iVar1 + 0x4c) = param_4 << 4;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetHitVolumeSlot
 * EN v1.0 Address: 0x80035FE8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80035EEC
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetHitVolumeSlot(int param_1,undefined param_2,undefined param_3,int param_4)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x54);
  if (iVar2 == 0) {
    return;
  }
  *(undefined *)(iVar2 + 0x6e) = param_2;
  *(undefined *)(iVar2 + 0x6f) = param_3;
  if (param_4 == -1) {
    return;
  }
  iVar1 = 1 << param_4 + 4;
  *(int *)(iVar2 + 0x48) = iVar1;
  *(int *)(iVar2 + 0x4c) = iVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ClearSourceMask
 * EN v1.0 Address: 0x8003601C
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035F28
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ClearSourceMask(int param_1,byte param_2)
{
  *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) = *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) & ~param_2
  ;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetSourceMask
 * EN v1.0 Address: 0x80036030
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
 * EN v1.0 Address: 0x80036044
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035F54
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ClearFlags(int param_1,ushort param_2)
{
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetFlags
 * EN v1.0 Address: 0x80036058
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035F6C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetFlags(int param_1,ushort param_2)
{
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_MarkObjectPositionDirty
 * EN v1.0 Address: 0x8003606C
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035F84
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_MarkObjectPositionDirty(int param_1)
{
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 0x40
  ;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SyncObjectPositionIfDirty
 * EN v1.0 Address: 0x80036080
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80035F9C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SyncObjectPositionIfDirty(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  if ((*(ushort *)(iVar1 + 0x60) & 0x40) == 0) {
    return;
  }
  *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) & 0xffbf;
  *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_1 + 0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_DisableObject
 * EN v1.0 Address: 0x800360D4
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80035FF8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_DisableObject(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) & 0xfffe;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_EnableObject
 * EN v1.0 Address: 0x800360F0
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80036018
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_EnableObject(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  if ((*(ushort *)(iVar1 + 0x60) & 1) != 0) {
    return;
  }
  *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) | 1;
  *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_1 + 0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_IsObjectEnabled
 * EN v1.0 Address: 0x80036144
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
  return *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SyncObjectPosition
 * EN v1.0 Address: 0x80036154
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80036084
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SyncObjectPosition(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_1 + 0x20);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_AllocObjectState
 * EN v1.0 Address: 0x80036194
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800360C4
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_AllocObjectState(int param_1,uint param_2)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_800177d4(param_2);
  *(uint *)(param_1 + 0x54) = uVar1;
  iVar2 = *(int *)(param_1 + 0x54);
  ObjHits_RefreshObjectState(param_1);
  *(undefined *)(iVar2 + 0xae) = 1;
  if ((*(byte *)(iVar2 + 0x62) & 0x30) != 0) {
    *(undefined *)(iVar2 + 0xaf) = 2;
  }
  return uVar1 + 0xb8;
}

/*
 * --INFO--
 *
 * Function: ObjHits_RefreshObjectState
 * EN v1.0 Address: 0x80036200
 * EN v1.0 Size: 932b
 * EN v1.1 Address: 0x8003613C
 * EN v1.1 Size: 1036b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_RefreshObjectState(int param_1)
{
  double dVar1;
  uint uVar2;
  short sVar3;
  short sVar4;
  int iVar5;
  int *piVar6;
  
  iVar5 = *(int *)(param_1 + 0x54);
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
    dVar1 = DOUBLE_803df5c0;
    uVar2 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
    *(float *)(iVar5 + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0) *
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
    *(undefined *)(iVar5 + 0xb6) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x90);
    *(ushort *)(iVar5 + 100) = (ushort)*(byte *)(*(int *)(param_1 + 0x50) + 0x77);
    *(undefined2 *)(iVar5 + 0x66) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6c);
    *(undefined2 *)(iVar5 + 0x68) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6e);
    *(float *)(iVar5 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if ((*(byte *)(iVar5 + 0x62) & 2) == 0) {
      if ((*(byte *)(iVar5 + 0x62) & 1) != 0) {
        uVar2 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
        if (*(float *)(iVar5 + 0x28) < (float)((double)CONCAT44(0x43300000,uVar2) - dVar1)) {
          *(float *)(iVar5 + 0x28) = (float)((double)CONCAT44(0x43300000,uVar2) - dVar1);
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
      if (*(float *)(iVar5 + 0x28) <
          (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0)) {
        *(float *)(iVar5 + 0x28) =
             (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0);
      }
    }
    *(float *)(iVar5 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if (((*(byte *)(iVar5 + 0x62) & 2) != 0) || ((*(byte *)(iVar5 + 0x62) & 1) != 0)) {
      uVar2 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar5 + 0x2c) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0))
      {
        *(float *)(iVar5 + 0x2c) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      }
    }
    *(float *)(iVar5 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if ((*(byte *)(iVar5 + 0xb6) & 2) == 0) {
      if ((*(byte *)(iVar5 + 0xb6) & 1) != 0) {
        uVar2 = (int)*(short *)(iVar5 + 100) ^ 0x80000000;
        if (*(float *)(iVar5 + 0x30) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0)
           ) {
          *(float *)(iVar5 + 0x30) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
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
      if (*(float *)(iVar5 + 0x30) <
          (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0)) {
        *(float *)(iVar5 + 0x30) =
             (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0);
      }
    }
    *(float *)(iVar5 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if (((*(byte *)(iVar5 + 0xb6) & 2) != 0) || ((*(byte *)(iVar5 + 0xb6) & 1) != 0)) {
      uVar2 = (int)*(short *)(iVar5 + 100) ^ 0x80000000;
      if (*(float *)(iVar5 + 0x34) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0))
      {
        *(float *)(iVar5 + 0x34) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      }
    }
    *(undefined4 *)(iVar5 + 0x38) = *(undefined4 *)(iVar5 + 0x2c);
    if (*(float *)(iVar5 + 0x38) < *(float *)(iVar5 + 0x34)) {
      *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x34);
    }
    *(undefined *)(iVar5 + 0xb4) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x70);
    *(undefined *)(iVar5 + 0xb5) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x67);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_RecordObjectHit
 * EN v1.0 Address: 0x800365A4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80036548
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjHits_RecordObjectHit(int param_1,int param_2,char param_3,undefined param_4,undefined param_5)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_3 == '\0') {
    return 0;
  }
  iVar2 = *(int *)(param_1 + 0x54);
  if ((*(ushort *)(iVar2 + 0x60) & 1) == 0) {
    return 0;
  }
  if ((param_2 != 0) && (*(int *)(param_2 + 0x54) != 0)) {
    *(int *)(*(int *)(param_2 + 0x54) + 0x50) = param_1;
  }
  iVar3 = 0;
  while( true ) {
    iVar1 = (int)*(char *)(iVar2 + 0x71);
    if (iVar1 <= iVar3) break;
    iVar1 = iVar2 + iVar3 * 4;
    if (*(int *)(iVar1 + 0x7c) == param_2) {
      iVar3 = iVar2 + iVar3;
      if (param_3 < *(char *)(iVar3 + 0x75)) {
        *(undefined *)(iVar3 + 0x72) = param_5;
        *(char *)(iVar3 + 0x75) = param_3;
        *(undefined *)(iVar3 + 0x78) = param_4;
        *(undefined4 *)(iVar1 + 0x88) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(iVar1 + 0x94) = *(undefined4 *)(param_1 + 0x10);
        *(undefined4 *)(iVar1 + 0xa0) = *(undefined4 *)(param_1 + 0x14);
      }
      iVar3 = *(char *)(iVar2 + 0x71) + 1;
    }
    iVar3 = iVar3 + 1;
  }
  if ((iVar3 == iVar1) && (iVar1 < 3)) {
    *(undefined *)(iVar2 + iVar1 + 0x72) = param_5;
    *(char *)(iVar2 + *(char *)(iVar2 + 0x71) + 0x75) = param_3;
    *(undefined *)(iVar2 + *(char *)(iVar2 + 0x71) + 0x78) = param_4;
    *(int *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0x7c) = param_2;
    *(undefined4 *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0x88) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0x94) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + *(char *)(iVar2 + 0x71) * 4 + 0xa0) = *(undefined4 *)(param_1 + 0x14);
    *(char *)(iVar2 + 0x71) = *(char *)(iVar2 + 0x71) + '\x01';
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_RecordPositionHit
 * EN v1.0 Address: 0x80036704
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x800366B0
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
ObjHits_RecordPositionHit(double param_1,double param_2,double param_3,int param_4,int param_5,char param_6,
            undefined param_7,undefined param_8)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_6 == '\0') {
    return 0;
  }
  iVar3 = *(int *)(param_4 + 0x54);
  if ((*(ushort *)(iVar3 + 0x60) & 1) == 0) {
    return 0;
  }
  if ((param_5 != 0) && (*(int *)(param_5 + 0x54) != 0)) {
    *(int *)(*(int *)(param_5 + 0x54) + 0x50) = param_4;
  }
  iVar2 = 0;
  while( true ) {
    iVar1 = (int)*(char *)(iVar3 + 0x71);
    if (iVar1 <= iVar2) break;
    iVar1 = iVar3 + iVar2 * 4;
    if (*(int *)(iVar1 + 0x7c) == param_5) {
      iVar2 = iVar3 + iVar2;
      if (param_6 < *(char *)(iVar2 + 0x75)) {
        *(undefined *)(iVar2 + 0x72) = param_8;
        *(char *)(iVar2 + 0x75) = param_6;
        *(undefined *)(iVar2 + 0x78) = param_7;
        *(float *)(iVar1 + 0x88) = (float)param_1;
        *(float *)(iVar1 + 0x94) = (float)param_2;
        *(float *)(iVar1 + 0xa0) = (float)param_3;
      }
      iVar2 = *(char *)(iVar3 + 0x71) + 1;
    }
    iVar2 = iVar2 + 1;
  }
  if ((iVar2 == iVar1) && (iVar1 < 3)) {
    *(undefined *)(iVar3 + iVar1 + 0x72) = param_8;
    *(char *)(iVar3 + *(char *)(iVar3 + 0x71) + 0x75) = param_6;
    *(undefined *)(iVar3 + *(char *)(iVar3 + 0x71) + 0x78) = param_7;
    *(int *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0x7c) = param_5;
    *(float *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0x88) = (float)param_1;
    *(float *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0x94) = (float)param_2;
    *(float *)(iVar3 + *(char *)(iVar3 + 0x71) * 4 + 0xa0) = (float)param_3;
    *(char *)(iVar3 + 0x71) = *(char *)(iVar3 + 0x71) + '\x01';
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_AddContactObject
 * EN v1.0 Address: 0x80036864
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80036800
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: ObjHits_GetPriorityHitWithPosition
 * EN v1.0 Address: 0x800368C4
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x80036868
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_GetPriorityHitWithPosition(int param_1,undefined4 *param_2,int *param_3,uint *param_4,undefined4 *param_5,
                undefined4 *param_6,undefined4 *param_7)
{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  char cVar6;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    iVar2 = (int)*(char *)(iVar3 + 0x71);
    if (iVar2 != 0) {
      cVar6 = '\x7f';
      cVar5 = -1;
      iVar4 = 0;
      if (0 < iVar2) {
        do {
          cVar1 = *(char *)(iVar3 + iVar4 + 0x75);
          if (cVar1 < cVar6) {
            cVar5 = (char)iVar4;
            cVar6 = cVar1;
          }
          iVar4 = iVar4 + 1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
      if (cVar5 != -1) {
        if (param_2 != (undefined4 *)0x0) {
          *param_2 = *(undefined4 *)(iVar3 + cVar5 * 4 + 0x7c);
        }
        if (param_3 != (int *)0x0) {
          *param_3 = (int)*(char *)(iVar3 + cVar5 + 0x72);
        }
        if (param_4 != (uint *)0x0) {
          *param_4 = (uint)*(byte *)(iVar3 + cVar5 + 0x78);
        }
        if (param_5 != (undefined4 *)0x0) {
          iVar3 = iVar3 + cVar5 * 4;
          *param_5 = *(undefined4 *)(iVar3 + 0x88);
          *param_6 = *(undefined4 *)(iVar3 + 0x94);
          *param_7 = *(undefined4 *)(iVar3 + 0xa0);
        }
        return (int)cVar6;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjHits_GetPriorityHit
 * EN v1.0 Address: 0x800369D0
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80036974
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_GetPriorityHit(int param_1,undefined4 *param_2,int *param_3,uint *param_4)
{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  char cVar6;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 == 0) {
    return 0;
  }
  iVar2 = (int)*(char *)(iVar3 + 0x71);
  if (iVar2 != 0) {
    cVar6 = '\x7f';
    cVar5 = -1;
    iVar4 = 0;
    if (0 < iVar2) {
      do {
        cVar1 = *(char *)(iVar3 + iVar4 + 0x75);
        if (cVar1 < cVar6) {
          cVar5 = (char)iVar4;
          cVar6 = cVar1;
        }
        iVar4 = iVar4 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    if (cVar5 != -1) {
      if (param_2 != (undefined4 *)0x0) {
        *param_2 = *(undefined4 *)(iVar3 + cVar5 * 4 + 0x7c);
      }
      if (param_3 != (int *)0x0) {
        *param_3 = (int)*(char *)(iVar3 + cVar5 + 0x72);
      }
      if (param_4 != (uint *)0x0) {
        *param_4 = (uint)*(byte *)(iVar3 + cVar5 + 0x78);
      }
      return (int)cVar6;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjHitReact_UpdateResetObjects
 * EN v1.0 Address: 0x80036A98
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x80036A3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitReact_UpdateResetObjects(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                                    int param_4,undefined4 param_5,int param_6,
                                    undefined4 param_7,undefined4 param_8)
{
  short *psVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dd860; iVar2 = iVar2 + 1) {
    psVar1 = *(short **)(DAT_803dd864 + iVar3);
    if (((*(uint *)(*(int *)(psVar1 + 0x28) + 0x44) & 0x40) == 0) &&
       (*(char *)(psVar1 + 0x57) != 'd')) {
      FUN_80017ac0(psVar1,*(int *)(psVar1 + 0x28),param_3,param_4,param_5,param_6,param_7,param_8);
    }
    iVar3 = iVar3 + 4;
  }
  iVar3 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dd860; iVar2 = iVar2 + 1) {
    ObjHitbox_UpdateRotatedBounds(*(ushort **)(DAT_803dd864 + iVar3),1);
    iVar3 = iVar3 + 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ResetWorkBuffers
 * EN v1.0 Address: 0x80036B6C
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80036AE8
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ResetWorkBuffers(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  iVar1 = 0;
  iVar3 = 3;
  do {
    *(undefined4 *)(DAT_803dd85c + iVar1) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x3c) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x78) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0xb4) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0xf0) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 300) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x168) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x1a4) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x1e0) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x21c) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 600) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x294) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x2d0) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x30c) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 0x348) = 0;
    *(undefined4 *)(DAT_803dd85c + iVar1 + 900) = 0;
    iVar1 = iVar1 + 0x3c0;
    iVar2 = iVar2 + 0x10;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  iVar3 = iVar2 * 0x3c;
  iVar1 = 0x32 - iVar2;
  if (iVar2 < 0x32) {
    do {
      *(undefined4 *)(DAT_803dd85c + iVar3) = 0;
      iVar3 = iVar3 + 0x3c;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  DAT_803dd860 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHitReact_GetResetObjects
 * EN v1.0 Address: 0x80036CA0
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80036BF4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjHitReact_GetResetObjects(undefined4 *param_1)
{
  *param_1 = DAT_803dd860;
  return DAT_803dd864;
}

/*
 * --INFO--
 *
 * Function: ObjHits_InitWorkBuffers
 * EN v1.0 Address: 0x80036CB0
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80036C04
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_InitWorkBuffers(void)
{
  DAT_803dd864 = FUN_80017830(200,0xe);
  DAT_803dd85c = FUN_80017830(3000,0xe);
  DAT_803dd858 = FUN_80017830(0x1900,0xe);
  DAT_803dd850 = FUN_80017830(0x400,0xe);
  iRam803dd854 = FUN_80017830(0x400,0xe);
  DAT_803dd848 = FUN_80017830(0x400,0xe);
  iRam803dd84c = FUN_80017830(0x400,0xe);
  FLOAT_803dd868 = FLOAT_803df594;
  gObjHitsActiveHitVolumeObjects[0] = 0;
  gObjHitsActiveHitVolumeObjects[1] = 0;
  gObjHitsActiveHitVolumeObjects[2] = 0;
  gObjHitsActiveHitVolumeObjects[3] = 0;
  gObjHitsActiveHitVolumeObjects[4] = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_ContainsObject
 * EN v1.0 Address: 0x80036D5C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80036D04
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint ObjGroup_ContainsObject(int param_1,int param_2)
{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  
  if ((-1 < param_2) && (param_2 < 0x54)) {
    uVar2 = (uint)(byte)(&DAT_80343958)[param_2];
    uVar3 = (uint)(byte)(&DAT_80343959)[param_2];
    for (piVar1 = &DAT_80343558 + uVar2; ((int)uVar2 < (int)uVar3 && (param_1 != *piVar1));
        piVar1 = piVar1 + 1) {
      uVar2 = uVar2 + 1;
    }
    return ((int)(uVar3 ^ uVar2) >> 1) - ((uVar3 ^ uVar2) & uVar3) >> 0x1f;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObjectToPoint
 * EN v1.0 Address: 0x80036DCC
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x80036D78
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_FindNearestObjectToPoint(undefined4 param_1,undefined4 param_2,float *param_3)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  double dVar6;
  double dVar7;
  longlong lVar8;
  
  lVar8 = FUN_8028683c();
  iVar2 = (int)((ulonglong)lVar8 >> 0x20);
  iVar4 = 0;
  dVar7 = (double)(*param_3 * *param_3);
  if ((-1 < lVar8) && (lVar8 < 0x5400000000)) {
    uVar3 = (uint)(byte)(&DAT_80343958)[iVar2];
    bVar1 = (&DAT_80343959)[iVar2];
    piVar5 = &DAT_80343558 + uVar3;
    while ((int)uVar3 < (int)(uint)bVar1) {
      if (*piVar5 != 0) {
        dVar6 = FUN_802480c0((float *)lVar8,(float *)(*piVar5 + 0x18));
        if (dVar6 < dVar7) {
          iVar4 = *piVar5;
          dVar7 = dVar6;
        }
        piVar5 = piVar5 + 1;
        uVar3 = uVar3 + 1;
      }
    }
    if (iVar4 != 0) {
      dVar7 = FUN_80293900(dVar7);
      *param_3 = (float)dVar7;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObjectForObject
 * EN v1.0 Address: 0x80036EDC
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80036E58
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_FindNearestObjectForObject(undefined4 param_1,undefined4 param_2,float *param_3)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  longlong lVar9;
  
  lVar9 = FUN_8028683c();
  iVar3 = (int)((ulonglong)lVar9 >> 0x20);
  iVar5 = 0;
  if ((-1 < lVar9) && (lVar9 < 0x5400000000)) {
    fVar2 = FLOAT_803df5e8;
    if (param_3 != (float *)0x0) {
      fVar2 = *param_3 * *param_3;
    }
    dVar8 = (double)fVar2;
    uVar4 = (uint)(byte)(&DAT_80343958)[iVar3];
    bVar1 = (&DAT_80343959)[iVar3];
    piVar6 = &DAT_80343558 + uVar4;
    for (; (int)uVar4 < (int)(uint)bVar1; uVar4 = uVar4 + 1) {
      if ((*piVar6 != (int)lVar9) &&
         (dVar7 = FUN_80017714((float *)((int)lVar9 + 0x18),(float *)(*piVar6 + 0x18)),
         dVar7 < dVar8)) {
        iVar5 = *piVar6;
        dVar8 = dVar7;
      }
      piVar6 = piVar6 + 1;
    }
    if ((iVar5 != 0) && (param_3 != (float *)0x0)) {
      dVar8 = FUN_80293900(dVar8);
      *param_3 = (float)dVar8;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObject
 * EN v1.0 Address: 0x80037008
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80036F50
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_FindNearestObject(undefined4 param_1,undefined4 param_2,float *param_3)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  longlong lVar9;
  
  lVar9 = FUN_8028683c();
  iVar3 = (int)((ulonglong)lVar9 >> 0x20);
  iVar5 = 0;
  if ((-1 < lVar9) && (lVar9 < 0x5400000000)) {
    fVar2 = FLOAT_803df5e8;
    if (param_3 != (float *)0x0) {
      fVar2 = *param_3 * *param_3;
    }
    dVar8 = (double)fVar2;
    uVar4 = (uint)(byte)(&DAT_80343958)[iVar3];
    bVar1 = (&DAT_80343959)[iVar3];
    piVar6 = &DAT_80343558 + uVar4;
    for (; (int)uVar4 < (int)(uint)bVar1; uVar4 = uVar4 + 1) {
      if ((*piVar6 != (int)lVar9) &&
         (dVar7 = FUN_80017714((float *)((int)lVar9 + 0x18),(float *)(*piVar6 + 0x18)),
         dVar7 < dVar8)) {
        iVar5 = *piVar6;
        dVar8 = dVar7;
      }
      piVar6 = piVar6 + 1;
    }
    if ((iVar5 != 0) && (param_3 != (float *)0x0)) {
      dVar8 = FUN_80293900(dVar8);
      *param_3 = (float)dVar8;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_GetObjects
 * EN v1.0 Address: 0x80037134
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x80037048
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * ObjGroup_GetObjects(int param_1,int *param_2)
{
  if ((-1 < param_1) && (param_1 < 0x54)) {
    *param_2 = (uint)(byte)(&DAT_80343959)[param_1] - (uint)(byte)(&DAT_80343958)[param_1];
    return (undefined4 *)(&DAT_80343558 + (byte)(&DAT_80343958)[param_1]);
  }
  *param_2 = 0;
  return (undefined4 *)0x0;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_RemoveObject
 * EN v1.0 Address: 0x80037180
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x8003709C
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_RemoveObject(int param_1,int param_2)
{
  byte *bucketStarts;
  char *bucketEnds;
  int count;
  int index;
  int limit;
  int *entries;
  
  if ((param_2 < 0) || (0x53 < param_2)) {
    return;
  }
  bucketStarts = &DAT_80343958;
  bucketEnds = &DAT_80343959;
  entries = &DAT_80343558;
  index = (int)bucketStarts[param_2];
  limit = (int)(byte)bucketEnds[param_2];
  while ((index < limit) && (entries[index] != param_1)) {
    index++;
  }
  if (limit <= index) {
    return;
  }
  count = (int)DAT_803dd870 - 1;
  DAT_803dd870 = count;
  while (index < count) {
    entries[index] = entries[index + 1];
    index++;
  }
  while (param_2 < 0x54) {
    bucketEnds[param_2] = bucketEnds[param_2] - 1;
    param_2++;
  }
}

/*
 * --INFO--
 *
 * Function: ObjGroup_GetObjectGroup
 * EN v1.0 Address: 0x800372F8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8003728C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjGroup_GetObjectGroup(int param_1)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = 0;
  piVar3 = &DAT_80343558;
  uVar1 = (uint)DAT_803dd870;
  while( true ) {
    if (uVar1 == 0) {
      return 0;
    }
    if (*piVar3 == param_1) break;
    piVar3 = piVar3 + 1;
    iVar5 = iVar5 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar2 = 0;
  pbVar4 = &DAT_80343958;
  while( true ) {
    if (iVar5 < (int)(uint)*pbVar4) {
      return iVar2;
    }
    if (0x54 < iVar2) break;
    pbVar4 = pbVar4 + 1;
    iVar2 = iVar2 + 1;
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_AddObject
 * EN v1.0 Address: 0x8003735C
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x800372F8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_AddObject(int param_1,int param_2)
{
  byte *bucketStarts;
  char *bucketEnds;
  int count;
  int index;
  int insertIndex;
  int limit;
  int *entries;
  
  if ((param_2 < 0) || (0x53 < param_2)) {
    return;
  }
  bucketStarts = &DAT_80343958;
  entries = &DAT_80343558;
  bucketEnds = &DAT_80343959;
  insertIndex = (int)bucketStarts[param_2];
  limit = (int)(byte)bucketEnds[param_2];
  for (index = insertIndex; index < limit; index++) {
    if (entries[index] == param_1) {
      return;
    }
  }
  if (limit != insertIndex) {
    insertIndex = limit - 1;
  }
  count = (int)DAT_803dd870;
  DAT_803dd870 = count + 1;
  for (index = count; insertIndex < index; index--) {
    entries[index] = entries[index - 1];
  }
  entries[insertIndex] = param_1;
  while (param_2 < 0x54) {
    bucketEnds[param_2] = bucketEnds[param_2] + 1;
    param_2++;
  }
}

/*
 * --INFO--
 *
 * Function: ObjGroup_ClearAll
 * EN v1.0 Address: 0x800374E4
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80037544
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_ClearAll(void)
{
  FUN_800033a8(-0x7fcbc6a8,0,0x55);
  DAT_803dd870 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_Peek
 * EN v1.0 Address: 0x8003751C
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
 * EN v1.0 Address: 0x80037584
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x800375E4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToNearbyObjects
 * EN v1.0 Address: 0x8003762C
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x80037694
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjMsg_SendToNearbyObjects(int targetId,float radius,uint flags,void *sender,uint message,uint param)
{
  int *objects;
  uint count;
  int maskedFlags;
  ObjMsgQueue *queue;
  ObjMsgEntry *entry;
  int objectIndex;
  int objectCount;
  void *obj;
  
  objects = (int *)FUN_80017b00(&objectIndex,&objectCount);
  maskedFlags = flags & 0xffff;
  for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
    obj = (void *)objects[objectIndex];
    if (((obj != sender) || ((maskedFlags & 1) == 0)) &&
        ((*(short *)((byte *)obj + 0x46) == (short)targetId || ((maskedFlags & 2) != 0))) &&
        ((FUN_8001771c((float *)((byte *)sender + 0x18),(float *)((byte *)obj + 0x18)) < radius &&
          (obj != (void *)0x0)) &&
         (queue = *(ObjMsgQueue **)((byte *)obj + 0xdc), queue != (ObjMsgQueue *)0x0))) {
      count = queue->count;
      if (count < queue->capacity) {
        entry = &queue->entries[count];
        entry->message = message;
        entry->sender = (uint)sender;
        entry->param = param;
        queue->count = queue->count + 1;
      } else {
        FUN_80135810(s_objmsg___x___overflow_in_object___802cba20,message,
                     (int)*(short *)((byte *)obj + 0x44),(int)*(short *)((byte *)obj + 0x46),
                     (int)*(short *)((byte *)sender + 0x46));
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToObjects
 * EN v1.0 Address: 0x80037844
 * EN v1.0 Size: 912b
 * EN v1.1 Address: 0x800377D0
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjMsg_SendToObjects(int targetId,uint flags,void *sender,uint message,uint param)
{
  int *objects;
  uint count;
  int maskedFlags;
  ObjMsgQueue *queue;
  ObjMsgEntry *entry;
  int objectIndex;
  int objectCount;
  void *obj;
  
  objects = (int *)FUN_80017b00(&objectIndex,&objectCount);
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
          entry = &queue->entries[count];
          entry->message = message;
          entry->sender = (uint)sender;
          entry->param = param;
          queue->count = queue->count + 1;
        } else {
          FUN_80135810(s_objmsg___x___overflow_in_object___802cba20,message,
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
          entry = &queue->entries[count];
          entry->message = message;
          entry->sender = (uint)sender;
          entry->param = param;
          queue->count = queue->count + 1;
        } else {
          FUN_80135810(s_objmsg___x___overflow_in_object___802cba20,message,
                       (int)*(short *)((byte *)obj + 0x44),(int)*(short *)((byte *)obj + 0x46),
                       (int)*(short *)((byte *)sender + 0x46));
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToObject
 * EN v1.0 Address: 0x80037BD4
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x800379BC
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint ObjMsg_SendToObject(void *obj,uint message,void *sender,uint param)
{
  uint count;
  void *dstObj;
  void *senderObj;
  ObjMsgQueue *queue;
  ObjMsgEntry *entry;
  
  dstObj = obj;
  senderObj = sender;
  if (dstObj != (void *)0x0) {
    queue = *(ObjMsgQueue **)((byte *)dstObj + 0xdc);
    if (queue != (ObjMsgQueue *)0x0) {
      count = queue->count;
      if (count < queue->capacity) {
        entry = &queue->entries[count];
        entry->message = message;
        entry->sender = (uint)senderObj;
        entry->param = param;
        queue->count = queue->count + 1;
        return queue->count;
      }
      FUN_80135810(s_objmsg___x___overflow_in_object___802cba20,message,
                   (int)*(short *)((byte *)dstObj + 0x44),(int)*(short *)((byte *)dstObj + 0x46),
                   (int)*(short *)((byte *)senderObj + 0x46));
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_AllocQueue
 * EN v1.0 Address: 0x80037CE0
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80037A5C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: Obj_IsObjectAlive
 * EN v1.0 Address: 0x80037D50
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80037AD4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 Obj_IsObjectAlive(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = 0;
  if ((param_1 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x40) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}

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
  
  iVar1 = (int)fn_8002B9EC();
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
 * EN v1.0 Address: 0x80037DD4
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80037B60
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_PollPriorityHitWithCooldown(int param_1,float *param_2,undefined4 *param_3,float *param_4)
{
  int iVar1;
  
  iVar1 = 0;
  *param_2 = *param_2 - FLOAT_803dc074;
  if (*param_2 <= FLOAT_803df5f0) {
    if (param_4 == (float *)0x0) {
      iVar1 = ObjHits_GetPriorityHit(param_1,param_3,(int *)0x0,(uint *)0x0);
    }
    else {
      iVar1 = ObjHits_GetPriorityHitWithPosition(param_1,param_3,(int *)0x0,(uint *)0x0,(undefined4 *)param_4,
                           (undefined4 *)(param_4 + 1),(undefined4 *)(param_4 + 2));
      if (iVar1 != 0) {
        FUN_80053ab4(param_1,param_4);
      }
    }
    if (iVar1 != 0) {
      *param_2 = FLOAT_803df5f4;
    }
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_PollPriorityHitEffectWithCooldown
 * EN v1.0 Address: 0x80037FA8
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80037C38
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_PollPriorityHitEffectWithCooldown(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 uint param_6,float *param_7)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  int local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  undefined2 local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  undefined4 uStack_34;
  float local_30[12];
  
  uVar4 = FUN_80286834();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  *param_7 = *param_7 - FLOAT_803dc074;
  iVar2 = ObjHits_GetPriorityHitWithPosition((int)uVar1, (undefined4 *)&local_58, (int *)0x0, (uint *)0x0,
                       (undefined4 *)&local_38,
                       &uStack_34, (undefined4 *)local_30);
  if ((((*param_7 <= FLOAT_803df5f0) && (iVar2 != 0)) && ((*param_7 = FLOAT_803df5f8), (iVar2 != 0x1a))) &&
      (iVar2 != 5)) {
    local_38 = local_38 + FLOAT_803dda58;
    local_30[0] = local_30[0] + FLOAT_803dda5c;
    local_3c = FLOAT_803df5fc;
    local_40 = 0;
    local_42 = 0;
    local_44 = 0;
    piVar3 = (int *)FUN_80006b14(0x5a);
    local_54 = (uint)uVar4 & 0xff;
    local_50 = param_3 & 0xff;
    local_4c = param_4 & 0xff;
    local_48 = param_5 & 0xff;
    (**(code **)(*piVar3 + 4))(0, 1, &local_44, 0x401, 0xffffffff, &local_54);
    if ((((param_6 & 0xffff) != 0) && (local_58 != 0)) && (*(short *)(local_58 + 0x46) == 0x69)) {
      FUN_80006824((int)uVar1, (ushort)param_6);
    }
  }
  FUN_80286880();
}

/*
 * --INFO--
 *
 * Function: ObjLink_DetachChild
 * EN v1.0 Address: 0x8003817C
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80037DA8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: ObjLink_AttachChild
 * EN v1.0 Address: 0x800381F8
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80037E24
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjLink_AttachChild(int param_1,int param_2,ushort param_3)
{
  byte bVar1;
  
  bVar1 = *(byte *)(param_1 + 0xeb);
  *(byte *)(param_1 + 0xeb) = bVar1 + 1;
  *(int *)(param_1 + (uint)bVar1 * 4 + 200) = param_2;
  *(int *)(param_2 + 0xc4) = param_1;
  *(ushort *)(param_2 + 0xb0) = *(ushort *)(param_2 + 0xb0) & 0xfff8;
  *(ushort *)(param_2 + 0xb0) = *(ushort *)(param_2 + 0xb0) | param_3;
  *(undefined *)(param_2 + 0xe5) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: ObjContact_DispatchCallbacks
 * EN v1.0 Address: 0x80038238
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80037E6C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: ObjContact_RemoveObjectCallbacks
 * EN v1.0 Address: 0x80038318
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80037F3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: ObjContact_AddCallback
 * EN v1.0 Address: 0x800383C0
 * EN v1.0 Size: 176b
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
 * EN v1.0 Address: 0x80038470
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x8003809C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    iVar1 = (int)param_2;
    if ((flagBlocked == 0) && (iVar1 = (*lbl_803DCA68)->isTriggerSet(iVar1), iVar1 != 0)) {
      iVar1 = fn_80296BA0(fn_8002B9EC());
      if (iVar1 == -1) {
        fn_80014B3C(0,0x100);
        return 1;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjTrigger_IsSet
 * EN v1.0 Address: 0x800384EC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8003811C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjTrigger_IsSet(int param_1)
{
  uint flags;
  int iVar1;
  int triggerFlags;
  int flagEnabled;
  int flagBlocked;
  
  if (*(int *)(*(int *)(param_1 + 0x50) + 0x40) == 0) {
    return 0;
  }
  flags = fn_80014B24(0);
  if ((flags & 0x100) == 0) {
    triggerFlags = *(byte *)(param_1 + 0xaf);
    flagEnabled = triggerFlags & 1;
    if (flagEnabled != 0) {
      flagBlocked = triggerFlags & 8;
      if ((flagBlocked == 0) && (iVar1 = (*lbl_803DCA68)->isCurrentTriggerClear(), iVar1 == 0)) {
        iVar1 = fn_80296BA0(fn_8002B9EC());
        if ((iVar1 == -1) || (iVar1 == 0x40)) {
          fn_80014B3C(0,0x100);
          return 1;
        }
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjList_FindNearestObjectByDefNo
 * EN v1.0 Address: 0x80038598
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x800381D8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjList_FindNearestObjectByDefNo(undefined4 param_1,undefined4 param_2,float *param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  double dVar6;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar7;
  int local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar7 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar2 = FUN_80017b00(local_34,&local_38);
  *param_3 = *param_3 * *param_3;
  if ((int)uVar7 == -1) {
    piVar4 = (int *)(iVar2 + local_34[0] * 4);
    dVar5 = (double)FLOAT_803df5f0;
    for (iVar2 = local_34[0]; iVar2 < local_38; iVar2 = iVar2 + 1) {
      dVar6 = FUN_80017714((float *)(iVar1 + 0x18),(float *)(*piVar4 + 0x18));
      if ((dVar6 != dVar5) && (dVar6 < (double)*param_3)) {
        *param_3 = (float)dVar6;
      }
      piVar4 = piVar4 + 1;
    }
  }
  else {
    piVar4 = (int *)(iVar2 + local_34[0] * 4);
    for (iVar2 = local_34[0]; iVar2 < local_38; iVar2 = iVar2 + 1) {
      iVar3 = *piVar4;
      if ((((int)uVar7 == (int)*(short *)(iVar3 + 0x46)) && (iVar1 != iVar3)) &&
         (dVar5 = FUN_80017714((float *)(iVar1 + 0x18),(float *)(iVar3 + 0x18)),
         dVar5 < (double)*param_3)) {
        *param_3 = (float)dVar5;
      }
      piVar4 = piVar4 + 1;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: ObjList_ContainsObject
 * EN v1.0 Address: 0x800386BC
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80038300
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjList_ContainsObject(int param_1)
{
  int *piVar1;
  int local_18;
  int local_14 [4];
  
  piVar1 = (int *)FUN_80017b00(local_14,&local_18);
  local_14[0] = 0;
  while( true ) {
    if (local_18 <= local_14[0]) {
      return 0;
    }
    if (*piVar1 == param_1) break;
    piVar1 = piVar1 + 1;
    local_14[0] = local_14[0] + 1;
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointWorldPositionArray
 * EN v1.0 Address: 0x80038730
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80038378
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointWorldPositionArray(undefined4 param_1,undefined4 param_2,int param_3,float *param_4)
{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286840();
  for (iVar1 = 0; iVar1 < param_3; iVar1 = iVar1 + 1) {
    ObjPath_GetPointWorldPosition((int)((ulonglong)uVar2 >> 0x20), (int)uVar2 + iVar1, param_4,
                 (undefined4 *)(param_4 + 1), param_4 + 2, 0);
    param_4 = param_4 + 3;
  }
  FUN_8028688c();
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointLocalPosition
 * EN v1.0 Address: 0x800387AC
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800383E8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointLocalPosition(int param_1,int param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)
{
  int iVar1;
  
  iVar1 = param_2 * 0x18;
  *param_3 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + iVar1);
  *param_4 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + iVar1 + 4);
  *param_5 = *(undefined4 *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + iVar1 + 8);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointLocalMtx
 * EN v1.0 Address: 0x800387EC
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80038428
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointLocalMtx(int param_1,int param_2,float *param_3)
{
  int iVar1;
  ushort local_18;
  undefined2 local_16;
  undefined2 local_14;
  float local_10;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x50) + 0x2c);
  local_c = *(undefined4 *)(iVar1 + param_2 * 0x18);
  iVar1 = iVar1 + param_2 * 0x18;
  local_8 = *(undefined4 *)(iVar1 + 4);
  local_4 = *(undefined4 *)(iVar1 + 8);
  local_18 = *(ushort *)(iVar1 + 0xc);
  local_16 = *(undefined2 *)(iVar1 + 0xe);
  local_14 = *(undefined2 *)(iVar1 + 0x10);
  local_10 = FLOAT_803df5fc;
  FUN_80017700(&local_18,param_3);
  return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointModelMtx
 * EN v1.0 Address: 0x8003882C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x80038498
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointModelMtx(int param_1,int param_2)
{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)FUN_80017a54(param_1);
  iVar2 = (int)*(char *)(*(int *)(*(int *)(param_1 + 0x50) + 0x2c) + param_2 * 0x18 +
                         (int)*(char *)(param_1 + 0xad) + 0x12);
  if ((iVar2 < 0) || ((int)(uint)*(byte *)(*piVar1 + 0xf3) <= iVar2)) {
    FUN_80017970(piVar1,0);
  }
  else {
    FUN_80017970(piVar1,iVar2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointWorldPosition
 * EN v1.0 Address: 0x800388B4
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x80038524
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
    piVar2 = (int *)FUN_80017a54((int)puVar1);
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
        pfVar3 = (float *)FUN_80017970(piVar2,iVar4);
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
      *param_3 = local_b4 + FLOAT_803dda58;
      *param_4 = local_a4;
      *param_5 = local_94 + FLOAT_803dda5c;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: Obj_GetYawDeltaToObject
 * EN v1.0 Address: 0x80038A34
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x800386E0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int Obj_GetYawDeltaToObject(ushort *param_1,int param_2,float *param_3)
{
  int iVar1;
  double dVar2;
  double dVar3;
  
  dVar3 = (double)(*(float *)(param_1 + 6) - *(float *)(param_2 + 0xc));
  dVar2 = (double)(*(float *)(param_1 + 10) - *(float *)(param_2 + 0x14));
  iVar1 = FUN_80017730();
  if (param_3 != (float *)0x0) {
    dVar2 = FUN_80293900((double)(float)(dVar3 * dVar3 + (double)(float)(dVar2 * dVar2)));
    *param_3 = (float)dVar2;
  }
  iVar1 = (int)(short)iVar1 - (uint)*param_1;
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  return (int)(short)iVar1;
}

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
