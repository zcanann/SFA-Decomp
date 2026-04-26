#include "ghidra_import.h"
#include "main/dll/DR/gasvent.h"

extern undefined4 FUN_80006824();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80035d58();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_ClearSourceMask();
extern undefined4 ObjHits_SetSourceMask();
extern undefined4 ObjHits_ClearFlags();
extern undefined4 ObjHits_SetFlags();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern int FUN_80037008();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8013651c();
extern int FUN_8020a468();
extern undefined4 FUN_8020a90c();
extern uint FUN_80286838();
extern uint FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e4f90;
extern f64 DOUBLE_803e4f98;
extern f32 FLOAT_803e4f58;
extern f32 FLOAT_803e4f5c;
extern f32 FLOAT_803e4f74;
extern f32 FLOAT_803e4f78;
extern f32 FLOAT_803e4f7c;
extern f32 FLOAT_803e4f80;
extern f32 FLOAT_803e4f84;
extern f32 FLOAT_803e4f88;
extern f32 FLOAT_803e4fa0;

/*
 * --INFO--
 *
 * Function: FUN_801a1230
 * EN v1.0 Address: 0x801A1230
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801A1380
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1230(int param_1,char param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(param_1 + 0x54);
  if (param_2 == '\0') {
    *(undefined *)(iVar1 + 0x6a) = *(undefined *)(*(int *)(param_1 + 0x50) + 99);
    *(undefined *)(iVar1 + 0x6b) = *(undefined *)(*(int *)(param_1 + 0x50) + 100);
    *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0x7f;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    ObjHits_ClearFlags(param_1,0x400);
    *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) | 1;
  }
  else {
    *(undefined *)(iVar1 + 0x6a) = 1;
    *(undefined *)(iVar1 + 0x6b) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0x7f | 0x80;
    *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) & 0xfd;
    ObjHits_SetFlags(param_1,0x480);
    ObjHits_ClearSourceMask(param_1,1);
    ObjHits_EnableObject(param_1);
    ObjHits_SyncObjectPositionIfDirty(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1310
 * EN v1.0 Address: 0x801A1310
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801A1474
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1310(int param_1,float *param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x15) != '\0') {
    return;
  }
  if (*(char *)(iVar1 + 0x17) != '\0') {
    return;
  }
  *(float *)(iVar1 + 0x24) = *(float *)(iVar1 + 0x24) + param_2[1];
  *(float *)(iVar1 + 0x20) = *(float *)(iVar1 + 0x20) + *param_2;
  *(float *)(iVar1 + 0x28) = *(float *)(iVar1 + 0x28) + param_2[2];
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) | 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a136c
 * EN v1.0 Address: 0x801A136C
 * EN v1.0 Size: 744b
 * EN v1.1 Address: 0x801A14D4
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a136c(undefined4 param_1,undefined4 param_2,short param_3)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  short extraout_r4;
  uint uVar5;
  short sVar6;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_68 [2];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar2 = FUN_80286840();
  local_68[0] = FLOAT_803e4f78;
  iVar3 = FUN_80017a98();
  iVar4 = FUN_80037008(0x1e,uVar2,local_68);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar3 + 0x10);
    if (fVar1 < FLOAT_803e4f58) {
      fVar1 = -fVar1;
    }
    if (FLOAT_803e4f7c <= fVar1) {
      dVar10 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(uVar2 + 0xc));
      dVar9 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(uVar2 + 0x10));
      dVar7 = (double)FLOAT_803e4f58;
      if (dVar9 <= dVar7) {
        dVar8 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(uVar2 + 0x14));
        if (dVar9 != dVar7) {
          dVar7 = (double)(float)((double)*(float *)(uVar2 + 0x28) / dVar9);
        }
        sVar6 = extraout_r4;
        if ((double)FLOAT_803e4f74 <= dVar7) {
          FUN_80006824(uVar2,0xd2);
          dVar7 = (double)FLOAT_803e4f74;
          *(float *)(uVar2 + 0x28) = (float)dVar9;
          fVar1 = FLOAT_803e4f80;
          *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) + FLOAT_803e4f80;
          *(float *)(iVar4 + 0x2c) = *(float *)(iVar4 + 0x2c) + fVar1;
          if (FLOAT_803e4f84 < *(float *)(iVar4 + 0x2c)) {
            *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) - *(float *)(iVar4 + 0x2c);
            *(float *)(iVar4 + 0x2c) = FLOAT_803e4f58;
          }
          *(undefined2 *)(uVar2 + 2) = 0;
          *(undefined2 *)(uVar2 + 4) = 0;
          sVar6 = 0;
          param_3 = 0;
        }
        *(float *)(uVar2 + 0x24) = (float)(dVar10 * dVar7);
        *(float *)(uVar2 + 0x2c) = (float)(dVar8 * dVar7);
        uVar5 = (uint)sVar6;
        if (uVar5 != 0) {
          if (uVar5 == 1) {
            local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 2));
            fVar1 = (float)((double)(FLOAT_803e4f88 - (float)(local_60 - DOUBLE_803e4f90)) * dVar7);
          }
          else {
            local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 2));
            fVar1 = (float)(local_60 - DOUBLE_803e4f90) *
                    (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000)
                                                   - DOUBLE_803e4f98));
          }
          uStack_54 = (int)*(short *)(uVar2 + 2) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e4f98) + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(uVar2 + 2) = (short)iVar3;
        }
        uVar5 = (uint)param_3;
        if (uVar5 != 0) {
          fVar1 = FLOAT_803e4f58;
          if (uVar5 != 1) {
            local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
            fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 4)) -
                           DOUBLE_803e4f90) *
                    (float)(dVar7 * (double)(float)(local_60 - DOUBLE_803e4f98));
          }
          uStack_54 = (int)*(short *)(uVar2 + 4) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e4f98) + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(uVar2 + 4) = (short)iVar3;
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1654
 * EN v1.0 Address: 0x801A1654
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x801A17AC
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1654(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_58;
  undefined4 auStack_54 [11];
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar1 = FUN_80286838();
  iVar8 = *(int *)(uVar1 + 0xb8);
  iVar2 = ObjHits_GetPriorityHit(uVar1,auStack_54,(int *)0x0,(uint *)0x0);
  if ((iVar2 != 0) ||
     ((*(char *)(*(int *)(uVar1 + 0x54) + 0xad) != '\0' && ((*(byte *)(iVar8 + 0x49) & 2) != 0)))) {
    *(char *)(iVar8 + 0x16) = *(char *)(iVar8 + 0x16) + '\x01';
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) | 1;
  }
  if (*(char *)(iVar8 + 0x16) != '\0') {
    if ((*(byte *)(iVar8 + 0x48) >> 6 & 1) != 0) {
      iVar6 = *(int *)(uVar1 + 0x4c);
      iVar2 = 0;
      if (*(short *)(iVar6 + 0x1a) == 0) {
        iVar2 = FUN_80037008(0x3a,uVar1,(float *)0x0);
      }
      else {
        piVar3 = ObjGroup_GetObjects(0x3a,&local_58);
        piVar5 = piVar3;
        for (iVar7 = 0; iVar7 < local_58; iVar7 = iVar7 + 1) {
          iVar4 = FUN_8020a468(*piVar5);
          if (*(short *)(iVar6 + 0x1a) == iVar4) {
            iVar2 = piVar3[iVar7];
            break;
          }
          piVar5 = piVar5 + 1;
        }
      }
      if (iVar2 != 0) {
        dVar11 = (double)*(float *)(uVar1 + 0xc);
        dVar10 = (double)*(float *)(uVar1 + 0x10);
        dVar9 = (double)*(float *)(uVar1 + 0x14);
        *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
        *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
        *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
        FUN_800e8630(uVar1);
        *(float *)(uVar1 + 0xc) = (float)dVar11;
        *(float *)(uVar1 + 0x10) = (float)dVar10;
        *(float *)(uVar1 + 0x14) = (float)dVar9;
      }
    }
    ObjHits_ClearFlags(uVar1,0x80);
    ObjHits_SetSourceMask(uVar1,1);
    FUN_80035d58(uVar1,0x14,-5,0x14);
    ObjHits_EnableObject(uVar1);
    ObjHits_MarkObjectPositionDirty(uVar1);
    ObjHits_SetHitVolumeSlot(uVar1,5,4,0);
    FUN_80006824(uVar1,0xd1);
    *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) + FLOAT_803e4fa0;
    FUN_8008112c((double)FLOAT_803e4f58,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,1,1,0,0,0,1,0);
    if (*(char *)(iVar8 + 0x15) != '\0') {
      (**(code **)(*DAT_803dd740 + 0x30))(uVar1,iVar8);
      *(undefined *)(iVar8 + 0x15) = 0;
    }
    *(undefined *)(iVar8 + 0x17) = 1;
    *(byte *)(iVar8 + 0x4a) = *(byte *)(iVar8 + 0x4a) & 0xdf;
    ObjGroup_RemoveObject(uVar1,0x19);
    if (*(int *)(uVar1 + 0x30) == 0) {
      *(float *)(iVar8 + 0x34) = FLOAT_803e4f5c;
    }
    else {
      *(float *)(iVar8 + 0x34) = FLOAT_803e4f5c;
    }
    iVar2 = FUN_80017a90();
    if (iVar2 != 0) {
      FUN_8013651c(iVar2);
    }
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) & 0xfd;
    if (*(int *)(iVar8 + 0x10) != 0) {
      FUN_8020a90c(*(int *)(iVar8 + 0x10));
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_getExtraSize
 * EN v1.0 Address: 0x801A1894
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int gunpowderbarrel_getExtraSize(void)
{
  return 0x58;
}
