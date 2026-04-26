#include "ghidra_import.h"
#include "main/dll/DR/cannontargetControl.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8001777c();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ad0();
extern undefined4 FUN_80035d58();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern undefined4 ObjHits_RefreshObjectState();
extern undefined4 ObjHits_AddContactObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern int FUN_80037d50();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_8003b818();
extern int FUN_8005b398();
extern int FUN_80061a78();
extern undefined4 FUN_80061a80();
extern int FUN_800620e8();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8019f1dc();
extern undefined4 FUN_801a1230();
extern undefined4 FUN_801a136c();
extern undefined4 FUN_801a1654();
extern int FUN_8020a468();
extern undefined4 FUN_8020a470();
extern undefined4 FUN_8020a90c();
extern undefined4 FUN_8020a910();
extern uint FUN_8020a914();
extern byte FUN_8020a91c();
extern double FUN_80247f54();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294c20();
extern double FUN_80294c6c();
extern uint FUN_80294ce8();
extern uint FUN_80294cf0();
extern uint FUN_80294db4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e4f90;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dcae8;
extern f32 FLOAT_803dcaec;
extern f32 FLOAT_803dcaf0;
extern f32 FLOAT_803e4f58;
extern f32 FLOAT_803e4f74;
extern f32 FLOAT_803e4fa4;
extern f32 FLOAT_803e4fa8;
extern f32 FLOAT_803e4fac;
extern f32 FLOAT_803e4fb0;
extern f32 FLOAT_803e4fb4;
extern f32 FLOAT_803e4fb8;
extern f32 FLOAT_803e4fbc;
extern f32 FLOAT_803e4fc0;
extern f32 FLOAT_803e4fc8;
extern f32 FLOAT_803e4fcc;
extern f32 FLOAT_803e4fd0;

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_hitDetect
 * EN v1.0 Address: 0x801A1A60
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801A1A78
 * EN v1.1 Size: 984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gunpowderbarrel_hitDetect(uint param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  float local_18;
  int local_14 [3];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar5 + 0x4a) >> 5 & 1) == 0) {
    iVar3 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
    if (iVar3 == -1) {
      if ((*(byte *)(iVar5 + 0x49) & 2) != 0) {
        *(undefined *)(iVar5 + 0x16) = 4;
      }
    }
    else {
      if ((*(char *)(iVar5 + 0x16) == '\0') &&
         (((*(byte *)(iVar5 + 0x49) & 2) != 0 || (FLOAT_803e4fa4 < *(float *)(iVar5 + 0x24))))) {
        ObjHits_SetHitVolumeSlot(param_1,0xe,1,0);
        ObjHits_EnableObject(param_1);
      }
      if (-1 < *(char *)(iVar5 + 0x4a)) {
        *(float *)(iVar5 + 0x24) = -(FLOAT_803e4fa8 * FLOAT_803dc074 - *(float *)(iVar5 + 0x24));
      }
      fVar1 = *(float *)(iVar5 + 0x20);
      fVar2 = FLOAT_803e4fac;
      if ((FLOAT_803e4fac <= fVar1) && (fVar2 = fVar1, FLOAT_803e4fb0 < fVar1)) {
        fVar2 = FLOAT_803e4fb0;
      }
      *(float *)(iVar5 + 0x20) = fVar2;
      fVar1 = *(float *)(iVar5 + 0x24);
      fVar2 = FLOAT_803e4fac;
      if ((FLOAT_803e4fac <= fVar1) && (fVar2 = fVar1, FLOAT_803e4fb0 < fVar1)) {
        fVar2 = FLOAT_803e4fb0;
      }
      *(float *)(iVar5 + 0x24) = fVar2;
      fVar1 = *(float *)(iVar5 + 0x28);
      fVar2 = FLOAT_803e4fac;
      if ((FLOAT_803e4fac <= fVar1) && (fVar2 = fVar1, FLOAT_803e4fb0 < fVar1)) {
        fVar2 = FLOAT_803e4fb0;
      }
      *(float *)(iVar5 + 0x28) = fVar2;
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar5 + 0x20);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(iVar5 + 0x24);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(iVar5 + 0x28);
      FUN_80017a88((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
                   (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
                   (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
      *(byte *)(iVar5 + 0x4a) = *(byte *)(iVar5 + 0x4a) & 0xef;
      if ((*(byte *)(iVar5 + 0x49) & 2) == 0) {
        dVar6 = (double)*(float *)(param_1 + 0x84);
        dVar7 = (double)*(float *)(param_1 + 0x10);
        if (dVar6 < dVar7) {
          dVar7 = (double)(float)(dVar7 + (double)FLOAT_803e4fb0);
        }
        else {
          dVar6 = (double)(float)(dVar6 + (double)FLOAT_803e4fb0);
        }
        iVar3 = FUN_80061a78((double)*(float *)(param_1 + 0xc),dVar6,
                             (double)*(float *)(param_1 + 0x14),dVar7,param_1,&local_18,local_14);
        if (iVar3 != 0) {
          if (iVar3 == 2) {
            *(undefined *)(iVar5 + 0x16) = 4;
          }
          else {
            if (*(char *)(iVar5 + 0x58) == '\0') {
              if ((*(byte *)(iVar5 + 0x4a) >> 3 & 1) == 0) {
                *(byte *)(iVar5 + 0x4a) = *(byte *)(iVar5 + 0x4a) & 0xf7 | 8;
              }
              else {
                FUN_80006824(param_1,0xd2);
              }
            }
            *(byte *)(iVar5 + 0x4a) = *(byte *)(iVar5 + 0x4a) & 0xef | 0x10;
            *(float *)(param_1 + 0x10) = local_18;
          }
        }
      }
      fVar1 = FLOAT_803e4f58;
      if ((*(byte *)(iVar5 + 0x4a) >> 4 & 1) == 0) {
        if (*(float *)(iVar5 + 0x24) < FLOAT_803e4fb8) {
          FUN_801a136c(param_1,(int)*(short *)(iVar5 + 0x44),*(short *)(iVar5 + 0x46));
        }
        if ((((*(byte *)(iVar5 + 0x4a) >> 5 & 1) == 0) && (-1 < (char)*(byte *)(iVar5 + 0x4a))) &&
           (*(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x38) + *(float *)(param_1 + 0x28),
           *(float *)(iVar5 + 0x38) < -FLOAT_803dcaf0)) {
          *(undefined *)(iVar5 + 0x16) = 4;
        }
      }
      else {
        *(float *)(param_1 + 0x24) = FLOAT_803e4f58;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
        *(float *)(iVar5 + 0x20) = fVar1;
        *(float *)(iVar5 + 0x24) = fVar1;
        *(float *)(iVar5 + 0x28) = fVar1;
        if (local_14[0] != 0) {
          ObjHits_AddContactObject(local_14[0],param_1);
          uVar4 = *(uint *)(*(int *)(local_14[0] + 0x50) + 0x44);
          if (((uVar4 & 0x40) == 0) || ((uVar4 & 0x8000) != 0)) {
            if (*(float *)(iVar5 + 0x38) < FLOAT_803e4fb4) {
              *(undefined *)(iVar5 + 0x16) = 4;
            }
          }
          else {
            *(int *)(iVar5 + 0xc) = local_14[0];
          }
        }
        if (*(char *)(iVar5 + 0x4a) < '\0') {
          FUN_801a1230(param_1,'\0');
        }
        *(float *)(iVar5 + 0x38) = FLOAT_803e4f58;
      }
      if ((*(byte *)(iVar5 + 0x4a) >> 4 & 1) == 0) {
        iVar3 = *(char *)(iVar5 + 0x58) + -1;
        if (iVar3 < 0) {
          iVar3 = 0;
        }
        *(char *)(iVar5 + 0x58) = (char)iVar3;
      }
      else {
        *(undefined *)(iVar5 + 0x58) = 3;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1df8
 * EN v1.0 Address: 0x801A1DF8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801A1E50
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1df8(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd740 + 0x10))();
  if (((*(int *)(iVar2 + 0x10) != 0) && (param_2 == 0)) &&
     (iVar1 = FUN_80037d50(*(int *)(iVar2 + 0x10)), iVar1 != 0)) {
    ObjLink_DetachChild(param_1,*(int *)(iVar2 + 0x10));
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  ObjGroup_RemoveObject(param_1,0x19);
  ObjGroup_RemoveObject(param_1,0x16);
  if (*(char *)(iVar2 + 0x17) != '\0') {
    (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1ec4
 * EN v1.0 Address: 0x801A1EC4
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801A1F14
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1ec4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar2 + 0xb8);
  if ((*(char *)(iVar3 + 0x17) == '\0') && ((*(byte *)(iVar3 + 0x4a) >> 5 & 1) == 0)) {
    if (*(char *)(iVar3 + 0x15) != '\0') {
      *(undefined2 *)(iVar2 + 4) = 0;
      *(undefined2 *)(iVar2 + 2) = 0;
    }
    iVar1 = (**(code **)(*DAT_803dd740 + 0xc))(iVar2,(int)(char)param_6);
    if ((iVar1 != 0) || ((char)param_6 == -1)) {
      FUN_8003b818(iVar2);
    }
    iVar2 = *(int *)(iVar3 + 0x10);
    if (iVar2 != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x10))
                (iVar2,(int)uVar4,param_3,param_4,param_5,param_6);
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: blasted_getExtraSize
 * EN v1.0 Address: 0x801A24A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801A2690
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int blasted_getExtraSize(void)
{
  return 0x14;
}

/*
 * --INFO--
 *
 * Function: blasted_func08
 * EN v1.0 Address: 0x801A24B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801A2698
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int blasted_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: blasted_free
 * EN v1.0 Address: 0x801A24B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A26A0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void blasted_free(void)
{
}

/*
 * --INFO--
 *
 * Function: blasted_hitDetect
 * EN v1.0 Address: 0x801A24FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A26E4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void blasted_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a1fb8
 * EN v1.0 Address: 0x801A1FB8
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801A2014
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1fb8(int *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  float local_80;
  undefined4 local_7c;
  undefined4 local_78;
  float local_74;
  float local_70;
  float local_6c;
  int aiStack_68 [7];
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  char local_17;
  
  iVar6 = param_1[0x2e];
  iVar4 = FUN_80037d50(*(int *)(iVar6 + 0x10));
  if ((iVar4 == 0) && (*(int *)(iVar6 + 0x10) != 0)) {
    ObjLink_DetachChild((int)param_1,*(int *)(iVar6 + 0x10));
    *(undefined4 *)(iVar6 + 0x10) = 0;
  }
  if (((*(char *)(iVar6 + 0x17) == '\0') &&
      (uVar5 = FUN_8007f6c8((float *)(iVar6 + 0x18)), uVar5 == 0)) &&
     (uVar5 = FUN_8007f6c8((float *)(iVar6 + 0x1c)), uVar5 == 0)) {
    if (*(short **)(iVar6 + 0xc) != (short *)0x0) {
      FUN_80061a80((short *)param_1,*(short **)(iVar6 + 0xc),1);
      *(undefined4 *)(iVar6 + 0xc) = 0;
    }
    if (*(char *)(iVar6 + 0x4a) < '\0') {
      fVar1 = (float)param_1[4];
      fVar2 = (float)param_1[0x21];
      fVar3 = FLOAT_803e4fbc * FLOAT_803dc078;
      local_74 = ((float)param_1[3] - (float)param_1[0x20]) * fVar3;
      local_6c = ((float)param_1[5] - (float)param_1[0x22]) * fVar3;
      *(float *)(iVar6 + 0x20) = local_74 + *(float *)(iVar6 + 0x20);
      *(float *)(iVar6 + 0x24) = (fVar1 - fVar2) * fVar3 + *(float *)(iVar6 + 0x24);
      *(float *)(iVar6 + 0x28) = local_6c + *(float *)(iVar6 + 0x28);
      fVar2 = FLOAT_803e4fc0;
      fVar1 = FLOAT_803e4f58;
      local_70 = FLOAT_803e4f58;
      *(float *)(iVar6 + 0x20) = FLOAT_803e4fc0 * *(float *)(iVar6 + 0x20);
      *(float *)(iVar6 + 0x24) = fVar2 * *(float *)(iVar6 + 0x24);
      *(float *)(iVar6 + 0x28) = fVar2 * *(float *)(iVar6 + 0x28);
      *(float *)(iVar6 + 0x24) = fVar1;
      *(byte *)(iVar6 + 0x49) = *(byte *)(iVar6 + 0x49) | 1;
    }
    if ((*(char *)(iVar6 + 0x15) == '\0') &&
       (iVar4 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x1,aiStack_68,param_1,8,0xffffffff
                             ,0xff,0), iVar4 != 0)) {
      if (local_17 == '\x14') {
        *(undefined *)(iVar6 + 0x16) = 4;
      }
      if ((*(char *)(iVar6 + 0x4a) < '\0') && (local_17 == '\x03')) {
        FUN_801a1230((int)param_1,'\0');
        ObjGroup_RemoveObject((int)param_1,0x16);
      }
      else {
        local_80 = local_4c;
        local_7c = local_48;
        local_78 = local_44;
        FUN_8001777c(&local_80,(float *)(param_1 + 9),(float *)(param_1 + 9));
        FUN_8001777c(&local_80,(float *)(iVar6 + 0x20),(float *)(iVar6 + 0x20));
        fVar1 = FLOAT_803e4fc8;
        param_1[9] = (int)(FLOAT_803e4fc8 * (float)param_1[9]);
        param_1[10] = (int)(fVar1 * (float)param_1[10]);
        param_1[0xb] = (int)(fVar1 * (float)param_1[0xb]);
        *(float *)(iVar6 + 0x20) = fVar1 * *(float *)(iVar6 + 0x20);
        *(float *)(iVar6 + 0x24) = fVar1 * *(float *)(iVar6 + 0x24);
        *(float *)(iVar6 + 0x28) = fVar1 * *(float *)(iVar6 + 0x28);
        if (FLOAT_803e4fcc < *(float *)(iVar6 + 0x54)) {
          dVar7 = FUN_80247f54((float *)(iVar6 + 0x20));
          if ((double)FLOAT_803dcaec < dVar7) {
            FUN_80006824((uint)param_1,0x446);
          }
          *(float *)(iVar6 + 0x54) = FLOAT_803e4f58;
        }
      }
    }
    param_1[0x20] = param_1[3];
    param_1[0x21] = param_1[4];
    param_1[0x22] = param_1[5];
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a2350
 * EN v1.0 Address: 0x801A2350
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x801A22FC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a2350(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  uint uVar2;
  short *psVar3;
  uint uVar4;
  byte bVar8;
  int iVar5;
  int *piVar6;
  int iVar7;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  double dVar14;
  int local_58;
  uint local_54;
  uint local_50;
  float local_4c [2];
  uint uStack_44;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  uVar2 = FUN_80286838();
  iVar12 = *(int *)(uVar2 + 0xb8);
  psVar3 = (short *)FUN_80017a98();
  iVar10 = *(int *)(uVar2 + 0x4c);
  if (*(float *)(iVar12 + 0x54) <= FLOAT_803e4fcc) {
    *(float *)(iVar12 + 0x54) = *(float *)(iVar12 + 0x54) + FLOAT_803dc074;
  }
  uVar4 = FUN_8007f6c8((float *)(iVar12 + 0x18));
  if (uVar4 == 0) {
    uVar4 = FUN_8007f6c8((float *)(iVar12 + 0x1c));
    if (uVar4 == 0) {
      if ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0) {
        if (((*(byte *)(iVar12 + 0x4a) >> 2 & 1) == 0) ||
           (bVar8 = FUN_80294c20((int)psVar3), bVar8 != 0)) {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) & 0xef;
        }
        else {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 0x10;
        }
      }
      if (*(int *)(uVar2 + 200) == 0) {
        local_4c[0] = FLOAT_803e4fd0;
        iVar5 = ObjGroup_FindNearestObject(0x4c,uVar2,local_4c);
        *(int *)(iVar12 + 0x10) = iVar5;
        if (((iVar5 != 0) && (uVar4 = FUN_8020a914(*(int *)(iVar12 + 0x10)), uVar4 != 0)) &&
           (*(int *)(*(int *)(iVar12 + 0x10) + 0xc4) == 0)) {
          ObjLink_AttachChild(uVar2,*(int *)(iVar12 + 0x10),0);
        }
      }
      else {
        iVar5 = FUN_80037d50(*(int *)(iVar12 + 0x10));
        if ((iVar5 == 0) && (*(int *)(iVar12 + 0x10) != 0)) {
          ObjLink_DetachChild(uVar2,*(int *)(iVar12 + 0x10));
          *(undefined4 *)(iVar12 + 0x10) = 0;
        }
      }
      local_54 = 0;
      local_50 = 0;
      while (iVar5 = ObjMsg_Pop(uVar2,&local_54,(uint *)0x0,&local_50), iVar5 != 0) {
        if (local_54 == 0x10) {
          FUN_801a1230(uVar2,'\0');
          if (local_50 != 0) {
            ObjGroup_AddObject(uVar2,0x16);
          }
        }
        else if (((int)local_54 < 0x10) && (0xe < (int)local_54)) {
          FUN_801a1230(uVar2,'\x01');
        }
      }
      if ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0) {
        *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) & 0xf7;
      }
      else {
        *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
      }
      if (*(char *)(iVar12 + 0x17) == '\0') {
        if (*(char *)(iVar12 + 0x15) == '\0') {
          if ((((*(byte *)(iVar12 + 0x48) >> 6 & 1) != 0) &&
              ((*(byte *)(iVar12 + 0x4a) >> 4 & 1) != 0)) && ((*(byte *)(iVar12 + 0x49) & 2) == 0))
          {
            FUN_800e8630(uVar2);
          }
        }
        else {
          uVar4 = FUN_80294db4((int)psVar3);
          if ((uVar4 & 0x4000) == 0) {
            FUN_8011e868(4);
          }
          else {
            FUN_8011e868(5);
          }
        }
        if (((((*(byte *)(iVar12 + 0x49) & 2) == 0) && ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0))
            && (iVar10 = (**(code **)(*DAT_803dd740 + 8))(uVar2,iVar12), iVar10 != 0)) &&
           ((uVar13 = extraout_f1, (*(byte *)(iVar12 + 0x4a) >> 2 & 1) == 0 ||
            (bVar8 = FUN_80294c20((int)psVar3), bVar8 != 0)))) {
          *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) | 1;
          if (*(char *)(iVar12 + 0x15) == '\0') {
            if (*(int *)(iVar12 + 0x10) != 0) {
              FUN_8020a910(*(int *)(iVar12 + 0x10));
            }
            uVar13 = ObjGroup_RemoveObject(uVar2,0x16);
          }
          *(undefined *)(iVar12 + 0x15) = 1;
          *(byte *)(iVar12 + 0x4a) = *(byte *)(iVar12 + 0x4a) & 0xbf | 0x40;
          *(short *)(iVar12 + 0x50) = *psVar3;
          FUN_801a1654(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else {
          uVar13 = ObjHits_EnableObject(uVar2);
          FUN_801a1654(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          *(undefined *)(uVar2 + 0x36) = 0xff;
          if (*(char *)(iVar12 + 0x15) != '\0') {
            *(undefined *)(iVar12 + 0x15) = 0;
            uVar4 = FUN_80294cf0((int)psVar3);
            if (uVar4 == 0) {
              uVar4 = FUN_80294ce8((int)psVar3);
              if (uVar4 == 0) {
                dVar14 = FUN_80294c6c((int)psVar3);
                if ((double)FLOAT_803e4f58 == dVar14) {
                  ObjHits_SyncObjectPositionIfDirty(uVar2);
                  FUN_8019f1dc();
                }
                else if (*(char *)(iVar12 + 0x17) == '\0') {
                  local_30 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80293f90();
                  *(float *)(iVar12 + 0x20) = (float)dVar14;
                  *(float *)(uVar2 + 0x24) = (float)dVar14;
                  fVar1 = FLOAT_803e4f58;
                  *(float *)(iVar12 + 0x24) = FLOAT_803e4f58;
                  *(float *)(uVar2 + 0x28) = fVar1;
                  local_38 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80294964();
                  *(float *)(iVar12 + 0x28) = (float)dVar14;
                  *(float *)(uVar2 + 0x2c) = (float)dVar14;
                  local_40 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80293f90();
                  *(float *)(uVar2 + 0xc) =
                       (float)((double)FLOAT_803dcae8 * -dVar14 + (double)*(float *)(uVar2 + 0xc));
                  uStack_44 = (int)*psVar3 ^ 0x80000000;
                  local_4c[1] = 176.0;
                  dVar14 = (double)FUN_80294964();
                  *(float *)(uVar2 + 0x14) =
                       (float)((double)FLOAT_803dcae8 * -dVar14 + (double)*(float *)(uVar2 + 0x14));
                  ObjGroup_AddObject(uVar2,0x16);
                }
              }
              else {
                ObjHits_MarkObjectPositionDirty(uVar2);
                FUN_8019f1dc();
              }
            }
            else {
              ObjHits_SyncObjectPositionIfDirty(uVar2);
            }
            ObjGroup_AddObject(uVar2,0x16);
          }
          gunpowderbarrel_hitDetect(uVar2);
        }
        if (*(char *)(iVar12 + 0x4a) < '\0') {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
          if (((*(byte *)(iVar12 + 0x4a) >> 6 & 1) != 0) && ((char)*(byte *)(iVar12 + 0x4a) < '\0'))
          {
            *(undefined4 *)(iVar12 + 0x20) = *(undefined4 *)(uVar2 + 0x24);
            *(undefined4 *)(iVar12 + 0x24) = *(undefined4 *)(uVar2 + 0x28);
            *(undefined4 *)(iVar12 + 0x28) = *(undefined4 *)(uVar2 + 0x2c);
            *(float *)(iVar12 + 0x24) = FLOAT_803e4f58;
            *(byte *)(iVar12 + 0x4a) = *(byte *)(iVar12 + 0x4a) & 0xbf;
          }
        }
        if ((*(int *)(iVar12 + 0x10) != 0) &&
           (bVar8 = FUN_8020a91c(*(int *)(iVar12 + 0x10)), bVar8 != 0)) {
          *(undefined *)(iVar12 + 0x16) = 10;
        }
      }
      else {
        *(char *)(iVar12 + 0x17) = *(char *)(iVar12 + 0x17) + DAT_803dc070;
        uStack_44 = (uint)*(byte *)(iVar12 + 0x17);
        local_4c[1] = 176.0;
        *(float *)(iVar12 + 0x2c) =
             *(float *)(iVar12 + 0x34) *
             (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4f90) + FLOAT_803e4f74;
        fVar1 = *(float *)(iVar12 + 0x2c);
        local_40 = (longlong)(int)fVar1;
        local_38 = (longlong)(int)(-fVar1 * FLOAT_803e4fc0);
        local_30 = (longlong)(int)(fVar1 * FLOAT_803e4fc0);
        FUN_80035d58(uVar2,(short)(int)fVar1,(short)(int)(-fVar1 * FLOAT_803e4fc0),
                     (short)(int)(fVar1 * FLOAT_803e4fc0));
        if (*(int *)(iVar12 + 0x10) != 0) {
          FUN_8020a90c(*(int *)(iVar12 + 0x10));
        }
        if (0x14 < *(byte *)(iVar12 + 0x17)) {
          if (*(char *)(iVar12 + 0x4a) < '\0') {
            FUN_801a1230(uVar2,'\0');
          }
          iVar5 = 0;
          if (*(short *)(iVar10 + 0x1a) == 0) {
            iVar5 = ObjGroup_FindNearestObject(0x3a,uVar2,(float *)0x0);
          }
          else {
            piVar6 = ObjGroup_GetObjects(0x3a,&local_58);
            piVar9 = piVar6;
            for (iVar11 = 0; iVar11 < local_58; iVar11 = iVar11 + 1) {
              iVar7 = FUN_8020a468(*piVar9);
              if (*(short *)(iVar10 + 0x1a) == iVar7) {
                iVar5 = piVar6[iVar11];
                break;
              }
              piVar9 = piVar9 + 1;
            }
          }
          if (iVar5 == 0) {
            FUN_80017ad0(uVar2);
            ObjHits_DisableObject(uVar2);
            *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            FUN_8007f718((float *)(iVar12 + 0x18),0x3c);
          }
          else {
            FUN_800033a8(iVar12 + 0x20,0,0xc);
            FUN_800033a8(uVar2 + 0x24,0,0xc);
            *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) & 0xfd;
            ObjHits_RefreshObjectState(uVar2);
            if (*(char *)(iVar12 + 0x48) < '\0') {
              FUN_8007f718((float *)(iVar12 + 0x18),0x3c);
              FUN_8007f6e4((undefined4 *)(iVar12 + 0x1c));
              FUN_8007f718((float *)(iVar12 + 0x1c),0x5a);
              FUN_8020a470(iVar5,uVar2,0x46);
              ObjHits_ClearHitVolumes(uVar2);
              ObjHits_DisableObject(uVar2);
              *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            }
            else {
              FUN_80017ad0(uVar2);
              ObjHits_DisableObject(uVar2);
              *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            }
          }
        }
      }
    }
    else {
      *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
      FUN_8007f764((float *)(iVar12 + 0x1c));
      FUN_800033a8(iVar12 + 0x20,0,0xc);
      FUN_800033a8(uVar2 + 0x24,0,0xc);
    }
  }
  else {
    *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    iVar10 = FUN_8007f764((float *)(iVar12 + 0x18));
    if (iVar10 != 0) {
      *(undefined *)(iVar12 + 0x17) = 0;
      *(undefined *)(iVar12 + 0x16) = 0;
      *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) | 1;
      *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) & 0xbfff;
      ObjHits_ClearHitVolumes(uVar2);
      FUN_80035d58(uVar2,8,-2,0x19);
      ObjHits_EnableObject(uVar2);
      ObjHits_SyncObjectPositionIfDirty(uVar2);
      gunpowderbarrel_hitDetect(uVar2);
      FUN_801a1230(uVar2,'\0');
    }
  }
  FUN_80286884();
  return;
}
