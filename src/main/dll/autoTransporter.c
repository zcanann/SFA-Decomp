#include "ghidra_import.h"
#include "main/dll/autoTransporter.h"

extern undefined4 FUN_80006728();
extern bool FUN_800067f8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern void* FUN_800069a8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern int FUN_80017b00();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Peek();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToNearbyObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80081110();
extern int FUN_801778e0();
extern uint FUN_80286830();
extern undefined4 FUN_8028687c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e42d8;
extern f32 lbl_803DC074;
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42C8;
extern f32 lbl_803E42CC;
extern f32 lbl_803E42D0;
extern f32 lbl_803E42E0;
extern f32 lbl_803E42EC;
extern f32 lbl_803E42F0;
extern f32 lbl_803E42F4;
extern f32 lbl_803E42F8;
extern f32 lbl_803E42FC;
extern f32 lbl_803E4300;
extern f32 lbl_803E4304;
extern f32 lbl_803E4308;
extern f32 lbl_803E430C;
extern f32 lbl_803E431C;

/*
 * --INFO--
 *
 * Function: FUN_80178338
 * EN v1.0 Address: 0x80178338
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80178648
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80178338(undefined4 param_1)
{
  float local_18;
  float local_14;
  float local_10;
  
  local_18 = lbl_803E42B0;
  local_14 = lbl_803E42B8;
  local_10 = lbl_803E42B0;
  FUN_80081110(param_1,2,0,0,&local_18);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80178370
 * EN v1.0 Address: 0x80178370
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x801786A0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80178370(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_9 + 0xb8);
  *pfVar2 = *pfVar2 + lbl_803DC074;
  dVar3 = (double)*pfVar2;
  if (dVar3 <= (double)lbl_803E42C8) {
    if (((double)lbl_803E42CC < dVar3) && (*(char *)((int)pfVar2 + 0x11) == '\0')) {
      ObjHits_SetHitVolumeSlot(param_9,0x1a,1,0);
    }
  }
  else {
    *pfVar2 = (float)(dVar3 - (double)lbl_803E42C8);
    iVar1 = FUN_801778e0(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         (int)pfVar2);
    if (iVar1 == 0) {
      return;
    }
  }
  *(float *)(param_9 + 0xc) = *(float *)(param_9 + 0x24) * *pfVar2 + pfVar2[1];
  *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x28) * *pfVar2 + pfVar2[2];
  *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x2c) * *pfVar2 + pfVar2[3];
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801784ac
 * EN v1.0 Address: 0x801784AC
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x80178774
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801784ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_9 + 0xb8);
  FUN_801778e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,(int)pfVar1);
  *pfVar1 = lbl_803E42D0 *
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_10 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e42d8);
  *(undefined *)((int)pfVar1 + 0x11) = 2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80178560
 * EN v1.0 Address: 0x80178560
 * EN v1.0 Size: 4700b
 * EN v1.1 Address: 0x801787E4
 * EN v1.1 Size: 3228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80178560(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  short sVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  bool bVar11;
  undefined2 *puVar10;
  int *piVar12;
  int unaff_r25;
  float *pfVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double in_f29;
  double in_f30;
  double dVar20;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_78;
  int local_74;
  uint local_70 [2];
  undefined4 local_68;
  uint uStack_64;
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
  uVar4 = FUN_80286830();
  iVar14 = *(int *)(uVar4 + 0x4c);
  pfVar13 = *(float **)(uVar4 + 0xb8);
  dVar20 = (double)lbl_803E42E0;
  iVar5 = FUN_80017b00(&local_78,&local_74);
  *(undefined *)(param_11 + 0x56) = 0;
  iVar6 = FUN_80017a98();
  dVar16 = (double)(*(float *)(iVar6 + 0xc) - *(float *)(iVar14 + 8));
  fVar3 = *(float *)(iVar6 + 0x14) - *(float *)(iVar14 + 0x10);
  dVar15 = FUN_80293900((double)(float)(dVar16 * dVar16 + (double)(fVar3 * fVar3)));
  dVar18 = dVar15;
  if (pfVar13[4] == -NAN) {
    uVar7 = 1;
  }
  else {
    uVar7 = FUN_80017690((uint)pfVar13[4]);
  }
  iVar8 = ObjMsg_Peek(uVar4,(int *)local_70,(int *)0x0,(int *)0x0);
  if (iVar8 != 0) {
    if (local_70[0] == 0x30003) {
      *(undefined *)(pfVar13 + 8) = 0;
    }
    else if (((int)local_70[0] < 0x30003) && (0x30001 < (int)local_70[0])) {
      *(undefined *)(pfVar13 + 8) = 1;
    }
  }
  iVar8 = (int)*(char *)(pfVar13 + 8);
  switch(*(undefined *)(iVar14 + 0x19)) {
  case 0:
    uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar15 = (double)FUN_80293f90();
    dVar16 = (double)FUN_80294964();
    dVar19 = -(double)(float)((double)*(float *)(iVar14 + 8) * dVar15 +
                             (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar16));
    dVar17 = (double)*(float *)(iVar6 + 0xc);
    dVar20 = (double)(float)(dVar19 + (double)(float)(dVar15 * dVar17 +
                                                     (double)(float)(dVar16 * (double)*(float *)(
                                                  iVar6 + 0x14))));
    dVar15 = (double)pfVar13[3];
    if ((((dVar18 < dVar15) && (uVar7 != 0)) && (dVar20 < dVar15)) && (-dVar15 < dVar20)) {
      iVar8 = 1;
    }
    if ((iVar8 == 0) || (*(char *)((int)pfVar13 + 0x22) != '\0')) {
      if ((iVar8 == 0) && (*(char *)((int)pfVar13 + 0x22) == '\x01')) {
        if ((*(short *)(uVar4 + 0x46) == 200) && (dVar20 <= (double)lbl_803E42E0)) {
          FUN_80006728(dVar16,dVar17,dVar19,param_4,param_5,param_6,param_7,param_8,0,0,0xe,0,
                       param_13,param_14,param_15,param_16);
        }
        *(undefined *)((int)pfVar13 + 0x22) = 0;
      }
    }
    else {
      if (*(short *)(uVar4 + 0x46) == 200) {
        uVar7 = FUN_80017690(0x57);
        if (uVar7 == 0) {
          FUN_80006728(dVar16,dVar17,dVar19,param_4,param_5,param_6,param_7,param_8,0,0,0x7c,0,
                       param_13,param_14,param_15,param_16);
        }
        else {
          FUN_80006728(dVar16,dVar17,dVar19,param_4,param_5,param_6,param_7,param_8,0,0,0x7f,0,
                       param_13,param_14,param_15,param_16);
        }
      }
      *(undefined *)((int)pfVar13 + 0x22) = 1;
    }
    break;
  case 1:
    if ((dVar18 < (double)lbl_803E42EC) && (uVar7 != 0)) {
      uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
      local_68 = 0x43300000;
      dVar18 = (double)FUN_80293f90();
      dVar15 = (double)FUN_80294964();
      dVar20 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                                (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar15)) +
                       (float)(dVar18 * (double)*(float *)(iVar6 + 0xc) +
                              (double)(float)(dVar15 * (double)*(float *)(iVar6 + 0x14))));
      if (*(int *)(uVar4 + 0xf8) == 0) {
        if ((dVar20 < (double)lbl_803E42E0) && ((double)lbl_803E42F0 < dVar20)) {
          iVar8 = 1;
        }
      }
      else if ((dVar20 < (double)lbl_803E42F4) && ((double)lbl_803E42F0 < dVar20)) {
        iVar8 = 1;
      }
    }
    break;
  case 2:
    if (uVar7 != 0) {
      if (uVar7 != 0) {
        iVar8 = 1;
      }
    }
    else {
      if (((*(byte *)(uVar4 + 0xaf) & 8) != 0) && (uVar7 = FUN_80017690(0x2c), uVar7 != 0)) {
        *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) & 0xf7;
      }
      if ((*(byte *)(uVar4 + 0xaf) & 1) != 0) {
        *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
        FUN_80017698((uint)pfVar13[4],1);
      }
    }
    break;
  case 3:
    if ((dVar18 < (double)lbl_803E42EC) && (uVar7 != 0)) {
      uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
      local_68 = 0x43300000;
      dVar18 = (double)FUN_80293f90();
      dVar15 = (double)FUN_80294964();
      dVar20 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                                (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar15)) +
                       (float)(dVar18 * (double)*(float *)(iVar6 + 0xc) +
                              (double)(float)(dVar15 * (double)*(float *)(iVar6 + 0x14))));
      if ((dVar20 < (double)lbl_803E4304) && ((double)lbl_803E4308 < dVar20)) {
        iVar8 = 1;
      }
    }
    break;
  case 4:
    *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) & 0xf7;
    if (uVar7 != 0) {
      piVar12 = (int *)(iVar5 + local_78 * 4);
      iVar5 = local_78;
      while ((iVar5 < local_74 && (iVar8 == 0))) {
        unaff_r25 = *piVar12;
        if (*(short *)(unaff_r25 + 0x46) == 0x7c) {
          dVar16 = (double)(*(float *)(unaff_r25 + 0xc) - *(float *)(iVar14 + 8));
          fVar3 = *(float *)(unaff_r25 + 0x14) - *(float *)(iVar14 + 0x10);
          dVar15 = FUN_80293900((double)(float)(dVar16 * dVar16 + (double)(fVar3 * fVar3)));
          if (dVar15 < (double)lbl_803E42F8) {
            uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
            local_68 = 0x43300000;
            dVar18 = (double)FUN_80293f90();
            dVar15 = (double)FUN_80294964();
            param_3 = -(double)(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                                      (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar15));
            dVar16 = (double)*(float *)(unaff_r25 + 0xc);
            dVar20 = (double)(float)(param_3 +
                                    (double)(float)(dVar18 * dVar16 +
                                                   (double)(float)(dVar15 * (double)*(float *)(
                                                  unaff_r25 + 0x14))));
            if ((dVar20 < (double)lbl_803E42FC) && ((double)lbl_803E4300 < dVar20)) {
              iVar8 = 1;
            }
          }
        }
        piVar12 = piVar12 + 1;
        iVar5 = iVar5 + 1;
      }
      if (iVar8 == 0) {
        if (*(int *)(uVar4 + 0xf8) == 1) {
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 8;
        }
      }
      else {
        iVar5 = ObjMsg_Pop(uVar4,local_70,(uint *)0x0,(uint *)0x0);
        if (((iVar5 != 0) && ((int)local_70[0] < 10)) && (7 < (int)local_70[0])) {
          ObjMsg_SendToObject(dVar15,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,unaff_r25,
                       local_70[0],uVar4,0,param_13,param_14,param_15,param_16);
        }
        if ((dVar20 < (double)lbl_803E42E0) && (*(int *)(uVar4 + 0xf8) == 0)) {
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 0x14;
        }
      }
    }
    break;
  case 5:
    uVar9 = FUN_80017690((uint)pfVar13[5]);
    if ((uVar9 != 0) && (uVar7 == 0)) {
      *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) & 0xf7;
      if ((*(byte *)(uVar4 + 0xaf) & 1) != 0) {
        *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
        FUN_80017698((uint)pfVar13[4],1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar4,0xffffffff);
        uVar7 = 1;
      }
    }
    if (uVar7 != 0) {
      iVar8 = 1;
      *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
    }
    break;
  case 6:
    if (uVar7 != 0) {
      iVar8 = 1;
    }
  }
  if (*(int *)(uVar4 + 0xf8) == 0) {
    if (iVar8 != 0) {
      *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 1;
    }
  }
  else if (iVar8 == 0) {
    *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 2;
  }
  *(int *)(uVar4 + 0xf8) = iVar8;
  if (((*(short *)(uVar4 + 0x46) == 0x13e) || (*(short *)(uVar4 + 0x46) == 0x151)) &&
     (*(char *)((int)pfVar13 + 0x21) != '\0')) {
    *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 1;
  }
  do {
    iVar5 = ObjMsg_Pop(uVar4,local_70,(uint *)0x0,(uint *)0x0);
  } while (iVar5 != 0);
  iVar5 = 0;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar5) {
      if (*(int *)(uVar4 + 0xf4) != 0) {
        *(undefined4 *)(uVar4 + 0xf4) = 0;
      }
      FUN_8028687c();
      return;
    }
    bVar1 = *(byte *)(param_11 + iVar5 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 3) {
LAB_80179188:
        if (*(ushort *)(pfVar13 + 7) != 0) {
          FUN_80006824(uVar4,*(ushort *)(pfVar13 + 7));
        }
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          puVar10 = FUN_800069a8();
          dVar16 = (double)pfVar13[2];
          dVar15 = (double)*pfVar13;
          dVar18 = (double)*(float *)(puVar10 + 6);
          if (lbl_803E42E0 <=
              (float)(dVar16 + (double)(float)(dVar15 * dVar18 +
                                              (double)(pfVar13[1] * *(float *)(puVar10 + 10))))) {
            if ((int)*(short *)(iVar14 + 0x1a) != 0xffffffff) {
              uVar7 = FUN_80017690((int)*(short *)(iVar14 + 0x1a));
              FUN_80017698((int)*(short *)(iVar14 + 0x1a),
                           uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) >> 8 & 0xffU);
            }
          }
          else if ((int)*(short *)(iVar14 + 0x20) != 0xffffffff) {
            uVar7 = FUN_80017690((int)*(short *)(iVar14 + 0x20));
            FUN_80017698((int)*(short *)(iVar14 + 0x20),
                         uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) & 0xffU);
          }
          if (dVar20 <= (double)lbl_803E42E0) {
            sVar2 = *(short *)(uVar4 + 0x46);
            if (sVar2 == 0x205) {
              ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x202,0,uVar4,0x30006,0,param_14,param_15,param_16);
            }
            else if (sVar2 < 0x205) {
              if (sVar2 == 0x1bb) {
                ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x1b9,0,uVar4,0x30006,0,param_14,param_15,param_16);
              }
              else if (sVar2 < 0x1bb) {
                if (sVar2 == 0x1ad) {
                  ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                               param_8,0x1ac,0,uVar4,0x30006,0,param_14,param_15,param_16);
                }
                else if ((sVar2 < 0x1ad) && (sVar2 == 0x1a2)) {
                  ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                               param_8,0x19c,0,uVar4,0x30006,0,param_14,param_15,param_16);
                }
              }
              else if (sVar2 == 0x1ea) {
                ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x1e7,0,uVar4,0x30006,0,param_14,param_15,param_16);
              }
            }
            else if (sVar2 == 0x238) {
              ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x233,0,uVar4,0x30006,0,param_14,param_15,param_16);
            }
            else if (sVar2 < 0x238) {
              if (sVar2 == 0x21a) {
                ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x217,0,uVar4,0x30006,0,param_14,param_15,param_16);
              }
            }
            else if (sVar2 == 0x23f) {
              ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x23c,0,uVar4,0x30006,0,param_14,param_15,param_16);
            }
          }
          goto LAB_80179188;
        }
        if (bVar1 != 0) {
          puVar10 = FUN_800069a8();
          dVar16 = (double)pfVar13[2];
          dVar15 = (double)*pfVar13;
          dVar18 = (double)*(float *)(puVar10 + 6);
          if (lbl_803E42E0 <=
              (float)(dVar16 + (double)(float)(dVar15 * dVar18 +
                                              (double)(pfVar13[1] * *(float *)(puVar10 + 10))))) {
            if ((int)*(short *)(iVar14 + 0x1a) != 0xffffffff) {
              uVar7 = FUN_80017690((int)*(short *)(iVar14 + 0x1a));
              FUN_80017698((int)*(short *)(iVar14 + 0x1a),
                           uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) >> 8 & 0xffU);
            }
          }
          else if ((int)*(short *)(iVar14 + 0x20) != 0xffffffff) {
            uVar7 = FUN_80017690((int)*(short *)(iVar14 + 0x20));
            FUN_80017698((int)*(short *)(iVar14 + 0x20),
                         uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) & 0xffU);
          }
          sVar2 = *(short *)(uVar4 + 0x46);
          if (sVar2 == 0x205) {
            ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,param_8
                         ,0x202,0,uVar4,0x30005,0,param_14,param_15,param_16);
          }
          else if (sVar2 < 0x205) {
            if (sVar2 == 0x1bb) {
              ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x1b9,0,uVar4,0x30005,0,param_14,param_15,param_16);
            }
            else if (sVar2 < 0x1bb) {
              if (sVar2 == 0x1ad) {
                ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x1ac,0,uVar4,0x30005,0,param_14,param_15,param_16);
              }
              else if ((sVar2 < 0x1ad) && (sVar2 == 0x1a2)) {
                ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x19c,0,uVar4,0x30005,0,param_14,param_15,param_16);
              }
            }
            else if (sVar2 == 0x1ea) {
              ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x1e7,0,uVar4,0x30005,0,param_14,param_15,param_16);
            }
          }
          else if (sVar2 == 0x238) {
            ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,param_8
                         ,0x233,0,uVar4,0x30005,0,param_14,param_15,param_16);
          }
          else if (sVar2 < 0x238) {
            if (sVar2 == 0x21a) {
              ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x217,0,uVar4,0x30005,0,param_14,param_15,param_16);
            }
          }
          else if (sVar2 == 0x23f) {
            ObjMsg_SendToNearbyObjects((double)lbl_803E430C,dVar18,dVar15,dVar16,param_5,param_6,param_7,param_8
                         ,0x23c,0,uVar4,0x30005,0,param_14,param_15,param_16);
          }
        }
      }
      else if (bVar1 == 5) {
        if ((*(short *)((int)pfVar13 + 0x1e) != 0) && (uVar7 = FUN_80017690(0xcbb), uVar7 == 0)) {
          FUN_80006824(uVar4,*(ushort *)((int)pfVar13 + 0x1e));
        }
      }
      else if (((bVar1 < 5) && (*(short *)(pfVar13 + 7) != 0)) &&
              (bVar11 = FUN_800067f8(uVar4,*(short *)(pfVar13 + 7)), bVar11)) {
        FUN_80006810(uVar4,*(short *)(pfVar13 + 7));
      }
      *(undefined *)(param_11 + iVar5 + 0x81) = 0;
    }
    iVar5 = iVar5 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_801797bc
 * EN v1.0 Address: 0x801797BC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80179480
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801797bc(int param_1)
{
  short sVar1;
  bool bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  sVar1 = *(short *)(iVar3 + 0x1c);
  if ((sVar1 != 0) && (bVar2 = FUN_800067f8(param_1,sVar1), bVar2)) {
    FUN_80006810(param_1,*(short *)(iVar3 + 0x1c));
  }
  ObjGroup_RemoveObject(param_1,0xe);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179820
 * EN v1.0 Address: 0x80179820
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801794E4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179820(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179848
 * EN v1.0 Address: 0x80179848
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x80179518
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179848(undefined2 *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar3 + 0x21) = 0;
  if (*(int *)(param_1 + 0x7a) == 0) {
    iVar1 = *(int *)(param_1 + 0x26);
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0x10);
    *param_1 = (short)((int)*(char *)(iVar1 + 0x18) << 8);
    if (param_1[0x23] == 0x151) {
      uVar2 = FUN_80017690(*(uint *)(iVar3 + 0x10));
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0x75);
        *(undefined *)(iVar3 + 0x21) = 1;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    else if (param_1[0x23] == 0x37a) {
      uVar2 = FUN_80017690(*(uint *)(iVar3 + 0x10));
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0x8a);
        *(undefined *)(iVar3 + 0x21) = 1;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801799bc
 * EN v1.0 Address: 0x801799BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017967C
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801799bc(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801799c0
 * EN v1.0 Address: 0x801799C0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80179850
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801799c0(int param_1)
{
  uint uVar1;
  
  uVar1 = countLeadingZeros((uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}


/* Trivial 4b 0-arg blr leaves. */
void doorf4_hitDetect(void) {}
void doorf4_release(void) {}
void doorf4_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int doorf4_getExtraSize(void) { return 0x24; }
int doorf4_func08(void) { return 0x1; }
int sidekickball_getExtraSize(void) { return 0x2cc; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3680;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void doorf4_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3680); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
int fn_801793A4(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x274) == 0; }
#pragma peephole reset
#pragma scheduling reset
