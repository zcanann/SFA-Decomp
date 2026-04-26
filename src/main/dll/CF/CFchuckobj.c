#include "ghidra_import.h"
#include "main/dll/CF/CFchuckobj.h"

extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80017640();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern double FUN_80017714();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int FUN_800384ec();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8018e0a8();
extern undefined4 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_803ad410;
extern undefined4 DAT_803ad41e;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803ddb38;
extern f64 DOUBLE_803e4af0;
extern f64 DOUBLE_803e4af8;
extern f64 DOUBLE_803e4b28;
extern f64 DOUBLE_803e4b70;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4ae4;
extern f32 FLOAT_803e4ae8;
extern f32 FLOAT_803e4b00;
extern f32 FLOAT_803e4b04;
extern f32 FLOAT_803e4b08;
extern f32 FLOAT_803e4b10;
extern f32 FLOAT_803e4b14;
extern f32 FLOAT_803e4b18;
extern f32 FLOAT_803e4b1c;
extern f32 FLOAT_803e4b20;
extern f32 FLOAT_803e4b30;
extern f32 FLOAT_803e4b34;
extern f32 FLOAT_803e4b38;
extern f32 FLOAT_803e4b3c;
extern f32 FLOAT_803e4b40;
extern f32 FLOAT_803e4b44;
extern f32 FLOAT_803e4b48;
extern f32 FLOAT_803e4b4c;
extern f32 FLOAT_803e4b50;
extern f32 FLOAT_803e4b54;
extern f32 FLOAT_803e4b58;
extern f32 FLOAT_803e4b5c;
extern f32 FLOAT_803e4b60;
extern f32 FLOAT_803e4b64;
extern f32 FLOAT_803e4b68;
extern f32 FLOAT_803e4b78;

/*
 * --INFO--
 *
 * Function: fxemit_init
 * EN v1.0 Address: 0x8018EFE0
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x8018F020
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fxemit_init(undefined4 param_1,undefined4 param_2,int param_3)
{
  short *psVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar1 = (short *)FUN_80286838();
  iVar3 = *(int *)(psVar1 + 0x5c);
  iVar5 = *(int *)(psVar1 + 0x26);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    iVar4 = iVar2 + 0x81;
    if (*(char *)(param_3 + iVar4) == '\x01') {
      FUN_8018e0a8();
    }
    if (*(char *)(param_3 + iVar4) == '\x02') {
      *(char *)(iVar3 + 0x1c) = '\x01' - *(char *)(iVar3 + 0x1c);
    }
    *(undefined *)(param_3 + iVar4) = 0;
  }
  if (*(char *)(iVar3 + 0x1c) != '\0') {
    if (*(char *)(iVar5 + 0x27) == '\x7f') {
      *psVar1 = *psVar1 + (ushort)DAT_803dc070 * 10;
    }
    else {
      *psVar1 = *psVar1 + (short)*(char *)(iVar5 + 0x27) * (ushort)DAT_803dc070 * 100;
    }
    if (*(char *)(iVar5 + 0x26) == '\x7f') {
      psVar1[1] = psVar1[1] + (ushort)DAT_803dc070 * 10;
    }
    else {
      psVar1[1] = psVar1[1] + (short)*(char *)(iVar5 + 0x26) * (ushort)DAT_803dc070 * 100;
    }
    if (*(char *)(iVar5 + 0x25) == '\x7f') {
      psVar1[2] = psVar1[2] + (ushort)DAT_803dc070 * 10;
    }
    else {
      psVar1[2] = psVar1[2] + (short)*(char *)(iVar5 + 0x25) * (ushort)DAT_803dc070 * 100;
    }
    FUN_8018e0a8();
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018f158
 * EN v1.0 Address: 0x8018F158
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8018F1B0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f158(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  (**(code **)(*DAT_803dd6fc + 0x14))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018f1b4
 * EN v1.0 Address: 0x8018F1B4
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x8018F214
 * EN v1.1 Size: 840b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f1b4(short *param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float *pfVar8;
  double dVar9;
  
  pfVar8 = *(float **)(param_1 + 0x5c);
  iVar7 = *(int *)(param_1 + 0x26);
  if (*(short *)((int)pfVar8 + 0x12) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
    iVar5 = FUN_80017a98();
    if ((iVar5 != 0) && (iVar7 != 0)) {
      if ((*(char *)(iVar7 + 0x29) != '\0') && (*(char *)(iVar7 + 0x29) != -1)) {
        if (*(short *)((int)pfVar8 + 0x1a) < 1) {
          *(undefined2 *)(pfVar8 + 6) = 0;
          *(ushort *)((int)pfVar8 + 0x1a) = (ushort)*(byte *)(iVar7 + 0x29) * 100;
          if (*(ushort *)(iVar7 + 0x2a) != 0) {
            FUN_80006824((uint)param_1,*(ushort *)(iVar7 + 0x2a));
          }
        }
        else {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        *(ushort *)((int)pfVar8 + 0x1a) = *(short *)((int)pfVar8 + 0x1a) - (ushort)DAT_803dc070;
      }
      if (*(char *)(iVar7 + 0x27) == '\x7f') {
        *param_1 = *param_1 + (ushort)DAT_803dc070 * 10;
      }
      else {
        *param_1 = *param_1 + (short)*(char *)(iVar7 + 0x27) * (ushort)DAT_803dc070 * 100;
      }
      if (*(char *)(iVar7 + 0x26) == '\x7f') {
        param_1[1] = param_1[1] + (ushort)DAT_803dc070 * 10;
      }
      else {
        param_1[1] = param_1[1] + (short)*(char *)(iVar7 + 0x26) * (ushort)DAT_803dc070 * 100;
      }
      if (*(char *)(iVar7 + 0x25) == '\x7f') {
        param_1[2] = param_1[2] + (ushort)DAT_803dc070 * 10;
      }
      else {
        param_1[2] = param_1[2] + (short)*(char *)(iVar7 + 0x25) * (ushort)DAT_803dc070 * 100;
      }
      if ((((int)*(short *)(pfVar8 + 5) == 0xffffffff) ||
          (uVar6 = FUN_80017690((int)*(short *)(pfVar8 + 5)), uVar6 != 0)) &&
         (*(short *)(pfVar8 + 6) == 0)) {
        if (((int)*(short *)((int)pfVar8 + 0x16) != 0xffffffff) &&
           (uVar6 = FUN_80017690((int)*(short *)((int)pfVar8 + 0x16)), uVar6 != 0)) {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        if (*(char *)(iVar7 + 0x29) == -1) {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        sVar1 = *(short *)((int)pfVar8 + 0xe);
        if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0x7a) < 1)))) {
          fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar5 + 0x18);
          fVar3 = *(float *)(param_1 + 0xe) - *(float *)(iVar5 + 0x1c);
          fVar4 = *(float *)(param_1 + 0x10) - *(float *)(iVar5 + 0x20);
          if (sVar1 == 0) {
            *(undefined2 *)(pfVar8 + 6) = 1;
          }
          dVar9 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
          if ((dVar9 <= (double)*pfVar8) || ((double)FLOAT_803e4ae4 == (double)*pfVar8)) {
            FUN_8018e0a8();
          }
          *(int *)(param_1 + 0x7a) = -(int)*(short *)((int)pfVar8 + 0xe);
        }
        else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0x7a))) {
          *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
        }
      }
    }
  }
  else {
    *(short *)((int)pfVar8 + 0x12) = *(short *)((int)pfVar8 + 0x12) - (short)(int)FLOAT_803dc074;
    if (*(short *)((int)pfVar8 + 0x12) < 0) {
      *(undefined2 *)((int)pfVar8 + 0x12) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018f4fc
 * EN v1.0 Address: 0x8018F4FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018F55C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f4fc(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018f500
 * EN v1.0 Address: 0x8018F500
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x8018F6C4
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f500(void)
{
  int iVar1;
  short sVar2;
  int iVar3;
  double in_f31;
  double dVar4;
  double in_ps31_1;
  undefined8 uVar5;
  undefined auStack_58 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar5 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (0 < (int)uVar5) {
    dVar4 = DOUBLE_803e4af8;
    for (sVar2 = 0; (int)sVar2 < (int)uVar5; sVar2 = sVar2 + 1) {
      uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar3 + 0x14),(uint)*(ushort *)(iVar3 + 0x14));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
      uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar3 + 0x18),(uint)*(ushort *)(iVar3 + 0x18));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_48 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
      uStack_2c = FUN_80017760(-(uint)*(ushort *)(iVar3 + 0x16),(uint)*(ushort *)(iVar3 + 0x16));
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_44 = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar4);
      FUN_80017748((ushort *)(iVar3 + 0x1a),&local_4c);
      if ((*(char *)(iVar3 + 8) == '\x04') || (*(char *)(iVar3 + 8) == '\x06')) {
        local_4c = local_4c + *(float *)(iVar1 + 0xc);
        local_48 = local_48 + *(float *)(iVar1 + 0x10);
        local_44 = local_44 + *(float *)(iVar1 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack_58,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack_58,2,0xffffffff,0);
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018f650
 * EN v1.0 Address: 0x8018F650
 * EN v1.0 Size: 1620b
 * EN v1.1 Address: 0x8018F854
 * EN v1.1 Size: 2220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f650(void)
{
  byte bVar1;
  int iVar2;
  int *piVar3;
  short sVar4;
  int iVar5;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  ushort local_68;
  undefined2 local_66;
  short local_64;
  undefined auStack_60 [8];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_8028683c();
  iVar5 = *(int *)(iVar2 + 0xb8);
  local_58 = FLOAT_803e4b00;
  bVar1 = *(byte *)(iVar5 + 8);
  if (bVar1 == 0) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4af8);
      uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4af8);
      uStack_44 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4af8);
      local_68 = *(ushort *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80017748(&local_68,&local_54);
      local_54 = local_54 + *(float *)(iVar2 + 0xc);
      local_50 = local_50 + *(float *)(iVar2 + 0x10);
      local_4c = local_4c + *(float *)(iVar2 + 0x14);
      (**(code **)(*DAT_803dd708 + 8))
                (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_44 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        local_68 = *(ushort *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80017748(&local_68,&local_54);
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
      }
    }
  }
  else if (bVar1 == 1) {
    piVar3 = (int *)FUN_80006b14(*(ushort *)(iVar5 + 10) + 0x58 & 0xffff);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
      }
    }
    FUN_80006b0c((undefined *)piVar3);
  }
  else if (bVar1 == 2) {
    piVar3 = (int *)FUN_80006b14(*(ushort *)(iVar5 + 10) + 0xab & 0xffff);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
      }
    }
    FUN_80006b0c((undefined *)piVar3);
  }
  else if (bVar1 == 3) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4af8);
      uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4af8);
      uStack_44 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4af8);
      local_68 = *(ushort *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80017748(&local_68,&local_54);
      (**(code **)(*DAT_803dd708 + 8))(iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_44 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        local_68 = *(ushort *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80017748(&local_68,&local_54);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
      }
    }
  }
  else if (5 < bVar1) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4af8);
      uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4af8);
      uStack_44 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4af8);
      FUN_80017748((ushort *)(iVar5 + 0x1a),&local_54);
      if (*(char *)(iVar5 + 8) == '\x06') {
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
      }
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_34 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        uStack_3c = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_44 = FUN_80017760(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        FUN_80017748((ushort *)(iVar5 + 0x1a),&local_54);
        if (*(char *)(iVar5 + 8) == '\x06') {
          local_54 = local_54 + *(float *)(iVar2 + 0xc);
          local_50 = local_50 + *(float *)(iVar2 + 0x10);
          local_4c = local_4c + *(float *)(iVar2 + 0x14);
          (**(code **)(*DAT_803dd708 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
        }
        else {
          (**(code **)(*DAT_803dd708 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
        }
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018fca4
 * EN v1.0 Address: 0x8018FCA4
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80190100
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8018fca4(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  
  for (bVar1 = 0; bVar1 < *(byte *)(param_3 + 0x8b); bVar1 = bVar1 + 1) {
    if (*(char *)(param_3 + bVar1 + 0x81) == '\x01') {
      FUN_8018f650();
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8018fd14
 * EN v1.0 Address: 0x8018FD14
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8019018C
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018fd14(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018fd48
 * EN v1.0 Address: 0x8018FD48
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801901CC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018fd48(int param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  
  pfVar7 = *(float **)(param_1 + 0xb8);
  iVar5 = FUN_80017a98();
  if ((iVar5 != 0) &&
     ((((int)*(short *)((int)pfVar7 + 0xe) == 0xffffffff ||
       (uVar6 = FUN_80017690((int)*(short *)((int)pfVar7 + 0xe)), uVar6 != 0)) &&
      (*(short *)((int)pfVar7 + 0x12) == 0)))) {
    uVar6 = FUN_80017690((int)*(short *)(pfVar7 + 4));
    if (uVar6 != 0) {
      *(undefined2 *)((int)pfVar7 + 0x12) = 1;
    }
    sVar1 = *(short *)(pfVar7 + 3);
    if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0xf4) < 1)))) {
      fVar2 = *(float *)(param_1 + 0x18) - *(float *)(iVar5 + 0x18);
      fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(iVar5 + 0x1c);
      fVar4 = *(float *)(param_1 + 0x20) - *(float *)(iVar5 + 0x20);
      if (sVar1 == 0) {
        *(undefined2 *)((int)pfVar7 + 0x12) = 1;
      }
      dVar8 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
      dVar9 = (double)*pfVar7;
      if ((dVar8 <= dVar9) || ((double)FLOAT_803e4b04 == dVar9)) {
        if ((3 < *(byte *)(pfVar7 + 2)) &&
           ((dVar9 < (double)pfVar7[1] && ((double)FLOAT_803e4b04 != dVar9)))) {
          FUN_8018f500();
        }
        FUN_8018f650();
      }
      *(int *)(param_1 + 0xf4) = -(int)*(short *)(pfVar7 + 3);
      pfVar7[1] = (float)dVar8;
    }
    else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0xf4))) {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018fec4
 * EN v1.0 Address: 0x8018FEC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80190354
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018fec4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018fec8
 * EN v1.0 Address: 0x8018FEC8
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801904C4
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018fec8(undefined2 *param_1,undefined2 *param_2)
{
  *param_2 = *param_1;
  param_2[1] = param_1[1];
  param_2[2] = param_1[2];
  param_2[3] = param_1[3];
  param_2[4] = param_1[4];
  param_2[5] = param_1[5];
  param_2[6] = param_1[6];
  param_2[7] = param_1[7];
  *(undefined *)(param_2 + 9) = *(undefined *)(param_1 + 9);
  *(undefined *)((int)param_2 + 0x13) = *(undefined *)((int)param_1 + 0x13);
  *(undefined *)((int)param_2 + 0x1b) = *(undefined *)((int)param_1 + 0x1b);
  *(undefined *)(param_2 + 0xe) = *(undefined *)(param_1 + 0xe);
  *(undefined *)((int)param_2 + 0x1d) = *(undefined *)((int)param_1 + 0x1d);
  *(undefined *)(param_2 + 0xf) = *(undefined *)(param_1 + 0xf);
  *(undefined *)((int)param_2 + 0x1f) = *(undefined *)((int)param_1 + 0x1f);
  *(undefined *)(param_2 + 0x10) = *(undefined *)(param_1 + 0x10);
  *(undefined *)((int)param_2 + 0x21) = *(undefined *)((int)param_1 + 0x21);
  *(undefined *)(param_2 + 0x11) = *(undefined *)(param_1 + 0x11);
  *(undefined *)((int)param_2 + 0x15) = *(undefined *)((int)param_1 + 0x15);
  *(undefined *)((int)param_2 + 0x23) = *(undefined *)((int)param_1 + 0x23);
  *(undefined *)(param_2 + 0xb) = *(undefined *)(param_1 + 0xb);
  *(undefined *)(param_2 + 0x12) = *(undefined *)(param_1 + 0x12);
  *(undefined *)((int)param_2 + 0x17) = *(undefined *)((int)param_1 + 0x17);
  *(undefined *)((int)param_2 + 0x25) = *(undefined *)((int)param_1 + 0x25);
  *(undefined *)(param_2 + 0xc) = *(undefined *)(param_1 + 0xc);
  *(undefined *)(param_2 + 0x13) = *(undefined *)(param_1 + 0x13);
  *(undefined *)((int)param_2 + 0x19) = *(undefined *)((int)param_1 + 0x19);
  *(undefined *)((int)param_2 + 0x27) = *(undefined *)((int)param_1 + 0x27);
  *(undefined *)(param_2 + 0xd) = *(undefined *)(param_1 + 0xd);
  *(undefined *)(param_2 + 0x14) = *(undefined *)(param_1 + 0x14);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018ffbc
 * EN v1.0 Address: 0x8018FFBC
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801905C8
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018ffbc(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x108);
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
  }
  ObjGroup_RemoveObject(param_1,0x1c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80190004
 * EN v1.0 Address: 0x80190004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80190618
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80190004(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80190008
 * EN v1.0 Address: 0x80190008
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8019085C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80190008(int param_1,int param_2)
{
  int iVar1;
  undefined4 local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = 0x21;
  *(float *)(param_1 + 8) = FLOAT_803e4b18 * *(float *)(*(int *)(param_1 + 0x50) + 4);
  *(undefined2 *)(iVar1 + 0x112) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(iVar1 + 0x110) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(iVar1 + 0x114) = 0xfffe;
  *(undefined2 *)(iVar1 + 0x116) = *(undefined2 *)(param_2 + 0x22);
  *(undefined2 *)(iVar1 + 0x118) = *(undefined2 *)(param_2 + 0x18);
  *(undefined2 *)(iVar1 + 0x11a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar1 + 0x11c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  if (*(short *)(iVar1 + 0x110) == 0) {
    *(undefined *)(iVar1 + 0x11e) = 0;
  }
  else {
    *(undefined *)(iVar1 + 0x11e) = 1;
  }
  if (*(char *)(param_2 + 0x24) != '\0') {
    *(byte *)(iVar1 + 0x120) = *(byte *)(iVar1 + 0x120) | 1;
    uStack_c = (int)*(char *)(param_2 + 0x25) ^ 0x80000000;
    local_10 = 0x43300000;
    *(float *)(iVar1 + 0x10c) =
         (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e4b28) / FLOAT_803e4b1c;
    (**(code **)(*DAT_803dd71c + 0x8c))((double)FLOAT_803e4b20,iVar1,param_1,local_18,0xffffffff);
  }
  ObjGroup_AddObject(param_1,0x1c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80190148
 * EN v1.0 Address: 0x80190148
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801909A8
 * EN v1.1 Size: 1376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80190148(int param_1)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  float *pfVar5;
  double dVar6;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  iVar3 = FUN_80017a98();
  local_2c = FLOAT_803e4b30;
  local_28 = FLOAT_803e4b34;
  local_24 = FLOAT_803e4b30;
  bVar1 = *(byte *)((int)pfVar5 + 0xe);
  if ((bVar1 & 0x40) == 0) {
    if ((bVar1 & 8) == 0) {
      if ((bVar1 & 0x10) == 0) {
        dVar6 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 < (double)FLOAT_803e4b38) {
          if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
            FUN_800810f8((double)FLOAT_803e4b48,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,3,6,100,(int)&local_38,0);
          }
          else {
            FUN_800810f8((double)FLOAT_803e4b3c,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,2,7,100,(int)&local_38,0);
          }
        }
        local_34 = 0xc13;
        local_36 = 0;
      }
      else {
        dVar6 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 < (double)FLOAT_803e4b38) {
          if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
            FUN_800810f8((double)FLOAT_803e4b48,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,5,6,100,(int)&local_38,0);
          }
          else {
            FUN_800810f8((double)FLOAT_803e4b3c,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,2,7,100,(int)&local_38,0);
          }
        }
        local_34 = 0xc7e;
        local_36 = 2;
      }
    }
    else {
      dVar6 = FUN_80017714((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
      if (dVar6 < (double)FLOAT_803e4b38) {
        if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
          FUN_800810f8((double)FLOAT_803e4b48,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                       (double)FLOAT_803e4b44,param_1,1,1,6,100,(int)&local_38,0);
        }
        else {
          FUN_800810f8((double)FLOAT_803e4b3c,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                       (double)FLOAT_803e4b44,param_1,1,2,7,100,(int)&local_38,0);
        }
      }
      local_34 = 0xc0e;
      local_36 = 1;
    }
  }
  else if ((bVar1 & 8) == 0) {
    if ((bVar1 & 0x10) == 0) {
      local_34 = 0xc13;
      local_36 = 0;
    }
    else {
      local_34 = 0xc7e;
      local_36 = 2;
    }
  }
  else {
    local_34 = 0xc0e;
    local_36 = 1;
  }
  if ((*(byte *)((int)pfVar5 + 0xe) & 4) != 0) {
    fVar2 = *pfVar5;
    if (FLOAT_803e4b4c <= fVar2) {
      if (FLOAT_803e4b50 <= fVar2) {
        if (FLOAT_803e4b60 <= fVar2) {
          if (FLOAT_803e4b68 <= fVar2) {
            *pfVar5 = FLOAT_803e4b30;
            *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) & 0xfb;
          }
        }
        else {
          uStack_1c = FUN_80017760(0,0x1e0);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4b70) <
              *pfVar5 * FLOAT_803e4b48) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)((int)pfVar5 + 0xe) & 2) != 0) {
            *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) & 0xfd;
            local_32 = 0x46;
            local_30 = FLOAT_803e4b64;
            for (cVar4 = '\x0f'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack_1c = FUN_80017760(0,0x1e0);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4b70) <
            *pfVar5 / FLOAT_803e4b54) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = FLOAT_803e4b58 * ((*pfVar5 - FLOAT_803e4b4c) / FLOAT_803e4b5c);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) | 2;
      }
    }
    else {
      uStack_1c = FUN_80017760(0,0x1e0);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4b70) <
          *pfVar5 * FLOAT_803e4b48) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *pfVar5 = *pfVar5 + FLOAT_803dc074;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801905c4
 * EN v1.0 Address: 0x801905C4
 * EN v1.0 Size: 632b
 * EN v1.1 Address: 0x80190F08
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801905c4(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  uVar1 = (uint)*(short *)(iVar3 + 0x20);
  if (uVar1 != 0xffffffff) {
    uVar1 = FUN_80017690(uVar1);
    if (uVar1 == 0) {
      *(byte *)(iVar4 + 0xe) = *(byte *)(iVar4 + 0xe) | 0x80;
    }
    else {
      *(byte *)(iVar4 + 0xe) = *(byte *)(iVar4 + 0xe) & 0x7f;
    }
  }
  if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
    FUN_8011e868(0x1b);
    uVar1 = FUN_80017690(0x912);
    if (uVar1 == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
      FUN_80017698(0x912,1);
      return;
    }
  }
  iVar2 = FUN_80017a98();
  if (iVar2 == 0) {
    return;
  }
  if (((*(char *)(iVar4 + 0xd) == '\0') && (*(char *)(iVar4 + 0xc) == '\0')) &&
     ((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0)) {
    if (-1 < DAT_803ddb38) {
      iVar2 = FUN_80017a98();
      dVar5 = (double)FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (dVar5 < (double)FLOAT_803e4b78) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
        *(int *)(param_1 + 0xf4) = (int)*(short *)(iVar4 + 8);
        *(undefined *)(iVar4 + 0xd) = 0;
        *(undefined *)(iVar4 + 0xc) = 1;
        DAT_803dda60 = 2;
        goto LAB_801910d0;
      }
    }
    uVar1 = (uint)*(short *)(iVar3 + 0x20);
    if (((uVar1 == 0xffffffff) ||
        ((uVar1 = FUN_80017690(uVar1), uVar1 != 0 && ((*(byte *)(param_1 + 0xaf) & 4) != 0)))) &&
       (iVar3 = FUN_800384ec(param_1), iVar3 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      *(int *)(param_1 + 0xf4) = (int)*(short *)(iVar4 + 8);
      *(undefined *)(iVar4 + 0xd) = 1;
      *(undefined *)(iVar4 + 0xc) = 1;
    }
  }
LAB_801910d0:
  if (*(char *)(iVar4 + 0xc) != '\0') {
    if (*(int *)(param_1 + 0xf4) < 1) {
      *(undefined4 *)(param_1 + 0xf4) = 0;
      *(undefined *)(iVar4 + 0xc) = 0;
    }
    else {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    }
  }
  *(float *)(iVar4 + 4) = *(float *)(iVar4 + 4) - FLOAT_803dc074;
  if (*(float *)(iVar4 + 4) <= FLOAT_803e4b30) {
    *(float *)(iVar4 + 4) = FLOAT_803e4b30;
    *(undefined2 *)(iVar4 + 10) = 0xffff;
  }
  return;
}
