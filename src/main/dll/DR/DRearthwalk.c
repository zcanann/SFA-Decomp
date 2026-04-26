#include "ghidra_import.h"
#include "main/dll/DR/DRearthwalk.h"

extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017760();
extern undefined4 FUN_80017a50();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a6c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305c4();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_800387ec();
extern undefined4 FUN_8003882c();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8004036c();
extern undefined4 FUN_80040a88();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247734();
extern undefined4 FUN_80286834();
extern int FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294c30();
extern int FUN_80294cf8();
extern undefined4 FUN_80294d18();

extern undefined4 DAT_803dccc0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern f64 DOUBLE_803e6198;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6168;
extern f32 FLOAT_803e616c;
extern f32 FLOAT_803e6170;
extern f32 FLOAT_803e6174;
extern f32 FLOAT_803e6178;
extern f32 FLOAT_803e617c;
extern f32 FLOAT_803e6180;
extern f32 FLOAT_803e6184;
extern f32 FLOAT_803e6188;
extern f32 FLOAT_803e618c;
extern f32 FLOAT_803e6190;
extern f32 FLOAT_803e61a0;
extern f32 FLOAT_803e61a4;
extern f32 FLOAT_803e61a8;
extern f32 FLOAT_803e61ac;
extern f32 FLOAT_803e61b4;
extern f32 FLOAT_803e61b8;
extern f32 FLOAT_803e61c0;

/*
 * --INFO--
 *
 * Function: FUN_801d9bdc
 * EN v1.0 Address: 0x801D9BDC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801DA010
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9bdc(undefined2 *param_1,int param_2)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  uint *puVar5;
  
  pbVar4 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined4 *)(param_1 + 0x7a) = 0;
  iVar3 = 0;
  puVar5 = (uint *)&DAT_803dccc0;
  do {
    uVar2 = FUN_80017690(*puVar5);
    if (uVar2 != 0) {
      *pbVar4 = (char)iVar3 + 1;
    }
    puVar5 = puVar5 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 2);
  bVar1 = *pbVar4;
  if (bVar1 == 1) {
    FUN_80017a6c((int)param_1,0,0,0,'\0','\x04');
  }
  else if ((bVar1 == 0) || (bVar1 < 3)) {
    FUN_80017a6c((int)param_1,0,0,0,'\0','\x03');
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d9cc4
 * EN v1.0 Address: 0x801D9CC4
 * EN v1.0 Size: 1656b
 * EN v1.1 Address: 0x801DA1CC
 * EN v1.1 Size: 1704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d9cc4(void)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  float *pfVar7;
  char *pcVar8;
  uint uVar9;
  char in_r8;
  char *pcVar10;
  int iVar11;
  double in_f27;
  double dVar12;
  double in_f28;
  double dVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float afStack_e0 [12];
  float afStack_b0 [12];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  puVar5 = (ushort *)FUN_80286834();
  pcVar10 = *(char **)(puVar5 + 0x5c);
  iVar6 = FUN_80017a98();
  if (in_r8 != '\0') {
    if (*pcVar10 == '\x03') {
      FUN_80017a50(puVar5,afStack_b0,'\0');
      pfVar7 = (float *)FUN_8003882c(iVar6,0);
      FUN_80247734(pfVar7,afStack_e0);
      FUN_80247618(afStack_e0,afStack_b0,(float *)(pcVar10 + 8));
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x04') {
      FUN_800387ec(iVar6,0,(float *)(pcVar10 + 8));
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x05') {
      pfVar7 = (float *)FUN_8003882c(iVar6,0);
      FUN_80247618(pfVar7,(float *)(pcVar10 + 8),afStack_b0);
      FUN_8004036c(afStack_b0);
      FUN_80040a88((int)puVar5);
    }
    else {
      FUN_8003b818((int)puVar5);
    }
    ObjPath_GetPointWorldPosition(puVar5,0,&local_ec,&local_e8,&local_e4,0);
    ObjPath_GetPointWorldPosition(puVar5,1,&local_f8,&local_f4,&local_f0,0);
    dVar16 = (double)(local_f8 - local_ec);
    dVar15 = (double)(local_f4 - local_e8);
    dVar14 = (double)(local_f0 - local_e4);
    if (((pcVar10[2] & 1U) != 0) && ((pcVar10[2] & 2U) == 0)) {
      iVar6 = 2;
      iVar11 = 4;
      pcVar8 = pcVar10;
      do {
        if (*(int *)(pcVar8 + 0x40) == 0) {
          pcVar10[iVar6 + 0x60] = '\x01';
          break;
        }
        iVar6 = iVar6 + 2;
        iVar11 = iVar11 + -1;
        pcVar8 = pcVar8 + 8;
      } while (iVar11 != 0);
      if (9 < iVar6) {
        pcVar10[2] = pcVar10[2] | 2;
      }
    }
    if (((pcVar10[2] & 4U) != 0) && ((pcVar10[2] & 8U) == 0)) {
      iVar6 = 1;
      pcVar8 = pcVar10 + 4;
      iVar11 = 5;
      do {
        if (*(int *)(pcVar8 + 0x38) == 0) {
          pcVar10[iVar6 + 0x60] = '\x01';
          break;
        }
        pcVar8 = pcVar8 + 8;
        iVar6 = iVar6 + 2;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      if (9 < iVar6) {
        pcVar10[2] = pcVar10[2] | 8;
      }
    }
    fVar3 = FLOAT_803e6190;
    fVar2 = FLOAT_803e616c;
    bVar1 = pcVar10[2];
    if (bVar1 == 0) {
      if (*(float *)(pcVar10 + 4) != FLOAT_803e616c) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
        if (fVar2 < *(float *)(pcVar10 + 4)) {
          fVar3 = FLOAT_803e617c * *(float *)(pcVar10 + 4);
        }
        else {
          iVar6 = *(int *)(pcVar10 + 0x38);
          if (iVar6 != 0) {
            *(ushort *)(iVar6 + 6) = *(ushort *)(iVar6 + 6) | 0x4000;
            pcVar10[0x38] = '\0';
            pcVar10[0x39] = '\0';
            pcVar10[0x3a] = '\0';
            pcVar10[0x3b] = '\0';
            *(float *)(pcVar10 + 4) = fVar2;
          }
        }
      }
      if (*(int *)(pcVar10 + 0x38) != 0) {
        *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) =
             (float)(dVar16 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_ec);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) =
             (float)(dVar15 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e8);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) =
             (float)(dVar14 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e4);
        *(float *)(*(int *)(pcVar10 + 0x38) + 8) = fVar3;
      }
    }
    else if ((bVar1 & 0x20) == 0) {
      dVar13 = (double)FLOAT_803e6170;
      if ((bVar1 & 0x10) != 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
        if (FLOAT_803e616c < *(float *)(pcVar10 + 4)) {
          dVar13 = (double)(FLOAT_803e617c * *(float *)(pcVar10 + 4));
        }
        else {
          pcVar10[2] = pcVar10[2] & 0xef;
        }
      }
      uVar9 = 0;
      do {
        if (*(int *)(pcVar10 + 0x38) != 0) {
          uStack_7c = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          dVar12 = (double)(FLOAT_803e6188 *
                           (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e6198));
          uStack_74 = FUN_80017760(0xffffffce,0x32);
          uStack_74 = uStack_74 ^ 0x80000000;
          local_78 = 0x43300000;
          dVar12 = (double)(float)(dVar12 + (double)((float)((double)CONCAT44(0x43300000,uStack_74)
                                                            - DOUBLE_803e6198) / FLOAT_803e618c));
          *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) = (float)(dVar16 * dVar12 + (double)local_ec);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) = (float)(dVar15 * dVar12 + (double)local_e8);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) = (float)(dVar14 * dVar12 + (double)local_e4);
          *(float *)(*(int *)(pcVar10 + 0x38) + 8) = (float)dVar13;
        }
        pcVar10 = pcVar10 + 4;
        uVar9 = uVar9 + 1;
      } while ((int)uVar9 < 10);
    }
    else {
      pcVar8 = pcVar10 + 0x14;
      for (iVar6 = 5; iVar6 < 5; iVar6 = iVar6 + 1) {
        iVar11 = *(int *)(pcVar8 + 0x38);
        if (iVar11 != 0) {
          *(ushort *)(iVar11 + 6) = *(ushort *)(iVar11 + 6) | 0x4000;
          pcVar8[0x38] = '\0';
          pcVar8[0x39] = '\0';
          pcVar8[0x3a] = '\0';
          pcVar8[0x3b] = '\0';
        }
        pcVar8 = pcVar8 + 4;
      }
      if ((pcVar10[2] & 0x10U) == 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) + FLOAT_803dc074;
        if (FLOAT_803e6178 <= *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = FLOAT_803e6178;
        }
        fVar3 = FLOAT_803e617c * *(float *)(pcVar10 + 4);
      }
      else {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
        fVar3 = FLOAT_803e6170;
        if (FLOAT_803e616c < *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
          fVar3 = FLOAT_803e6174 * *(float *)(pcVar10 + 4);
        }
      }
      uVar9 = 0;
      iVar6 = 5;
      pcVar8 = pcVar10;
      do {
        if ((*(int *)(pcVar8 + 0x38) != 0) && (*(int *)(pcVar10 + 0x48) != 0)) {
          uStack_7c = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = FLOAT_803e6180 +
                  (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e6198) / FLOAT_803e6184
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x48) + 0xc);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0xc) = fVar4 * (local_ec - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x10) =
               fVar4 * (local_e8 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x10);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x14) =
               fVar4 * (local_e4 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x14);
          *(float *)(*(int *)(pcVar8 + 0x38) + 8) = fVar3;
        }
        pcVar8 = pcVar8 + 4;
        uVar9 = uVar9 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      iVar6 = 9;
      pcVar8 = pcVar10 + 0x24;
      iVar11 = 5;
      do {
        if ((*(int *)(pcVar8 + 0x38) != 0) && (*(int *)(pcVar10 + 0x4c) != 0)) {
          uStack_7c = 9U - iVar6 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = FLOAT_803e6180 +
                  (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e6198) / FLOAT_803e6184
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x4c) + 0xc);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0xc) = fVar4 * (local_f8 - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x10) =
               fVar4 * (local_f4 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x14) =
               fVar4 * (local_f0 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14);
          *(float *)(*(int *)(pcVar8 + 0x38) + 8) = fVar3;
        }
        pcVar8 = pcVar8 + -4;
        iVar6 = iVar6 + -1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da33c
 * EN v1.0 Address: 0x801DA33C
 * EN v1.0 Size: 664b
 * EN v1.1 Address: 0x801DA874
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da33c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  iVar1 = FUN_8028683c();
  puVar6 = *(undefined **)(iVar1 + 0xb8);
  iVar5 = 0;
  puVar7 = puVar6;
  uVar8 = extraout_f1;
  do {
    if (puVar6[iVar5 + 0x60] != '\0') {
      uVar2 = FUN_80017ae8();
      if ((uVar2 & 0xff) == 0) {
        iVar3 = 0;
      }
      else {
        puVar4 = FUN_80017aa4(0x20,0x659);
        *(undefined *)(puVar4 + 2) = 2;
        *(undefined *)((int)puVar4 + 7) = 0xff;
        iVar3 = FUN_80017a5c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             puVar4);
      }
      *(int *)(puVar7 + 0x38) = iVar3;
      puVar6[iVar5 + 0x60] = 0;
    }
    puVar7 = puVar7 + 4;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 10);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    switch(*(undefined *)(param_11 + iVar5 + 0x81)) {
    case 2:
      *puVar6 = 3;
      break;
    case 3:
      puVar6[1] = 1;
      break;
    case 4:
      puVar6[1] = 0;
      break;
    case 5:
      FUN_801da5d4(iVar1,puVar6,1);
      break;
    case 6:
      *puVar6 = 4;
      break;
    case 7:
      FUN_8011e800(1);
      break;
    case 8:
      puVar6[2] = puVar6[2] | 1;
      break;
    case 9:
      puVar6[2] = puVar6[2] | 4;
      break;
    case 10:
      puVar6[2] = puVar6[2] | 0x10;
      *(float *)(puVar6 + 4) = FLOAT_803e6178;
      break;
    case 0xb:
      puVar6[2] = puVar6[2] | 0x20;
      *(float *)(puVar6 + 4) = FLOAT_803e616c;
      break;
    case 0xc:
      puVar6[2] = puVar6[2] | 0x10;
      puVar6[2] = puVar6[2] | 10;
      *(float *)(puVar6 + 4) = FLOAT_803e61a0;
    }
  }
  if (puVar6[1] != '\0') {
    (**(code **)(*DAT_803dd6e8 + 0x34))((int)*(short *)(*(int *)(iVar1 + 0x50) + 0x7e),0xa0,0x8c);
  }
  *(float *)(puVar6 + 0x6c) = FLOAT_803e6170 * FLOAT_803dc074 + *(float *)(puVar6 + 0x6c);
  if (FLOAT_803e6168 < *(float *)(puVar6 + 0x6c)) {
    *(float *)(puVar6 + 0x6c) = FLOAT_803e616c;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da5d4
 * EN v1.0 Address: 0x801DA5D4
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x801DAA98
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da5d4(int param_1,undefined *param_2,int param_3)
{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  
  iVar1 = FUN_80017a98();
  ObjHits_DisableObject(param_1);
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (param_3 != 0) {
    FUN_80294c30(iVar1,1);
    FUN_80294d18(iVar1,1);
    iVar1 = 2;
    puVar2 = param_2;
    do {
      iVar3 = *(int *)(puVar2 + 0x38);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x38) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x3c);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x3c) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x40);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x40) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x44);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x44) = 0;
      }
      iVar3 = *(int *)(puVar2 + 0x48);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        *(undefined4 *)(puVar2 + 0x48) = 0;
      }
      puVar2 = puVar2 + 0x14;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  *param_2 = 6;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da724
 * EN v1.0 Address: 0x801DA724
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DABF8
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da724(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801da728
 * EN v1.0 Address: 0x801DA728
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801DAEB4
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da728(int param_1)
{
  float local_18;
  float local_14;
  float local_10;
  
  FUN_8003b818(param_1);
  local_18 = FLOAT_803e61b4;
  local_14 = FLOAT_803e61b8;
  local_10 = FLOAT_803e61b4;
  FUN_80081110(param_1,4,0,0,&local_18);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da774
 * EN v1.0 Address: 0x801DA774
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801DAF14
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da774(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  if ((*(ushort *)(param_9 + 6) & 0x4000) != 0) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801da7f8
 * EN v1.0 Address: 0x801DA7F8
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801DAF44
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801da7f8(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) + FLOAT_803dc074;
  if ((FLOAT_803e61c0 <= *(float *)(iVar1 + 4)) &&
     (*(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) - FLOAT_803e61c0,
     (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    FUN_80081110(param_1,0,2,0,(undefined4 *)0x0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801da868
 * EN v1.0 Address: 0x801DA868
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801DAFD8
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801da868(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  uVar3 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (((param_10 == 0) && (iVar1 = *piVar2, iVar1 != 0)) &&
     ((*(ushort *)(iVar1 + 0xb0) & 0x40) == 0)) {
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  return;
}
