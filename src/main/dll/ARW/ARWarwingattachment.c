#include "ghidra_import.h"
#include "main/dll/ARW/ARWarwingattachment.h"

extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000bb00();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern undefined8 FUN_80014b68();
extern uint FUN_80014e9c();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800217c8();
extern int FUN_80021884();
extern uint FUN_80022264();
extern undefined4 FUN_8002b95c();
extern int FUN_8002ba84();
extern uint FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002f6cc();
extern int FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern char FUN_8003549c();
extern undefined8 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036974();
extern void* FUN_80037048();
extern undefined4 FUN_800379bc();
extern undefined8 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80054484();
extern int FUN_80054ed0();
extern int FUN_80065fcc();
extern undefined4 FUN_80137cd0();
extern uint FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80296bd4();
extern int FUN_80297174();
extern undefined4 FUN_80297184();
extern int FUN_80297300();

extern undefined4 DAT_802c2bf0;
extern undefined4 DAT_802c2bf4;
extern undefined4 DAT_802c2bf8;
extern undefined4 DAT_802c2bfc;
extern undefined4 DAT_802c2c00;
extern undefined4 DAT_802c2c04;
extern undefined4 DAT_803294d8;
extern undefined4 DAT_803295b4;
extern undefined4 DAT_803295b8;
extern undefined4 DAT_803295bc;
extern undefined4 DAT_803295c0;
extern undefined4 DAT_803295c4;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de900;
extern f64 DOUBLE_803e69e8;
extern f64 DOUBLE_803e6a38;
extern f64 DOUBLE_803e6a50;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e699c;
extern f32 FLOAT_803e69a0;
extern f32 FLOAT_803e69a8;
extern f32 FLOAT_803e69ac;
extern f32 FLOAT_803e69b0;
extern f32 FLOAT_803e69b4;
extern f32 FLOAT_803e69c0;
extern f32 FLOAT_803e69c4;
extern f32 FLOAT_803e69c8;
extern f32 FLOAT_803e69cc;
extern f32 FLOAT_803e69d0;
extern f32 FLOAT_803e69d4;
extern f32 FLOAT_803e69d8;
extern f32 FLOAT_803e69dc;
extern f32 FLOAT_803e69e0;
extern f32 FLOAT_803e69f4;
extern f32 FLOAT_803e69f8;
extern f32 FLOAT_803e69fc;
extern f32 FLOAT_803e6a00;
extern f32 FLOAT_803e6a04;
extern f32 FLOAT_803e6a08;
extern f32 FLOAT_803e6a0c;
extern f32 FLOAT_803e6a10;
extern f32 FLOAT_803e6a1c;
extern f32 FLOAT_803e6a20;
extern f32 FLOAT_803e6a24;
extern f32 FLOAT_803e6a30;
extern f32 FLOAT_803e6a34;
extern f32 FLOAT_803e6a40;
extern f32 FLOAT_803e6a44;
extern f32 FLOAT_803e6a48;
extern f32 FLOAT_803e6a4c;
extern f32 FLOAT_803e6a58;
extern f32 FLOAT_803e6a64;
extern f32 FLOAT_803e6a68;
extern f32 FLOAT_803e6a6c;
extern f32 FLOAT_803e6a70;
extern f32 FLOAT_803e6a74;
extern f32 FLOAT_803e6a78;
extern f32 FLOAT_803e6a80;

/*
 * --INFO--
 *
 * Function: FUN_801f0da4
 * EN v1.0 Address: 0x801F0DA4
 * EN v1.0 Size: 488b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0da4(int param_1)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  int local_18 [5];
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x4c) + 0x19);
  if ((((cVar1 != '\b') && (cVar1 < '\b')) && (cVar1 == '\0')) &&
     (((*(int *)(param_1 + 0xf4) == 0 && (uVar4 = FUN_80020078(0xa4), uVar4 == 0)) &&
      (uVar4 = FUN_80020078(0x78), uVar4 == 0)))) {
    piVar5 = FUN_80037048(6,local_18);
    bVar2 = false;
    if (0 < local_18[0]) {
      do {
        if (*(short *)(*piVar5 + 0x46) == 0x139) {
          bVar2 = true;
        }
        piVar5 = piVar5 + 1;
        local_18[0] = local_18[0] + -1;
      } while (local_18[0] != 0);
    }
    if (bVar2) {
      if (*(int *)(param_1 + 0xf8) == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        *(undefined4 *)(param_1 + 0xf4) = 1;
        FUN_800201ac(0xa4,1);
      }
      else {
        (**(code **)(*DAT_803dd6cc + 0xc))(0x50,1);
      }
    }
    else {
      *(undefined4 *)(param_1 + 0xf8) = 0x14;
      (**(code **)(*DAT_803dd6cc + 0xc))(0x50,1);
    }
    iVar3 = *(int *)(param_1 + 0xf8) + -1;
    *(int *)(param_1 + 0xf8) = iVar3;
    if (iVar3 < 0) {
      *(undefined4 *)(param_1 + 0xf8) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0f8c
 * EN v1.0 Address: 0x801F0F8C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0f8c(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(char *)(*(int *)(param_1 + 0xb8) + 9) == '\0')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0fd4
 * EN v1.0 Address: 0x801F0FD4
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0fd4(int param_1)
{
  uint uVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(short *)(*(int *)(param_1 + 0xb8) + 6) == 2)) &&
     (uVar1 = FUN_80020078(0x9ad), uVar1 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_1,0xffffffff);
    FUN_80014b68(0,0x100);
    FUN_800201ac(0x9ad,1);
  }
  FUN_8002fb40((double)FLOAT_803e699c,(double)FLOAT_803dc074);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1078
 * EN v1.0 Address: 0x801F1078
 * EN v1.0 Size: 180b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f112c
 * EN v1.0 Address: 0x801F112C
 * EN v1.0 Size: 92b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f112c(int param_1)
{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6fc + 0x18))();
  if (*piVar1 != 0) {
    FUN_80054484();
    *piVar1 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1188
 * EN v1.0 Address: 0x801F1188
 * EN v1.0 Size: 2376b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1188(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f1ad0
 * EN v1.0 Address: 0x801F1AD0
 * EN v1.0 Size: 284b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1ad0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  int *piVar4;
  undefined8 uVar5;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  uVar5 = FUN_80037a5c((int)param_9,2);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  if (*(short *)(param_10 + 0x1c) == 0) {
    uVar3 = 0x50;
    uVar1 = FUN_80022264(0xffffffb0,0x50);
    *(short *)(piVar4 + 0xc) = (short)uVar1 + 400;
  }
  else {
    *(short *)(piVar4 + 0xc) = *(short *)(param_10 + 0x1c);
    uVar3 = extraout_r4;
  }
  *(undefined2 *)(piVar4 + 0xb) = *(undefined2 *)(piVar4 + 0xc);
  *(undefined *)((int)piVar4 + 0x4d) = 0;
  piVar4[7] = (int)FLOAT_803e69a8;
  *(undefined *)((int)piVar4 + 0x4e) = *(undefined *)(param_10 + 0x19);
  *(undefined2 *)((int)piVar4 + 0x2e) = 0x118;
  *(undefined2 *)((int)piVar4 + 0x32) = 0xffff;
  if (*(char *)((int)piVar4 + 0x4e) == '\x1e') {
    if (*piVar4 == 0) {
      iVar2 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e9,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*(char *)((int)piVar4 + 0x4e) == '\x01') {
    if (*piVar4 == 0) {
      iVar2 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x23d,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*piVar4 == 0) {
    iVar2 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xd9,uVar3,
                         param_11,param_12,param_13,param_14,param_15,param_16);
    *piVar4 = iVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1bec
 * EN v1.0 Address: 0x801F1BEC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1bec(void)
{
  FUN_80013e4c(DAT_803de900);
  DAT_803de900 = (undefined4*)0x0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1c18
 * EN v1.0 Address: 0x801F1C18
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1c18(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f1c70
 * EN v1.0 Address: 0x801F1C70
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1c70(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1ca4
 * EN v1.0 Address: 0x801F1CA4
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1ca4(void)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar6;
  uint uVar5;
  int iVar7;
  int iVar8;
  char *pcVar9;
  int iVar10;
  bool bVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  
  uVar3 = FUN_8028683c();
  iVar4 = FUN_8002bac4();
  iVar10 = *(int *)(uVar3 + 0x4c);
  pcVar9 = *(char **)(uVar3 + 0xb8);
  dVar13 = (double)FUN_800217c8((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18));
  dVar12 = (double)FLOAT_803e69f4;
  *pcVar9 = *pcVar9 + -1;
  if (*pcVar9 < '\0') {
    *pcVar9 = '\0';
    pcVar9[1] = '\0';
  }
  iVar4 = 0;
  pcVar9[6] = pcVar9[6] & 0x7f;
  if ((*(int *)(uVar3 + 0x58) == 0) || (*(char *)(*(int *)(uVar3 + 0x58) + 0x10f) < '\x01')) {
    if ((*(char *)(uVar3 + 0xac) == '\v') &&
       (((cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(), cVar6 == '\x03' &&
         (iVar4 = FUN_8002ba84(), iVar4 != 0)) &&
        (dVar14 = (double)FUN_800217c8((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18)),
        dVar14 < (double)FLOAT_803e69fc)))) {
      *pcVar9 = '\x05';
    }
  }
  else {
    *(short *)(pcVar9 + 2) = *(short *)(iVar10 + 0x1e) * 0x3c;
    dVar14 = (double)FLOAT_803e69f8;
    for (iVar8 = 0; iVar8 < *(char *)(*(int *)(uVar3 + 0x58) + 0x10f); iVar8 = iVar8 + 1) {
      iVar7 = *(int *)(*(int *)(uVar3 + 0x58) + iVar4 + 0x100);
      if (*(short *)(iVar7 + 0x46) == 0x6d) {
        pcVar9[6] = pcVar9[6] & 0x7fU | 0x80;
      }
      if (dVar14 < (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar3 + 0x10))) {
        *pcVar9 = '\x05';
      }
      if (((pcVar9[1] == '\0') && (iVar7 != 0)) && (*(short *)(iVar7 + 0x46) == 0x146)) {
        if (dVar13 <= dVar12) {
          FUN_8000bb38(uVar3,0x7e);
        }
        pcVar9[1] = '\x01';
      }
      iVar4 = iVar4 + 4;
    }
  }
  if (((*(char *)(uVar3 + 0xac) == '\v') &&
      (cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(), cVar6 == '\x01')) && (dVar13 <= dVar12)) {
    if (*pcVar9 == '\0') {
      uVar5 = FUN_80020078(0x905);
      if (uVar5 != 0) {
        FUN_800201ac(0x905,0);
      }
    }
    else {
      fVar1 = *(float *)(iVar10 + 0xc) - *(float *)(uVar3 + 0x10);
      if (((fVar1 <= FLOAT_803e6a00) || (FLOAT_803e6a04 <= fVar1)) ||
         (uVar5 = FUN_80020078((int)*(short *)(pcVar9 + 4)), uVar5 != 0)) {
        uVar5 = FUN_80020078(0x905);
        if (uVar5 != 0) {
          FUN_800201ac(0x905,0);
        }
      }
      else {
        FUN_800201ac(0x905,1);
      }
    }
  }
  bVar11 = false;
  if (*pcVar9 == '\0') {
    if (*(short *)(pcVar9 + 2) == 0) {
      *(float *)(uVar3 + 0x10) = FLOAT_803e6a0c * FLOAT_803dc074 + *(float *)(uVar3 + 0x10);
      bVar11 = *(float *)(uVar3 + 0x10) <= *(float *)(iVar10 + 0xc);
      if (!bVar11) {
        *(float *)(uVar3 + 0x10) = *(float *)(iVar10 + 0xc);
      }
      FUN_800201ac((int)*(short *)(iVar10 + 0x1c),0);
      if (((int)*(short *)(pcVar9 + 4) != 0xffffffff) && (((byte)pcVar9[6] >> 6 & 1) == 0)) {
        FUN_800201ac((int)*(short *)(pcVar9 + 4),0);
      }
    }
  }
  else {
    fVar2 = *(float *)(iVar10 + 0xc) - FLOAT_803e6a04;
    fVar1 = *(float *)(uVar3 + 0x10);
    if (fVar2 <= fVar1) {
      *(float *)(uVar3 + 0x10) = -(FLOAT_803e6a0c * FLOAT_803dc074 - fVar1);
      if (fVar2 <= *(float *)(uVar3 + 0x10)) {
        bVar11 = true;
      }
      else {
        *(float *)(uVar3 + 0x10) = fVar2;
        FUN_800201ac((int)*(short *)(iVar10 + 0x1c),1);
        if ((int)*(short *)(pcVar9 + 4) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(pcVar9 + 4),1);
          if (pcVar9[6] < '\0') {
            pcVar9[6] = pcVar9[6] & 0xbfU | 0x40;
          }
        }
      }
    }
    else {
      *(float *)(uVar3 + 0x10) = FLOAT_803e6a08 * FLOAT_803dc074 + fVar1;
      if (fVar2 < *(float *)(uVar3 + 0x10)) {
        *(float *)(uVar3 + 0x10) = fVar2;
      }
      FUN_800201ac((int)*(short *)(iVar10 + 0x1c),1);
      if (pcVar9[6] < '\0') {
        FUN_800201ac((int)*(short *)(pcVar9 + 4),1);
      }
    }
  }
  if (bVar11) {
    FUN_8000bb38(uVar3,0x7f);
  }
  else {
    FUN_8000b7dc(uVar3,8);
  }
  if ((*(short *)(pcVar9 + 2) != 0) &&
     (*(ushort *)(pcVar9 + 2) = *(short *)(pcVar9 + 2) - (ushort)DAT_803dc070,
     *(short *)(pcVar9 + 2) < 0)) {
    pcVar9[2] = '\0';
    pcVar9[3] = '\0';
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f20f4
 * EN v1.0 Address: 0x801F20F4
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f20f4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f2228
 * EN v1.0 Address: 0x801F2228
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2228(int param_1)
{
  char in_r8;
  
  if (*(int *)(param_1 + 0xf8) == 0) {
    if (in_r8 == '\0') {
      return;
    }
  }
  else if (in_r8 != -1) {
    return;
  }
  if (*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 2) {
    if (*(short *)(param_1 + 0xb4) == -1) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xffffefff;
    }
    else {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) | 0x1000
      ;
    }
  }
  FUN_8003b9ec(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f22bc
 * EN v1.0 Address: 0x801F22BC
 * EN v1.0 Size: 684b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f22bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined uVar8;
  float *pfVar6;
  uint uVar7;
  int iVar9;
  float fVar10;
  int iVar11;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar12;
  undefined8 uVar13;
  int local_18 [3];
  
  puVar12 = *(undefined2 **)(param_9 + 0xb8);
  iVar5 = FUN_8002bac4();
  if (*(char *)((int)puVar12 + 5) == '\0') {
    uVar8 = 0;
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) && (*(int *)(param_9 + 0xf8) == 0)) {
      *puVar12 = 0;
      puVar12[1] = 0x28;
      FUN_80014b68(0,0x100);
      uVar8 = 1;
    }
    *(undefined *)((int)puVar12 + 5) = uVar8;
    if (*(char *)((int)puVar12 + 5) != '\0') {
      *(undefined *)(puVar12 + 3) = 1;
    }
    if (*(int *)(param_9 + 0xf8) == 0) {
      FUN_80036018(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
      *(float *)(param_9 + 0x28) = -(FLOAT_803e6a1c * FLOAT_803dc074 - *(float *)(param_9 + 0x28));
      *(float *)(param_9 + 0x10) =
           *(float *)(param_9 + 0x28) * FLOAT_803dc074 + *(float *)(param_9 + 0x10);
      iVar5 = FUN_80065fcc((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                           (double)*(float *)(param_9 + 0x14),param_9,local_18,0,1);
      fVar4 = FLOAT_803e6a24;
      fVar3 = FLOAT_803e6a20;
      fVar10 = 0.0;
      iVar11 = 0;
      iVar9 = 0;
      if (0 < iVar5) {
        do {
          pfVar6 = *(float **)(local_18[0] + iVar9);
          if (*(char *)(pfVar6 + 5) != '\x0e') {
            fVar2 = *pfVar6;
            if ((*(float *)(param_9 + 0x10) < fVar2) &&
               ((fVar2 - fVar3 < *(float *)(param_9 + 0x10) || (iVar11 == 0)))) {
              fVar10 = pfVar6[4];
              *(float *)(param_9 + 0x10) = fVar2;
              *(float *)(param_9 + 0x28) = fVar4;
            }
          }
          iVar9 = iVar9 + 4;
          iVar11 = iVar11 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      if (fVar10 != 0.0) {
        iVar5 = *(int *)((int)fVar10 + 0x58);
        cVar1 = *(char *)(iVar5 + 0x10f);
        *(char *)(iVar5 + 0x10f) = cVar1 + '\x01';
        *(uint *)(iVar5 + cVar1 * 4 + 0x100) = param_9;
      }
    }
  }
  else {
    uVar13 = FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar7 = FUN_80014e9c(0);
    if ((uVar7 & 0x100) != 0) {
      *(undefined *)(puVar12 + 3) = 0;
      uVar13 = FUN_80014b68(0,0x100);
    }
    if (*(int *)(param_9 + 0xf8) == 1) {
      *(undefined *)((int)puVar12 + 5) = 2;
    }
    if ((*(char *)((int)puVar12 + 5) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) {
      *(undefined *)((int)puVar12 + 5) = 0;
      *(undefined *)(puVar12 + 3) = 0;
    }
    if (*(char *)(puVar12 + 3) != '\0') {
      FUN_800379bc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x100008,
                   param_9,CONCAT22(puVar12[1],*puVar12),in_r7,in_r8,in_r9,in_r10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2568
 * EN v1.0 Address: 0x801F2568
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2568(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f259c
 * EN v1.0 Address: 0x801F259C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f259c(int param_1)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 != 0) {
    *(undefined *)(psVar3 + 1) = 1;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  if ((*psVar3 < 1) && (*(char *)(psVar3 + 1) != '\0')) {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x1e));
    if (uVar2 == 0) {
      FUN_8002b95c(param_1,1);
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
      FUN_800201ac((int)*(short *)(iVar4 + 0x20),1);
    }
    else {
      FUN_8002b95c(param_1,0);
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),0);
      FUN_800201ac((int)*(short *)(iVar4 + 0x20),0);
    }
    *(undefined *)(psVar3 + 1) = 0;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  else if (0 < *psVar3) {
    *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f26a4
 * EN v1.0 Address: 0x801F26A4
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f26a4(int param_1,int param_2)
{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  *(char *)(param_1 + 0xad) = (char)uVar1;
  *puVar2 = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(puVar2 + 1) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f270c
 * EN v1.0 Address: 0x801F270C
 * EN v1.0 Size: 444b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f270c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  FUN_8002bac4();
  local_28 = DAT_802c2bfc;
  local_24 = DAT_802c2c00;
  local_20 = DAT_802c2c04;
  if ((*(byte *)(param_9 + 0xaf) & 8) != 0) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) ^ 8;
  }
  uVar1 = FUN_80020078(0x2fb);
  if (uVar1 == 0) {
    if (*(short *)(param_9 + 0xa0) != 7) {
      FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,7,0,param_12,param_13,param_14,param_15,param_16);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    FUN_8002fb40((double)FLOAT_803e6a34,
                 (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6a38));
  }
  else {
    if (*(short *)(param_9 + 0xa0) != 2) {
      FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,2,0,param_12,param_13,param_14,param_15,param_16);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    FUN_8002fb40((double)FLOAT_803e6a34,
                 (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6a38));
  }
  if (((*(byte *)(param_9 + 0xaf) & 1) == 0) || (uVar1 = FUN_80020078(0x2fb), uVar1 != 0)) {
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
       (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_28,3), -1 < iVar2)) {
      FUN_800201ac(0x310,1);
      *(char *)(iVar3 + 0x27) = *(char *)(iVar3 + 0x27) + '\x01';
      FUN_80014b68(0,0x100);
    }
  }
  else {
    FUN_800201ac(0x2fb,1);
    *(undefined *)(iVar3 + 0x27) = 0;
    FUN_80014b68(0,0x100);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f28c8
 * EN v1.0 Address: 0x801F28C8
 * EN v1.0 Size: 1364b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28c8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined8 local_50;
  
  pfVar5 = *(float **)(param_9 + 0x5c);
  FUN_8002bac4();
  local_78 = DAT_802c2bf0;
  local_74 = DAT_802c2bf4;
  local_70 = DAT_802c2bf8;
  *(float *)(param_9 + 8) = pfVar5[1];
  uVar3 = FUN_80020078(0x1fc);
  if (uVar3 == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    if (*(short *)(pfVar5 + 8) < 1) {
      uVar3 = FUN_80022264(1,4);
      if (uVar3 == 3) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 3;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 3) {
        if (uVar3 == 1) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 1;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
        else if (0 < (int)uVar3) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 2;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
      }
      else if (uVar3 == 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 5;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 4;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
    }
    else {
      uVar3 = (uint)*(byte *)((int)pfVar5 + 0x22);
      if (uVar3 == 0xc) {
        dVar7 = (double)*(float *)(&DAT_803295b8 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
        iVar4 = FUN_80021884();
        sVar2 = (short)iVar4 - *param_9;
        FUN_80137cd0();
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -100;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 100;
          }
        }
        else {
          local_50 = (double)(longlong)
                             (int)*(float *)(&DAT_803295bc +
                                            (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          FUN_8003042c((double)FLOAT_803e6a30,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,(int)*(float *)(&DAT_803295bc +
                                              (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14),0,param_12
                       ,param_13,param_14,param_15,param_16);
          pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          *(undefined *)((int)pfVar5 + 0x22) = 0xd;
        }
      }
      else if (uVar3 == 0xd) {
        dVar7 = (double)FLOAT_803dc074;
        iVar4 = FUN_8002fb40((double)pfVar5[3],dVar7);
        if (iVar4 != 0) {
          local_50 = (double)CONCAT44(0x43300000,(int)param_9[0x50] ^ 0x80000000);
          iVar4 = (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14;
          if ((float)(local_50 - DOUBLE_803e6a50) == *(float *)(&DAT_803295bc + iVar4)) {
            local_50 = (double)(longlong)(int)*(float *)(&DAT_803295c0 + iVar4);
            FUN_8003042c((double)FLOAT_803e6a30,dVar7,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,(int)*(float *)(&DAT_803295c0 + iVar4),0,param_12,param_13,
                         param_14,param_15,param_16);
            pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          }
        }
        *(ushort *)(pfVar5 + 8) = *(short *)(pfVar5 + 8) - (ushort)DAT_803dc070;
        if (*(short *)(pfVar5 + 8) < 1) {
          *(undefined2 *)(pfVar5 + 8) = 0;
        }
      }
      else {
        dVar9 = (double)(*(float *)(&DAT_803295b4 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 6) - *pfVar5));
        dVar8 = (double)(*(float *)(&DAT_803295b8 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 10) - pfVar5[2]));
        dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
        dVar7 = dVar8;
        iVar4 = FUN_80021884();
        sVar2 = (short)iVar4 - *param_9;
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (param_9[0x50] != 0xc) {
            FUN_8003042c((double)FLOAT_803e6a30,dVar8,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0xc,0,param_12,param_13,param_14,param_15,param_16);
            pfVar5[3] = FLOAT_803e6a48;
          }
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -300;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 300;
          }
        }
        else {
          if (param_9[0x50] != 0x3b) {
            FUN_8003042c((double)FLOAT_803e6a30,dVar8,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0x3b,0,param_12,param_13,param_14,param_15,param_16);
            pfVar5[3] = FLOAT_803e6a40;
          }
          dVar8 = (double)FLOAT_803e6a44;
          *(float *)(param_9 + 0x12) = (float)(dVar8 * (double)(float)(dVar9 / dVar6));
          *(float *)(param_9 + 0x16) = (float)(dVar8 * (double)(float)(dVar7 / dVar6));
          FUN_8002f6cc(dVar8,(int)param_9,pfVar5 + 3);
        }
        if (dVar6 < (double)FLOAT_803e6a4c) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 0xc;
          fVar1 = FLOAT_803e6a30;
          *(float *)(param_9 + 0x12) = FLOAT_803e6a30;
          *(float *)(param_9 + 0x16) = fVar1;
        }
        *(float *)(param_9 + 6) =
             *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
        *(float *)(param_9 + 10) =
             *(float *)(param_9 + 0x16) * FLOAT_803dc074 + *(float *)(param_9 + 10);
        FUN_8002fb40((double)pfVar5[3],(double)FLOAT_803dc074);
      }
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    if (((*(byte *)((int)param_9 + 0xaf) & 1) != 0) &&
       (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_78,3), -1 < iVar4)) {
      FUN_800201ac(0x4d1,1);
      *(char *)((int)pfVar5 + 0x27) = *(char *)((int)pfVar5 + 0x27) + '\x01';
      FUN_800201ac(0x310,1);
      FUN_80014b68(0,0x100);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2e1c
 * EN v1.0 Address: 0x801F2E1C
 * EN v1.0 Size: 400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2e1c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(short *)(param_9 + 0xa0) != 2) {
    FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8002fb40((double)FLOAT_803e6a34,
               (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e6a38));
  *(undefined *)(iVar3 + 0x24) = 1;
  if (*(char *)(iVar3 + 0x24) == '\0') {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_800201ac(0xd0,1);
      *(undefined *)(iVar3 + 0x24) = 1;
      FUN_80014b68(0,0x100);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      iVar1 = FUN_8002bac4();
      iVar1 = FUN_80297174(iVar1);
      if (iVar1 < 1) {
        uVar2 = FUN_80020078(0xb1);
        if (((uVar2 == 0) || (uVar2 = FUN_80020078(0xb2), uVar2 == 0)) ||
           (uVar2 = FUN_80020078(0xb3), uVar2 == 0)) {
          *(undefined *)(iVar3 + 0x25) = 1;
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
          FUN_80014b68(0,0x100);
        }
      }
      else {
        *(undefined *)(iVar3 + 0x25) = 2;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
        FUN_80014b68(0,0x100);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2fac
 * EN v1.0 Address: 0x801F2FAC
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801f2fac(int param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = FUN_8002bac4();
  iVar4 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(iVar4 + 0x25);
    if (cVar1 == '\x01') {
      if (*(char *)(param_3 + iVar3 + 0x81) == '\x04') {
        FUN_80297184(iVar2,5);
      }
    }
    else if (cVar1 != '\x02') {
      cVar1 = *(char *)(param_3 + iVar3 + 0x81);
      if (cVar1 == '\x01') {
        FUN_800201ac(0xd0,1);
        *(undefined *)(iVar4 + 0x24) = 1;
      }
      else if (cVar1 == '\x02') {
        FUN_80296bd4(iVar2,0,1);
        FUN_80297184(iVar2,5);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f30a8
 * EN v1.0 Address: 0x801F30A8
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801f30a8(int param_1,undefined4 param_2,int param_3)
{
  undefined uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  switch(uVar1) {
  case 1:
    FUN_801f2fac(param_1,param_2,param_3);
    break;
  case 4:
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    break;
  case 6:
    iVar2 = *(int *)(param_1 + 0xb8);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      if ((*(char *)(param_3 + iVar3 + 0x81) == '\x01') && (1 < *(byte *)(iVar2 + 0x27))) {
        FUN_800201ac(0x314,1);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f31d8
 * EN v1.0 Address: 0x801F31D8
 * EN v1.0 Size: 196b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f31d8(void)
{
  int iVar1;
  char cVar3;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
    if (cVar3 == '\x04') {
      uVar2 = FUN_80020078(0x2bd);
      if (uVar2 != 0) {
        FUN_8003b9ec(iVar1);
      }
    }
    else {
      FUN_8003b9ec(iVar1);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f329c
 * EN v1.0 Address: 0x801F329C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f329c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f33f4
 * EN v1.0 Address: 0x801F33F4
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f33f4(undefined2 *param_1,undefined2 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f34e4
 * EN v1.0 Address: 0x801F34E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f34e4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f3518
 * EN v1.0 Address: 0x801F3518
 * EN v1.0 Size: 524b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f3518(uint param_1)
{
  float fVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_1 + 0x4c);
  psVar7 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar7 + 1) = *(char *)(psVar7 + 1) + -1;
  if (*(char *)(psVar7 + 1) < '\0') {
    *(undefined *)(psVar7 + 1) = 0;
  }
  fVar1 = FLOAT_803e6a64;
  if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
    iVar5 = 0;
    for (iVar6 = 0; iVar6 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar6 = iVar6 + 1) {
      if (fVar1 < *(float *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x10) -
                  *(float *)(param_1 + 0x10)) {
        *(undefined *)(psVar7 + 1) = 0x3c;
      }
      iVar5 = iVar5 + 4;
    }
  }
  bVar3 = false;
  if ((((int)*psVar7 == 0xffffffff) || (uVar4 = FUN_80020078((int)*psVar7), uVar4 != 0)) &&
     (*(char *)(psVar7 + 1) != '\0')) {
    fVar2 = FLOAT_803e6a68 + FLOAT_803e6a6c + *(float *)(iVar8 + 0xc);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= fVar2) {
      *(float *)(param_1 + 0x10) = FLOAT_803e6a74 * FLOAT_803dc074 + fVar1;
      if (*(float *)(param_1 + 0x10) <= fVar2) {
        bVar3 = true;
      }
      else {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
    else {
      *(float *)(param_1 + 0x10) = -(FLOAT_803e6a70 * FLOAT_803dc074 - fVar1);
      if (fVar2 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = -(FLOAT_803e6a78 * FLOAT_803dc074 - *(float *)(param_1 + 0x10));
    fVar1 = *(float *)(iVar8 + 0xc);
    if (fVar1 <= *(float *)(param_1 + 0x10)) {
      bVar3 = true;
    }
    else {
      *(float *)(param_1 + 0x10) = fVar1;
    }
  }
  if (bVar3) {
    FUN_8000bb38(param_1,0x7d);
  }
  else {
    FUN_8000b7dc(param_1,8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f3724
 * EN v1.0 Address: 0x801F3724
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f3724(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  if ((param_10 == 0) && (**(int **)(param_9 + 0xb8) != 0)) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 **(int **)(param_9 + 0xb8));
  }
  (**(code **)(*DAT_803dd6fc + 0x18))(param_9);
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f37a8
 * EN v1.0 Address: 0x801F37A8
 * EN v1.0 Size: 124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f37a8(short *param_1)
{
  int iVar1;
  double dVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0xc) == '\x02') {
    *param_1 = *param_1 + 0x32;
  }
  iVar1 = FUN_8002bac4();
  dVar2 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_1 + 0xc));
  if ((double)FLOAT_803e6a80 <= dVar2) {
    FUN_8000b7dc((int)param_1,0x40);
  }
  else {
    FUN_8000bb38((uint)param_1,0x72);
  }
  return;
}
