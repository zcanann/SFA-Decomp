#include "ghidra_import.h"
#include "main/dll/MMP/mmp_barrel.h"

extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern int FUN_80017a90();
extern undefined4 FUN_80017a98();
extern int FUN_80017af0();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_800480a0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern undefined4 FUN_8005ff38();
extern undefined4 FUN_8005ff90();
extern uint FUN_80060058();
extern int FUN_80060064();
extern undefined4 FUN_800600b4();
extern int FUN_800600c4();
extern int FUN_800600e4();
extern undefined4 FUN_800631d4();
extern int FUN_80063298();
extern undefined4 FUN_801a8ae8();
extern undefined4 FUN_801a8b20();
extern undefined4 FUN_80242178();
extern uint FUN_80286810();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined8 FUN_8028682c();
extern uint FUN_80286840();
extern undefined4 FUN_8028685c();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca58;
extern undefined4 DAT_803de768;
extern undefined4 DAT_803de76c;
extern undefined4 DAT_803de770;
extern undefined4 DAT_803de774;
extern f64 DOUBLE_803e4c00;
extern f64 DOUBLE_803e4c20;
extern f64 DOUBLE_803e4c28;
extern f64 DOUBLE_803e4c38;
extern f64 DOUBLE_803e4c60;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e4bdc;
extern f32 FLOAT_803e4be8;
extern f32 FLOAT_803e4bec;
extern f32 FLOAT_803e4bf0;
extern f32 FLOAT_803e4bf4;
extern f32 FLOAT_803e4bf8;
extern f32 FLOAT_803e4bfc;
extern f32 FLOAT_803e4c08;
extern f32 FLOAT_803e4c10;
extern f32 FLOAT_803e4c14;
extern f32 FLOAT_803e4c18;
extern f32 FLOAT_803e4c1c;
extern f32 FLOAT_803e4c30;
extern f32 FLOAT_803e4c40;
extern f32 FLOAT_803e4c44;
extern f32 FLOAT_803e4c48;
extern f32 FLOAT_803e4c4c;
extern f32 FLOAT_803e4c50;
extern f32 FLOAT_803e4c54;
extern f32 FLOAT_803e4c58;
extern f32 FLOAT_803e4c5c;

/*
 * --INFO--
 *
 * Function: waveanimator_func0B
 * EN v1.0 Address: 0x801923C4
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801923CC
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void waveanimator_func0B(undefined2 *param_1,int param_2)
{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *puVar2 = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x19) << 9);
  puVar2[2] = (int)*(short *)(param_2 + 0x1a) << 8;
  *(char *)(puVar2 + 1) = (char)*(undefined2 *)(param_2 + 0x1c);
  puVar2[3] = (int)*(char *)(param_2 + 0x18) << 8;
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  *(byte *)(puVar2 + 5) = (byte)((uVar1 & 1) << 6) | *(byte *)(puVar2 + 5) & 0xbf;
  if ((uVar1 & 1) != 0) {
    puVar2[4] = puVar2[2];
    *(byte *)(puVar2 + 5) = *(byte *)(puVar2 + 5) & 0xdf | 0x20;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192488
 * EN v1.0 Address: 0x80192488
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801924D0
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192488(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_8028682c();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  iVar10 = *(int *)(iVar2 + 0x4c);
  iVar3 = FUN_8005b398((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10));
  iVar3 = FUN_8005af70(iVar3);
  if (iVar3 == 0) {
    *(undefined *)(iVar8 + 0x10) = 1;
  }
  else {
    iVar4 = FUN_80017af0(0xe);
    if ((iVar4 != 0) &&
       (iVar10 = FUN_8005337c(-*(int *)(iVar4 + *(short *)(iVar10 + 0x18) * 4)), iVar10 != 0)) {
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xa2); iVar4 = iVar4 + 1) {
        iVar5 = FUN_800600e4(iVar3,iVar4);
        iVar12 = iVar5;
        for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar5 + 0x41); iVar11 = iVar11 + 1) {
          if (*(int *)(iVar12 + 0x24) == iVar10) {
            iVar7 = (uint)*(ushort *)(iVar10 + 10) << 6;
            iVar1 = (uint)*(ushort *)(iVar10 + 0xc) << 6;
            if (*(byte *)(iVar12 + 0x2a) == 0xff) {
              iVar7 = FUN_80056448((int)*(char *)(iVar8 + 0x11),(int)*(char *)(iVar8 + 0x12),iVar7,
                                   iVar1);
              *(char *)(iVar12 + 0x2a) = (char)iVar7;
            }
            else {
              iVar9 = *(int *)(*(int *)(iVar2 + 0x4c) + 0x14);
              if ((iVar9 == 0x49b2f) || (iVar9 == 0x49b67)) {
                uVar6 = FUN_80017690(*(uint *)(iVar8 + 8));
                if (uVar6 != 0) {
                  FUN_80056418((uint)*(byte *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                               (int)*(char *)(iVar8 + 0x12),iVar7,iVar1);
                }
              }
              else {
                FUN_80056418((uint)*(byte *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                             (int)*(char *)(iVar8 + 0x12),iVar7,iVar1);
              }
            }
          }
          iVar12 = iVar12 + 8;
        }
      }
    }
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192618
 * EN v1.0 Address: 0x80192618
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801926C4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192618(int param_1)
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
 * Function: FUN_80192640
 * EN v1.0 Address: 0x80192640
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801926F8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192640(int param_1)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005af70(iVar1);
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if ((((iVar2 == 0x49b2f) || (iVar2 == 0x49b67)) && (iVar1 != 0)) &&
     ((uVar3 = FUN_80017690(*(uint *)(iVar4 + 8)), *(uint *)(iVar4 + 0xc) != uVar3 &&
      (*(char *)(iVar4 + 0x10) == '\0')))) {
    FUN_80192488();
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  uVar3 = FUN_80017690(*(uint *)(iVar4 + 8));
  *(uint *)(iVar4 + 0xc) = uVar3;
  if (iVar1 == 0) {
    *(undefined *)(iVar4 + 0x10) = 1;
  }
  else if (*(char *)(iVar4 + 0x10) != '\0') {
    FUN_80192488();
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192720
 * EN v1.0 Address: 0x80192720
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801927E4
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192720(int param_1,int param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0x11) = *(undefined *)(param_2 + 0x1e);
  *(undefined *)(iVar1 + 0x12) = *(undefined *)(param_2 + 0x1f);
  *(undefined *)(iVar1 + 0x13) = *(undefined *)(param_2 + 0x1c);
  *(undefined *)(iVar1 + 0x14) = *(undefined *)(param_2 + 0x1d);
  if (param_3 == 0) {
    FUN_80192488();
  }
  *(int *)(iVar1 + 8) = (int)*(short *)(param_2 + 0x1a);
  *(undefined4 *)(iVar1 + 0xc) = 0xffffffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192790
 * EN v1.0 Address: 0x80192790
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80192874
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192790(int param_1)
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
 * Function: FUN_801927b8
 * EN v1.0 Address: 0x801927B8
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x80192974
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801927b8(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short sVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  
  iVar4 = FUN_8028682c();
  DAT_803de774 = FUN_80017830(*(int *)(iVar4 + 0x1c) * *(int *)(iVar4 + 0x1c) * 4,0xffffff);
  DAT_803de76c = FUN_80017830(*(int *)(iVar4 + 0x1c) * *(int *)(iVar4 + 0x1c) * 3,0xffffff);
  fVar3 = FLOAT_803e4bdc;
  *(float *)(iVar4 + 0x28) = FLOAT_803e4bdc;
  *(float *)(iVar4 + 0x24) = fVar3;
  iVar12 = 0;
  for (iVar11 = 0; fVar3 = FLOAT_803e4bdc, iVar11 < *(int *)(iVar4 + 0x1c); iVar11 = iVar11 + 1) {
    iVar7 = iVar12;
    for (iVar10 = 0; iVar10 < *(int *)(iVar4 + 0x1c); iVar10 = iVar10 + 1) {
      dVar13 = (double)FUN_80293f90();
      dVar14 = (double)(float)((double)*(float *)(iVar4 + 0x14) * dVar13);
      dVar13 = (double)FUN_80293f90();
      *(float *)(DAT_803de774 + iVar7) = (float)((double)*(float *)(iVar4 + 0x10) * dVar13 + dVar14)
      ;
      if (*(float *)(DAT_803de774 + iVar7) < *(float *)(iVar4 + 0x24)) {
        *(float *)(iVar4 + 0x24) = *(float *)(DAT_803de774 + iVar7);
      }
      if (*(float *)(iVar4 + 0x28) < *(float *)(DAT_803de774 + iVar7)) {
        *(float *)(iVar4 + 0x28) = *(float *)(DAT_803de774 + iVar7);
      }
      iVar7 = iVar7 + 4;
      iVar12 = iVar12 + 4;
    }
  }
  fVar1 = *(float *)(iVar4 + 0x24);
  iVar11 = 0;
  iVar12 = 0;
  for (iVar7 = 0; iVar7 < *(int *)(iVar4 + 0x1c); iVar7 = iVar7 + 1) {
    iVar10 = iVar11;
    iVar6 = iVar12;
    for (iVar9 = 0; iVar9 < *(int *)(iVar4 + 0x1c); iVar9 = iVar9 + 1) {
      if (fVar3 <= *(float *)(DAT_803de774 + iVar11)) {
        *(undefined *)(DAT_803de76c + iVar12) = 0xff;
        *(undefined *)(DAT_803de76c + iVar12 + 1) = 0xff;
        *(undefined *)(DAT_803de76c + iVar12 + 2) = 0xff;
      }
      else {
        fVar2 = (*(float *)(DAT_803de774 + iVar11) - *(float *)(iVar4 + 0x24)) / -fVar1;
        *(char *)(DAT_803de76c + iVar12) = (char)(int)(FLOAT_803e4bec * fVar2 + FLOAT_803e4be8);
        *(char *)(DAT_803de76c + iVar12 + 1) = (char)(int)(FLOAT_803e4bf4 * fVar2 + FLOAT_803e4bf0);
        *(char *)(DAT_803de76c + iVar12 + 2) = (char)(int)(FLOAT_803e4bfc * fVar2 + FLOAT_803e4bf8);
      }
      iVar11 = iVar11 + 4;
      iVar12 = iVar12 + 3;
      iVar10 = iVar10 + 4;
      iVar6 = iVar6 + 3;
    }
    iVar11 = iVar10;
    iVar12 = iVar6;
  }
  DAT_803de770 = FUN_80017830(*(int *)(iVar4 + 0x20) * *(int *)(iVar4 + 0x20) * 4,0xffffff);
  sVar8 = 0;
  iVar11 = 0;
  for (iVar12 = 0; iVar12 < *(int *)(iVar4 + 0x20); iVar12 = iVar12 + 1) {
    sVar5 = 0;
    iVar7 = iVar11;
    for (iVar10 = 0; iVar10 < *(int *)(iVar4 + 0x20); iVar10 = iVar10 + 1) {
      *(short *)(DAT_803de770 + iVar11) = sVar8;
      *(short *)(DAT_803de770 + iVar11 + 2) = sVar5;
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 4;
      sVar5 = sVar5 + 10;
    }
    sVar8 = sVar8 + 10;
    iVar11 = iVar7;
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192ab4
 * EN v1.0 Address: 0x80192AB4
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80192D50
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192ab4(int param_1)
{
  DAT_803de768 = DAT_803de768 + -1;
  if (DAT_803de768 == '\0') {
    if (DAT_803de774 != 0) {
      FUN_80017814(DAT_803de774);
    }
    if (DAT_803de770 != 0) {
      FUN_80017814(DAT_803de770);
    }
    if (DAT_803de76c != 0) {
      FUN_80017814(DAT_803de76c);
    }
  }
  ObjGroup_RemoveObject(param_1,0x1b);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192b28
 * EN v1.0 Address: 0x80192B28
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80192DCC
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192b28(int param_1)
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
 * Function: FUN_80192b50
 * EN v1.0 Address: 0x80192B50
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80192EE8
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192b50(int param_1,int param_2)
{
  double dVar1;
  float fVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  piVar3[6] = (int)*(char *)(param_2 + 0x20);
  *piVar3 = (int)*(short *)(param_2 + 0x18);
  piVar3[1] = (int)*(short *)(param_2 + 0x1a);
  piVar3[2] = (int)*(char *)(param_2 + 0x1c);
  piVar3[3] = (int)*(char *)(param_2 + 0x1d);
  dVar1 = DOUBLE_803e4c00;
  piVar3[4] = (int)(float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1e) ^ 0x80000000)
                          - DOUBLE_803e4c00);
  piVar3[5] = (int)(float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1f) ^ 0x80000000)
                          - dVar1);
  piVar3[7] = (int)*(char *)(param_2 + 0x21);
  piVar3[8] = (int)*(char *)(param_2 + 0x22);
  fVar2 = FLOAT_803e4c08;
  piVar3[0xb] = (int)FLOAT_803e4c08;
  piVar3[0xc] = (int)fVar2;
  if (DAT_803de768 == '\0') {
    FUN_801927b8();
  }
  ObjGroup_AddObject(param_1,0x1b);
  DAT_803de768 = DAT_803de768 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192c90
 * EN v1.0 Address: 0x80192C90
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80192FF4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192c90(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x10);
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192cc0
 * EN v1.0 Address: 0x80192CC0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80193024
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192cc0(int param_1)
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
 * Function: FUN_80192ce8
 * EN v1.0 Address: 0x80192CE8
 * EN v1.0 Size: 1680b
 * EN v1.1 Address: 0x80193058
 * EN v1.1 Size: 1584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192ce8(void)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  int *piVar8;
  int iVar9;
  
  uVar3 = FUN_80286840();
  iVar9 = *(int *)(uVar3 + 0x4c);
  piVar8 = *(int **)(uVar3 + 0xb8);
  bVar1 = *(byte *)(iVar9 + 0x20);
  bVar7 = bVar1 & 3;
  iVar4 = FUN_8005b398((double)*(float *)(uVar3 + 0xc),(double)*(float *)(uVar3 + 0x10));
  iVar4 = FUN_8005af70(iVar4);
  if (iVar4 == 0) {
    *(undefined *)(piVar8 + 6) = 0;
  }
  else if ((*(ushort *)(iVar4 + 4) & 8) != 0) {
    if (*piVar8 == 0) {
      *(undefined *)((int)piVar8 + 0x16) = *(undefined *)(iVar9 + 0x1e);
      if (*piVar8 == 0) {
        *(undefined *)((int)piVar8 + 0x16) = 0;
      }
      fVar2 = FLOAT_803e4c14;
      if (*(char *)((int)piVar8 + 0x16) == '\0') goto LAB_8019364c;
      piVar8[1] = (int)FLOAT_803e4c14;
      piVar8[2] = (int)fVar2;
      piVar8[3] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 0x22)) -
                              DOUBLE_803e4c20);
      if ((int)*(short *)(iVar9 + 0x18) == 0xffffffff) {
        *(undefined *)((int)piVar8 + 0x17) = 1;
      }
      else {
        uVar5 = FUN_80017690((int)*(short *)(iVar9 + 0x18));
        *(char *)((int)piVar8 + 0x17) = (char)uVar5;
      }
      *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
      if (((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) &&
         (uVar5 = FUN_80017690((int)*(short *)(iVar9 + 0x1a)), uVar5 != 0)) {
        *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
        piVar8[1] = (int)(FLOAT_803e4c10 + (float)piVar8[3]);
        *(undefined *)((int)piVar8 + 0x17) = 1;
      }
      if (bVar7 == 3) {
        iVar6 = FUN_80017830(*piVar8 << 2,5);
        piVar8[4] = iVar6;
      }
      *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) ^ 1;
      *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) ^ 1;
    }
    if (*(char *)((int)piVar8 + 0x16) != '\0') {
      if (bVar7 == 2) {
        uVar5 = FUN_80017690((int)*(short *)(iVar9 + 0x18));
        *(char *)((int)piVar8 + 0x17) = (char)uVar5;
        if (('\x02' < *(char *)(piVar8 + 6)) &&
           (*(char *)((int)piVar8 + 0x17) != *(char *)((int)piVar8 + 0x19))) {
          if ((int)(uint)*(byte *)(iVar9 + 0x20) >> 2 != 0) {
            FUN_80006824(uVar3,*(ushort *)(iVar9 + 0x24));
          }
          *(undefined *)(piVar8 + 6) = 0;
          *(undefined *)((int)piVar8 + 0x19) = *(undefined *)((int)piVar8 + 0x17);
        }
        if ('\x02' < *(char *)(piVar8 + 6)) goto LAB_8019364c;
      }
      else {
        if ('\x02' < *(char *)(piVar8 + 6)) goto LAB_8019364c;
        if (*(char *)((int)piVar8 + 0x17) == '\0') {
          uVar5 = FUN_80017690((int)*(short *)(iVar9 + 0x18));
          *(char *)((int)piVar8 + 0x17) = (char)uVar5;
          if (*(char *)((int)piVar8 + 0x17) == '\0') goto LAB_8019364c;
          if ((int)(uint)*(byte *)(iVar9 + 0x20) >> 2 != 0) {
            FUN_80006824(uVar3,*(ushort *)(iVar9 + 0x24));
          }
        }
      }
      if (bVar7 == 2) {
        if (*(char *)((int)piVar8 + 0x17) == '\0') {
          if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if ((short)(ushort)*(byte *)(iVar9 + 0x1c) <= *(short *)(piVar8 + 5)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_80017698((int)*(short *)(iVar9 + 0x1a),0);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1c)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_80017698((int)*(short *)(iVar9 + 0x1a),0);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
            *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
            if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
              FUN_80017698((int)*(short *)(iVar9 + 0x1a),1);
            }
            *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
          }
        }
        else {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if ((short)(ushort)*(byte *)(iVar9 + 0x1d) <= *(short *)(piVar8 + 5)) {
            *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
            if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
              FUN_80017698((int)*(short *)(iVar9 + 0x1a),1);
            }
            *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
          }
        }
      }
      else if (bVar7 < 2) {
        if ((bVar1 & 3) == 0) {
          if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_80017698((int)*(short *)(iVar9 + 0x1a),1);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if ((short)(ushort)*(byte *)(iVar9 + 0x1d) <= *(short *)(piVar8 + 5)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_80017698((int)*(short *)(iVar9 + 0x1a),1);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if (*(short *)(piVar8 + 5) < (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
            *(ushort *)(piVar8 + 5) =
                 (ushort)*(byte *)(iVar9 + 0x1c) -
                 ((ushort)*(byte *)(iVar9 + 0x1d) - *(short *)(piVar8 + 5));
          }
        }
        else {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if ((short)(ushort)*(byte *)(iVar9 + 0x1c) < *(short *)(piVar8 + 5)) {
            *(short *)(piVar8 + 5) = *(short *)(piVar8 + 5);
          }
        }
      }
      else if (bVar7 < 4) {
        uVar3 = (uint)*(char *)(iVar9 + 0x1f);
        if ((int)uVar3 < 0) {
          uVar3 = -uVar3;
        }
        piVar8[1] = (int)(((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e4c28
                                  ) / FLOAT_803e4c18) * FLOAT_803dc074 + (float)piVar8[1]);
        if ((float)piVar8[3] < (float)piVar8[1]) {
          piVar8[1] = piVar8[3];
          FUN_80017698((int)*(short *)(iVar9 + 0x1a),1);
          *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
        }
        piVar8[2] = (int)((float)piVar8[1] - FLOAT_803e4c1c);
      }
    }
  }
LAB_8019364c:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80193378
 * EN v1.0 Address: 0x80193378
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80193688
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80193378(int param_1)
{
  return ((uint)(byte)((FLOAT_803e4c30 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x20)) -
                               DOUBLE_803e4c38) < *(float *)(*(int *)(param_1 + 0xb8) + 0xc)) << 2)
         << 0x1c) >> 0x1e;
}

/*
 * --INFO--
 *
 * Function: FUN_801933d8
 * EN v1.0 Address: 0x801933D8
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801936D0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801933d8(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  fVar1 = *(float *)(param_2 + 0x10) - *(float *)(param_1 + 0x10);
  if ((fVar1 < FLOAT_803e4c40) || (FLOAT_803e4c44 < fVar1)) {
    dVar7 = (double)FLOAT_803e4c48;
  }
  else {
    fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 0xc);
    fVar2 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 0x14);
    fVar3 = FLOAT_803e4c4c + *(float *)(iVar5 + 0x14);
    if (fVar1 * fVar1 + fVar2 * fVar2 <= fVar3 * fVar3) {
      fVar1 = FLOAT_803e4c30 *
              (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x20)) - DOUBLE_803e4c38);
      if ((fVar1 <= *(float *)(iVar5 + 0xc)) && (*(int *)(iVar5 + 8) != 0)) {
        *(float *)(iVar5 + 0xc) = fVar1;
        iVar4 = *(int *)(iVar5 + 8);
        if (*(short *)(iVar4 + 0x46) == 0x519) {
          FUN_801a8b20(iVar4,'\0');
        }
        else {
          (**(code **)(**(int **)(iVar4 + 0x68) + 0x24))(iVar4,0);
        }
      }
      *(float *)(iVar5 + 0xc) = FLOAT_803e4c54 * FLOAT_803dc074 + *(float *)(iVar5 + 0xc);
      *(byte *)(iVar5 + 0x2d) = *(byte *)(iVar5 + 0x2d) | 4;
      dVar7 = (double)(*(float *)(iVar5 + 0x14) *
                      (*(float *)(iVar5 + 0xc) /
                      (FLOAT_803e4c30 *
                      (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x20)) -
                             DOUBLE_803e4c38))));
    }
    else {
      dVar7 = (double)FLOAT_803e4c50;
    }
  }
  return dVar7;
}

/*
 * --INFO--
 *
 * Function: FUN_80193544
 * EN v1.0 Address: 0x80193544
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x80193844
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80193544(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar18;
  double in_f31;
  double dVar19;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  float local_a8;
  float local_a4;
  float local_a0;
  longlong local_98;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined8 local_80;
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
  uVar20 = FUN_8028681c();
  iVar8 = (int)((ulonglong)uVar20 >> 0x20);
  piVar6 = (int *)uVar20;
  iVar2 = FUN_8005b398((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10));
  iVar2 = FUN_8005af70(iVar2);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 4) & 8) != 0)) {
    dVar16 = (double)FUN_802924c4();
    local_98 = (longlong)(int)dVar16;
    dVar17 = (double)FUN_802924c4();
    local_90 = (longlong)(int)dVar17;
    uStack_84 = (int)dVar16 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar19 = (double)(*(float *)(iVar8 + 0xc) -
                     (FLOAT_803e4c58 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e4c60) +
                     FLOAT_803dda58));
    local_80 = (double)CONCAT44(0x43300000,(int)dVar17 ^ 0x80000000);
    dVar17 = (double)(*(float *)(iVar8 + 0x14) -
                     (FLOAT_803e4c58 * (float)(local_80 - DOUBLE_803e4c60) + FLOAT_803dda5c));
    iVar10 = 0;
    *(undefined *)((int)piVar6 + 0x2a) = 0;
    dVar16 = (double)((float)piVar6[5] * (float)piVar6[5]);
    iVar9 = 0;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar8 = iVar8 + 1) {
      puVar3 = (ushort *)FUN_800600c4(iVar2,iVar8);
      uVar4 = FUN_80060058((int)puVar3);
      if (*(byte *)(param_3 + 0x25) == uVar4) {
        dVar18 = (double)FLOAT_803e4c5c;
        iVar11 = iVar9;
        iVar12 = iVar10;
        for (uVar4 = (uint)*puVar3; (int)uVar4 < (int)(uint)puVar3[10]; uVar4 = uVar4 + 1) {
          puVar5 = (ushort *)FUN_800600b4(iVar2,uVar4);
          iVar7 = 0;
          iVar13 = iVar11;
          iVar14 = iVar12;
          do {
            FUN_8005ff90((short *)(*(int *)(iVar2 + 0x58) + (uint)*puVar5 * 6),&local_a8);
            dVar15 = (double)(float)((double)((float)((double)local_a8 - dVar19) *
                                              (float)((double)local_a8 - dVar19) +
                                             (float)((double)local_a0 - dVar17) *
                                             (float)((double)local_a0 - dVar17)) / dVar16);
            if (dVar18 < dVar15) {
              dVar15 = dVar18;
            }
            *(float *)(*piVar6 + iVar14) = (float)(dVar18 - (double)(float)(dVar15 * dVar15));
            local_80 = (double)(longlong)(int)local_a4;
            *(short *)(piVar6[1] + iVar13) = (short)(int)local_a4;
            iVar14 = iVar14 + 4;
            iVar13 = iVar13 + 2;
            iVar12 = iVar12 + 4;
            iVar11 = iVar11 + 2;
            iVar10 = iVar10 + 4;
            iVar9 = iVar9 + 2;
            puVar5 = puVar5 + 1;
            iVar7 = iVar7 + 1;
          } while (iVar7 < 3);
        }
        bVar1 = *(byte *)((int)piVar6 + 0x2a);
        *(byte *)((int)piVar6 + 0x2a) = bVar1 + 1;
        *(short *)((int)piVar6 + (uint)bVar1 * 2 + 0x1c) = (short)iVar8;
      }
    }
  }
  FUN_80286868();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80193800
 * EN v1.0 Address: 0x80193800
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80193ACC
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80193800(void)
{
  int iVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  uint uVar5;
  uint uVar6;
  short *psVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined8 uVar15;
  float fStack_58;
  float local_54;
  undefined4 local_48;
  uint uStack_44;
  
  uVar15 = FUN_80286820();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  puVar9 = *(uint **)(iVar1 + 0xb8);
  iVar8 = *(int *)(iVar1 + 0x4c);
  if ((int)uVar15 == 0) {
    iVar2 = FUN_8005b398((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10));
    iVar2 = FUN_8005af70(iVar2);
    if (iVar2 != 0) {
      iVar12 = 0;
      for (iVar11 = 0; iVar11 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar11 = iVar11 + 1) {
        puVar3 = (ushort *)FUN_800600c4(iVar2,iVar11);
        uVar6 = FUN_80060058((int)puVar3);
        if (*(byte *)(iVar8 + 0x25) == uVar6) {
          iVar13 = iVar12;
          for (uVar6 = (uint)*puVar3; (int)uVar6 < (int)(uint)puVar3[10]; uVar6 = uVar6 + 1) {
            puVar4 = (ushort *)FUN_800600b4(iVar2,uVar6);
            iVar10 = 0;
            iVar14 = iVar13;
            do {
              psVar7 = (short *)(*(int *)(iVar2 + 0x58) + (uint)*puVar4 * 6);
              FUN_8005ff90(psVar7,&fStack_58);
              uVar5 = puVar9[1];
              if (uVar5 != 0) {
                uStack_44 = (int)*(short *)(uVar5 + iVar14) ^ 0x80000000;
                local_48 = 0x43300000;
                local_54 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4c60);
                FUN_8005ff38(psVar7,&fStack_58);
              }
              iVar14 = iVar14 + 2;
              iVar13 = iVar13 + 2;
              iVar12 = iVar12 + 2;
              puVar4 = puVar4 + 1;
              iVar10 = iVar10 + 1;
            } while (iVar10 < 3);
          }
        }
      }
    }
  }
  uVar6 = *puVar9;
  if (uVar6 != 0) {
    FUN_80017814(uVar6);
  }
  ObjGroup_RemoveObject(iVar1,0x31);
  FUN_8028686c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80193924
 * EN v1.0 Address: 0x80193924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80193C2C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80193924(int param_1)
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
 * Function: FUN_8019394c
 * EN v1.0 Address: 0x8019394C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80193C5C
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019394c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80193950
 * EN v1.0 Address: 0x80193950
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80194238
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80193950(int param_1,int param_2)
{
  double dVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar3 + 0x2b) = (char)*(undefined2 *)(param_2 + 0x1e);
  dVar1 = DOUBLE_803e4c38;
  *(float *)(iVar3 + 0x18) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x27)) - DOUBLE_803e4c38);
  *(float *)(iVar3 + 0x10) = FLOAT_803e4c50;
  *(float *)(iVar3 + 0x14) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x26)) - dVar1);
  if (*(char *)(param_2 + 0x25) != '\0') {
    uVar2 = FUN_80017690((int)*(short *)(param_2 + 0x18));
    if (uVar2 != 0) {
      *(float *)(iVar3 + 0xc) =
           FLOAT_803e4c30 *
           (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - DOUBLE_803e4c38);
      *(byte *)(iVar3 + 0x2d) = *(byte *)(iVar3 + 0x2d) | 2;
    }
    ObjGroup_AddObject(param_1,0x31);
    if (1 < *(byte *)(param_2 + 0x21)) {
      *(undefined *)(param_2 + 0x21) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80193a50
 * EN v1.0 Address: 0x80193A50
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80194338
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80193a50(undefined4 param_1,undefined4 param_2,char *param_3,int param_4)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar1 = FUN_80286840();
  if ((*(byte *)(param_4 + 0x1c) & 0x10) == 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar5 = iVar5 + 1) {
      iVar3 = FUN_800600c4(iVar1,iVar5);
      uVar2 = FUN_80060058(iVar3);
      if (*(byte *)(param_4 + 0x1b) == uVar2) {
        if (*param_3 == '\0') {
          *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 2;
          if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
            *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 1;
          }
        }
        else {
          *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffd;
          if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
            *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffe;
          }
        }
      }
    }
  }
  if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar5 = iVar5 + 1) {
      iVar3 = FUN_800600e4(iVar1,iVar5);
      iVar4 = FUN_800480a0(iVar3,0);
      if (*(char *)(param_4 + 0x1b) == *(char *)(iVar4 + 5)) {
        if (*param_3 == '\0') {
          *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) | 2;
        }
        else {
          *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) & 0xfffffffd;
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
 * Function: FUN_80193ba8
 * EN v1.0 Address: 0x80193BA8
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801944AC
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80193ba8(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar1 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005af70(iVar1);
  if (iVar1 == 0) {
    pbVar4[1] = pbVar4[1] & 0xfe;
    pbVar4[1] = pbVar4[1] | 4;
  }
  else {
    uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x18));
    pbVar4[2] = (byte)uVar2;
    if (pbVar4[3] != pbVar4[2]) {
      *pbVar4 = *pbVar4 ^ 1;
      if (*(char *)(iVar5 + 0x1a) == '\x01') {
        pbVar4[1] = pbVar4[1] | 1;
      }
      if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if ((*(byte *)(iVar5 + 0x1c) & 4) != 0) {
        pbVar4[1] = pbVar4[1] | 4;
      }
    }
    pbVar4[3] = pbVar4[2];
    if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
      iVar3 = FUN_80063298();
      if (iVar3 != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if (((pbVar4[1] & 2) != 0) && (iVar3 = FUN_80063298(), iVar3 == 0)) {
        FUN_800631d4((uint)*(byte *)(iVar5 + 0x1d),*(int *)(param_1 + 0x30),(int)(char)*pbVar4);
        pbVar4[1] = pbVar4[1] & 0xfd;
      }
    }
    if ((((*(byte *)(iVar5 + 0x1c) & 4) != 0) && (*(char *)(iVar5 + 0x1b) != '\0')) &&
       ((pbVar4[1] & 4) != 0)) {
      FUN_80193a50(iVar1,param_1,(char *)pbVar4,iVar5);
      pbVar4[1] = pbVar4[1] & 0xfb;
    }
  }
  return;
}
