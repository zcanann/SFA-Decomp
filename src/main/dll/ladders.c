#include "ghidra_import.h"
#include "main/dll/ladders.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern double FUN_80017714();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80035d58();
extern undefined4 FUN_800360d4();
extern void* FUN_80037134();
extern int fn_80037B60();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_8016157c();
extern undefined4 FUN_801615d4();
extern undefined4 FUN_80161708();
extern undefined4 FUN_80161920();
extern undefined4 FUN_80161984();
extern undefined4 FUN_80161a8c();
extern undefined4 FUN_80161c08();
extern undefined4 FUN_80161d30();
extern undefined4 FUN_80161ea0();
extern undefined4 FUN_80161f0c();
extern undefined4 FUN_801620c0();
extern undefined4 FUN_8016228c();
extern undefined4 FUN_80162450();
extern undefined4 FUN_801628c4();
extern undefined4 FUN_80162b78();
extern undefined4 FUN_80162ec0();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_80320d30;
extern undefined4 DAT_80320da8;
extern undefined4 DAT_803ad258;
extern undefined4 DAT_803ad25c;
extern undefined4 DAT_803ad260;
extern undefined4 DAT_803ad264;
extern undefined4 DAT_803ad268;
extern undefined4 DAT_803ad26c;
extern undefined4 DAT_803ad270;
extern undefined4 DAT_803ad274;
extern undefined4 DAT_803ad278;
extern undefined4 DAT_803ad27c;
extern undefined4 DAT_803ad280;
extern undefined4 DAT_803ad284;
extern undefined4 DAT_803ad288;
extern undefined4 DAT_803ad28c;
extern undefined4 DAT_803ad290;
extern undefined4 DAT_803ad294;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de700;
extern f64 DOUBLE_803e3ba8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e3b50;
extern f32 FLOAT_803e3b54;
extern f32 FLOAT_803e3bc0;
extern f32 FLOAT_803e3bcc;
extern f32 FLOAT_803e3bd0;
extern f32 FLOAT_803e3bd8;
extern f32 FLOAT_803e3be0;
extern f32 FLOAT_803e3be4;
extern f32 FLOAT_803e3be8;
extern f32 FLOAT_803e3bec;
extern f32 FLOAT_803e3bf0;

/*
 * --INFO--
 *
 * Function: cannonclaw_update
 * EN v1.0 Address: 0x801630EC
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801630F0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cannonclaw_update(short *param_1)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  iVar3 = *(int *)(iVar4 + 0x40c);
  iVar2 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(iVar3 + 0x34) == 0) {
      FUN_80162ec0(param_1);
    }
    else {
      (**(code **)(*DAT_803dd70c + 8))
                ((double)FLOAT_803e3b54,(double)FLOAT_803e3b54,param_1,iVar4,&DAT_803ad270,
                 &DAT_803ad258);
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)*(float *)(iVar3 + 0x48),*(int *)(iVar3 + 0x38),param_1 + 6,param_1 + 8,
                 param_1 + 10);
      (**(code **)(*DAT_803dd738 + 0x54))
                (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),iVar4 + 0x405,0,0,0);
      iVar2 = (**(code **)(*DAT_803dd738 + 0x50))
                        (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),&DAT_80320d30,
                         &DAT_80320da8,3,0);
      if (iVar2 == 0xe) {
        *(undefined *)(iVar4 + 0x405) = 2;
        uVar1 = FUN_80017a98();
        *(undefined4 *)(iVar4 + 0x2d0) = uVar1;
      }
      if ((*(int *)(iVar4 + 0x2d0) == 0) && (*(char *)(iVar4 + 0x354) != '\0')) {
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
        iVar2 = (**(code **)(*DAT_803dd738 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar4 + 0x3fe)) -
                                          DOUBLE_803e3ba8),param_1,iVar4,0x8000);
        if (iVar2 != 0) {
          *(int *)(iVar4 + 0x2d0) = iVar2;
          *(undefined *)(iVar4 + 0x349) = 0;
        }
      }
      else {
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
        iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar4 + 0x3fe)) -
                                          DOUBLE_803e3ba8),param_1,iVar4,1);
        if (iVar2 != 0) {
          *(undefined4 *)(iVar4 + 0x2d0) = 0;
        }
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar2 + 0x14));
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dd738 + 0x58))
                ((double)FLOAT_803e3bc0,param_1,iVar2,iVar4,10,6,0x10e,0x36);
      *(undefined2 *)(iVar4 + 0x270) = 1;
      *(undefined *)(iVar4 + 0x27b) = 1;
      *(undefined *)(param_1 + 0x1b) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163388
 * EN v1.0 Address: 0x80163388
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80163390
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163388(int param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8016338c
 * EN v1.0 Address: 0x8016338C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8016344C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016338c(void)
{
  FUN_801633ac();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801633ac
 * EN v1.0 Address: 0x801633AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8016346C
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801633ac(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801633b0
 * EN v1.0 Address: 0x801633B0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80163554
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801633b0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801633e4
 * EN v1.0 Address: 0x801633E4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80163598
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801633e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  
  FUN_80017a90();
  iVar1 = FUN_80017af8(0x1723);
  if (*(int *)(param_9 + 0xf4) == 0) {
    if (*(short *)(param_9 + 0xa0) != 0x208) {
      FUN_800305f8((double)FLOAT_803e3bcc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x208,0,param_12,param_13,param_14,param_15,param_16);
    }
    FUN_8002fc3c((double)FLOAT_803e3bd0,(double)FLOAT_803dc074);
    if ((iVar1 != 0) &&
       (uVar2 = FUN_80017690((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1a)), uVar2 != 0)) {
      *(undefined4 *)(param_9 + 0xf4) = 1;
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      FUN_800360d4(param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163544
 * EN v1.0 Address: 0x80163544
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x80163674
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163544(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined2 *puVar7;
  undefined4 uVar8;
  int iVar9;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  int unaff_r29;
  int iVar11;
  int iVar12;
  double dVar13;
  undefined auStack_28 [4];
  int local_24;
  int local_20 [8];
  
  iVar4 = FUN_80286840();
  iVar12 = *(int *)(iVar4 + 0xb8);
  iVar11 = *(int *)(iVar4 + 0x4c);
  sVar1 = *(short *)(iVar4 + 0x46);
  if (sVar1 == 0x4b9) {
    unaff_r29 = 0x4ba;
  }
  else if (sVar1 < 0x4b9) {
    if (sVar1 == 0x3fd) {
      unaff_r29 = 0x3fb;
    }
    else if ((sVar1 < 0x3fd) && (sVar1 == 0x28d)) {
      iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
      if (iVar5 == 0) goto LAB_80163950;
      unaff_r29 = 0x39d;
    }
  }
  else if (sVar1 == 0x4be) {
    unaff_r29 = 0x4c1;
  }
  local_20[0] = 0;
  iVar10 = -1;
  iVar5 = iVar12;
  while ((local_20[0] < (int)(uint)*(byte *)(iVar12 + 0x50) && (iVar10 == -1))) {
    if (*(int *)(iVar5 + 0xc) == 0) {
      iVar10 = local_20[0];
    }
    iVar5 = iVar5 + 4;
    local_20[0] = local_20[0] + 1;
  }
  if (iVar10 != -1) {
    iVar5 = FUN_80017b00(local_20,&local_24);
    iVar9 = 0;
    while (local_20[0] < local_24) {
      iVar3 = local_20[0] + 1;
      iVar2 = local_20[0] * 4;
      local_20[0] = iVar3;
      if (unaff_r29 == *(short *)(*(int *)(iVar5 + iVar2) + 0x46)) {
        iVar9 = iVar9 + 1;
      }
    }
    if ((iVar9 < 7) && (uVar6 = FUN_80017ae8(), (uVar6 & 0xff) != 0)) {
      puVar7 = FUN_80017aa4(0x20,(short)unaff_r29);
      iVar5 = iVar12 + iVar10 * 0xc;
      *(float *)(puVar7 + 4) = *(float *)(iVar4 + 0xc) + *(float *)(iVar5 + 0x1c);
      *(float *)(puVar7 + 6) = *(float *)(iVar4 + 0x10) + *(float *)(iVar5 + 0x20);
      dVar13 = (double)*(float *)(iVar4 + 0x14);
      *(float *)(puVar7 + 8) = (float)(dVar13 + (double)*(float *)(iVar5 + 0x24));
      *(undefined *)(puVar7 + 2) = *(undefined *)(iVar11 + 4);
      *(undefined *)((int)puVar7 + 5) = *(undefined *)(iVar11 + 5);
      *(undefined *)(puVar7 + 3) = *(undefined *)(iVar11 + 6);
      *(undefined *)((int)puVar7 + 7) = *(undefined *)(iVar11 + 7);
      *(float *)(puVar7 + 0xe) = FLOAT_803e3bd8;
      if (((*(byte *)(iVar12 + 0x4c) & 1) != 0) &&
         ((*(int *)(*(int *)(iVar4 + 0x4c) + 0x14) == 0x292c && (*(short *)(iVar12 + 0x4e) == 6))))
      {
        *(undefined *)((int)puVar7 + 0x1b) = 1;
        iVar11 = FUN_80017b00(local_20,&local_24);
        for (; local_20[0] < local_24; local_20[0] = local_20[0] + 1) {
          iVar5 = *(int *)(iVar11 + local_20[0] * 4);
          if (*(short *)(iVar5 + 0x46) == 0x27f) {
            *(undefined4 *)(puVar7 + 4) = *(undefined4 *)(iVar5 + 0xc);
            *(undefined4 *)(puVar7 + 6) = *(undefined4 *)(*(int *)(iVar11 + local_20[0] * 4) + 0x10)
            ;
            *(undefined4 *)(puVar7 + 8) = *(undefined4 *)(*(int *)(iVar11 + local_20[0] * 4) + 0x14)
            ;
            local_20[0] = local_24;
          }
        }
      }
      uVar8 = FUN_80017ae4(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7,5,
                           *(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30),in_r8,
                           in_r9,in_r10);
      iVar11 = iVar12 + iVar10 * 4;
      *(undefined4 *)(iVar11 + 0xc) = uVar8;
      (**(code **)(**(int **)(*(int *)(iVar11 + 0xc) + 0x68) + 0x24))
                ((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14));
      *(short *)(iVar12 + 0x4e) = *(short *)(iVar12 + 0x4e) + 1;
    }
  }
LAB_80163950:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801638bc
 * EN v1.0 Address: 0x801638BC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801639B8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801638bc(int param_1)
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
 * Function: FUN_801638e4
 * EN v1.0 Address: 0x801638E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801639EC
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801638e4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801638e8
 * EN v1.0 Address: 0x801638E8
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x80163B9C
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801638e8(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  ushort uVar2;
  ushort *puVar3;
  int iVar4;
  float *pfVar5;
  float *pfVar6;
  int unaff_r30;
  uint uVar7;
  float *pfVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  pfVar8 = *(float **)(puVar3 + 0x5c);
  *pfVar8 = FLOAT_803e3be0;
  *(ushort *)(pfVar8 + 2) = (ushort)*(byte *)(iVar4 + 0x1b) << 1;
  *(undefined *)(pfVar8 + 0x13) = *(undefined *)(iVar4 + 0x23);
  puVar3[2] = (*(byte *)(iVar4 + 0x18) - 0x7f) * 0x80;
  puVar3[1] = (*(byte *)(iVar4 + 0x19) - 0x7f) * 0x80;
  *puVar3 = (ushort)*(byte *)(iVar4 + 0x1a) << 8;
  *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar4 + 0x1c);
  fVar1 = *(float *)(puVar3 + 4);
  FUN_80035d58((int)puVar3,(short)(int)(FLOAT_803e3be4 * fVar1),(short)(int)(FLOAT_803e3be8 * fVar1)
               ,(short)(int)(FLOAT_803e3bec * fVar1));
  uVar2 = puVar3[0x23];
  if (uVar2 != 0x4b9) {
    if ((short)uVar2 < 0x4b9) {
      if (uVar2 == 0x3fd) {
        *(undefined *)(pfVar8 + 0x14) = 3;
        unaff_r30 = 1;
        goto LAB_80163cb0;
      }
      if ((0x3fc < (short)uVar2) || (uVar2 != 0x28d)) goto LAB_80163cb0;
    }
    else if (uVar2 != 0x4be) goto LAB_80163cb0;
  }
  *(undefined *)(pfVar8 + 0x14) = 3;
  unaff_r30 = 0;
LAB_80163cb0:
  if (param_3 == 0) {
    uVar7 = unaff_r30 * 0x30 + 0x80320e38;
    pfVar5 = pfVar8;
    pfVar6 = pfVar8;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(pfVar8 + 0x14); iVar4 = iVar4 + 1) {
      pfVar6[3] = 0.0;
      FUN_80003494((uint)(pfVar5 + 7),uVar7,0xc);
      pfVar5[7] = pfVar5[7] * *(float *)(puVar3 + 4);
      pfVar5[8] = pfVar5[8] * *(float *)(puVar3 + 4);
      pfVar5[9] = pfVar5[9] * *(float *)(puVar3 + 4);
      FUN_80017748(puVar3,pfVar5 + 7);
      pfVar6 = pfVar6 + 1;
      uVar7 = uVar7 + 0xc;
      pfVar5 = pfVar5 + 3;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80163ac8
 * EN v1.0 Address: 0x80163AC8
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x80163D68
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80163ac8(float *param_1)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  int local_28 [2];
  
  dVar6 = (double)FLOAT_803e3bf0;
  iVar3 = 0;
  piVar1 = FUN_80037134(0x31,local_28);
  for (iVar4 = 0; iVar4 < local_28[0]; iVar4 = iVar4 + 1) {
    iVar2 = *piVar1;
    if (((*(short *)(iVar2 + 0x46) == 0x3fb) && (1 < *(byte *)(*(int *)(iVar2 + 0xb8) + 0x278))) &&
       (dVar5 = FUN_80017714((float *)(iVar2 + 0x18),param_1), dVar5 < dVar6)) {
      iVar3 = *piVar1;
      dVar6 = dVar5;
    }
    piVar1 = piVar1 + 1;
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80163b8c
 * EN v1.0 Address: 0x80163B8C
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80163E2C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80163b8c(int param_1)
{
  *(undefined *)(*(int *)(param_1 + 0xb8) + 0x278) = 7;
  return;
}
