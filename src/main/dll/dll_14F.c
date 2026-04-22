#include "ghidra_import.h"
#include "main/dll/dll_14F.h"

extern bool FUN_8000b598();
extern bool FUN_8000b5f0();
extern undefined4 FUN_8000b7dc();
extern undefined8 FUN_8000bb38();
extern undefined4 FUN_80010340();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern double FUN_80021730();
extern undefined4 FUN_80021754();
extern double FUN_80021794();
extern undefined4 FUN_800217c8();
extern uint FUN_80021884();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern undefined4 FUN_800238c4();
extern undefined8 FUN_8002ad08();
extern undefined4 FUN_8002b070();
extern byte FUN_8002b11c();
extern undefined4 FUN_8002b128();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8002f66c();
extern int FUN_8002fb40();
extern undefined4 FUN_800303fc();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035ea4();
extern undefined8 FUN_80035ff8();
extern ushort FUN_80036074();
extern undefined4 FUN_80036548();
extern int FUN_80036868();
extern int FUN_80036974();
extern undefined4 FUN_80036f50();
extern void* FUN_80037048();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800375e4();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_80037a5c();
extern undefined8 FUN_80037da8();
extern undefined4 FUN_80037e24();
extern undefined4 FUN_80038524();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();
extern int FUN_8005a288();
extern int FUN_80064248();
extern int FUN_80065fcc();
extern undefined4 FUN_8009a468();
extern int FUN_800da4c8();
extern bool FUN_800dac0c();
extern undefined4 FUN_800dbcd8();
extern uint FUN_800dbf88();
extern int FUN_8012f000();
extern int FUN_8013930c();
extern undefined4 FUN_80181c50();
extern undefined4 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern uint FUN_8029698c();
extern byte FUN_80296ba8();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca00;
extern undefined4 DAT_803dca08;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803e4580;
extern f64 DOUBLE_803e44f8;
extern f64 DOUBLE_803e4500;
extern f64 DOUBLE_803e4570;
extern f64 DOUBLE_803e45b0;
extern f64 DOUBLE_803e45b8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dca0c;
extern f32 FLOAT_803dca10;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e44ec;
extern f32 FLOAT_803e44f0;
extern f32 FLOAT_803e44f4;
extern f32 FLOAT_803e4508;
extern f32 FLOAT_803e450c;
extern f32 FLOAT_803e4510;
extern f32 FLOAT_803e4518;
extern f32 FLOAT_803e451c;
extern f32 FLOAT_803e4524;
extern f32 FLOAT_803e4528;
extern f32 FLOAT_803e452c;
extern f32 FLOAT_803e4530;
extern f32 FLOAT_803e4538;
extern f32 FLOAT_803e4540;
extern f32 FLOAT_803e4548;
extern f32 FLOAT_803e4550;
extern f32 FLOAT_803e4554;
extern f32 FLOAT_803e4558;
extern f32 FLOAT_803e455c;
extern f32 FLOAT_803e4560;
extern f32 FLOAT_803e4564;
extern f32 FLOAT_803e4568;
extern f32 FLOAT_803e456c;
extern f32 FLOAT_803e4578;
extern f32 FLOAT_803e4584;
extern f32 FLOAT_803e4588;
extern f32 FLOAT_803e458c;
extern f32 FLOAT_803e4590;
extern f32 FLOAT_803e4594;
extern f32 FLOAT_803e4598;
extern f32 FLOAT_803e459c;
extern f32 FLOAT_803e45a0;
extern f32 FLOAT_803e45a4;
extern f32 FLOAT_803e45a8;
extern f32 FLOAT_803e45ac;
extern f32 FLOAT_803e45c0;
extern f32 FLOAT_803e45d0;

/*
 * --INFO--
 *
 * Function: FUN_8017f548
 * EN v1.0 Address: 0x8017F548
 * EN v1.0 Size: 836b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f548(undefined2 *param_1)
{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  byte *pbVar5;
  int iVar6;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e44ec;
  iVar6 = *(int *)(param_1 + 0x26);
  pbVar5 = *(byte **)(param_1 + 0x5c);
  if (*(int *)(pbVar5 + 4) == 0) {
    uVar2 = FUN_80036f50((uint)*(byte *)(iVar6 + 0x21),param_1,local_18);
    *(undefined4 *)(pbVar5 + 4) = uVar2;
    if (*(int *)(pbVar5 + 4) == 0) {
      return;
    }
    if ((int)*(short *)(iVar6 + 0x1a) == 0xffffffff) {
      pbVar5[1] = 0;
    }
    else {
      uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x1a));
      pbVar5[1] = (byte)uVar3;
    }
    if ((pbVar5[1] == 0) || (*(short *)(iVar6 + 0x1e) == -1)) {
      *pbVar5 = 2;
    }
    else {
      *pbVar5 = 1;
    }
  }
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0xc);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0x10);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(pbVar5 + 4) + 0x14);
  *param_1 = **(undefined2 **)(pbVar5 + 4);
  param_1[2] = *(undefined2 *)(*(int *)(pbVar5 + 4) + 4);
  param_1[1] = *(undefined2 *)(*(int *)(pbVar5 + 4) + 2);
  bVar1 = *pbVar5;
  if (bVar1 == 3) {
    uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x18));
    if (uVar3 != 0) {
      *pbVar5 = 2;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar6 + 0x1e));
      (**(code **)(*DAT_803dd6d4 + 0x48))
                (*(undefined *)(iVar6 + 0x22),param_1,*(undefined *)(iVar6 + 0x20));
      *pbVar5 = 4;
    }
    else if (bVar1 != 0) {
      if ((pbVar5[1] == 0) || ((*(byte *)(iVar6 + 0x23) & 1) != 0)) {
        if (((int)*(short *)(iVar6 + 0x18) == 0xffffffff) ||
           (uVar3 = FUN_80020078((int)*(short *)(iVar6 + 0x18)), uVar3 != 0)) {
          if (((*(byte *)((int)param_1 + 0xaf) & 1) == 0) ||
             ((*(short *)(iVar6 + 0x1c) != -1 &&
              (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x20))(), iVar4 == 0)))) {
            *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) | 0x20;
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
          }
          else {
            if ((*(byte *)(iVar6 + 0x23) & 2) != 0) {
              FUN_800201ac((int)*(short *)(iVar6 + 0x18),0);
            }
            if ((int)*(short *)(iVar6 + 0x1a) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar6 + 0x1a),1);
            }
            *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
            pbVar5[1] = 1;
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(iVar6 + 0x22),param_1,0xffffffff);
          }
        }
        else {
          *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
          *pbVar5 = 3;
        }
      }
      else {
        *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar5 + 4) + 0xaf) & 0xdf;
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        *pbVar5 = 4;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017f88c
 * EN v1.0 Address: 0x8017F88C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f88c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,int *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  FUN_8002bac4();
  FUN_8000b7dc(param_9,0x40);
  iVar2 = *param_11;
  if (((iVar2 != 0) && (*(int *)(iVar2 + 0xc4) != 0)) &&
     (FLOAT_803e4508 <= *(float *)(param_9 + 0x98))) {
    *param_11 = 0;
    FUN_80037da8(param_9,iVar2);
    uVar1 = FUN_80022264(0x27,0x2c);
    dVar4 = (double)((float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e44f8) /
                    FLOAT_803e450c);
    uVar1 = FUN_80021884();
    FUN_80022264((uVar1 & 0xffff) - 0x1000,(uVar1 & 0xffff) + 0x1000);
    dVar3 = (double)FUN_802945e0();
    *(float *)(iVar2 + 0x24) = (float)(dVar4 * dVar3);
    param_2 = (double)FLOAT_803e4510;
    dVar3 = (double)FUN_80294964();
    *(float *)(iVar2 + 0x2c) = (float)(dVar4 * dVar3);
    FUN_8000bb38(param_9,0x5e);
  }
  if (FLOAT_803e44f0 <= *(float *)(param_9 + 0x98)) {
    *(undefined *)((int)param_11 + 0xf) = 2;
    param_11[2] = (int)FLOAT_803e4518;
    FUN_8003042c((double)FLOAT_803e44f4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fa4c
 * EN v1.0 Address: 0x8017FA4C
 * EN v1.0 Size: 708b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fa4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017fd10
 * EN v1.0 Address: 0x8017FD10
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fd10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined2 param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  piVar3 = *(int **)(param_9 + 0xb8);
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x30,param_10);
    *(undefined *)(puVar2 + 0xd) = 0x14;
    puVar2[0x16] = 0xffff;
    puVar2[0xe] = 0xffff;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    puVar2[0x12] = 0xffff;
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar4 + 5);
    *(char *)((int)puVar2 + 7) = *(char *)(iVar4 + 7) + -0xf;
    iVar4 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    if (iVar4 == 0) {
      FUN_800238c4((uint)puVar2);
      *piVar3 = 0;
    }
    else {
      FUN_80037e24(param_9,iVar4,0);
      *piVar3 = iVar4;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fe20
 * EN v1.0 Address: 0x8017FE20
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017fe20(void)
{
  (**(code **)(*DAT_803dd6d0 + 0x4c))();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017fe70
 * EN v1.0 Address: 0x8017FE70
 * EN v1.0 Size: 124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017fe70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int *piVar1;
  undefined8 uVar2;
  
  piVar1 = *(int **)(param_9 + 0xb8);
  FUN_8003709c(param_9,0x34);
  FUN_8003709c(param_9,0x3e);
  if ((*(char *)(param_9 + 0xeb) != '\0') && (uVar2 = FUN_80037da8(param_9,*piVar1), param_10 == 0))
  {
    FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017feec
 * EN v1.0 Address: 0x8017FEEC
 * EN v1.0 Size: 124b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017feec(int param_1)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    iVar1 = *piVar2;
    if ((iVar1 != 0) && (*(int *)(iVar1 + 0xc4) != 0)) {
      FUN_80038524(param_1,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                   (float *)(iVar1 + 0x14),0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017ff68
 * EN v1.0 Address: 0x8017FF68
 * EN v1.0 Size: 884b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ff68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  char cVar2;
  float fVar3;
  byte bVar6;
  int iVar4;
  uint uVar5;
  int iVar7;
  int *piVar8;
  undefined8 extraout_f1;
  double dVar9;
  int iStack_48;
  uint uStack_44;
  undefined4 uStack_40;
  undefined auStack_3c [12];
  float local_30;
  undefined4 uStack_2c;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar7 = *(int *)(param_9 + 0x26);
  piVar8 = *(int **)(param_9 + 0x5c);
  if ((*piVar8 == 0) || (*(char *)((int)param_9 + 0xeb) != '\0')) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    bVar6 = FUN_8002b11c((int)param_9);
    if (bVar6 == 0) {
      cVar2 = *(char *)((int)piVar8 + 0xf);
      if (cVar2 == '\x02') {
        if (FLOAT_803e44f0 <= *(float *)(param_9 + 0x4c)) {
          iVar7 = (uint)*(byte *)(param_9 + 0x1b) + (uint)DAT_803dc070 * -2;
          if (iVar7 < 0) {
            iVar7 = 0;
            *(undefined *)((int)piVar8 + 0xf) = 3;
            fVar1 = FLOAT_803e44f4;
            dVar9 = (double)FLOAT_803e44f4;
            piVar8[1] = (int)FLOAT_803e44f4;
            piVar8[2] = (int)fVar1;
            FUN_8003042c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,
                         param_12,param_13,param_14,param_15,param_16);
            FUN_800303fc((double)FLOAT_803e44f4,(int)param_9);
          }
          *(char *)(param_9 + 0x1b) = (char)iVar7;
        }
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      }
      else if (cVar2 < '\x02') {
        if (cVar2 == '\0') {
          iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar7 + 0x14));
          if (iVar4 == 0) {
            dVar9 = (double)(**(code **)(*DAT_803dd72c + 0x6c))(*(undefined4 *)(iVar7 + 0x14));
            param_2 = DOUBLE_803e44f8;
            uStack_1c = (uint)*(ushort *)(iVar7 + 0x18);
            if (uStack_1c < 100) {
              uStack_1c = 100;
            }
            uStack_1c = uStack_1c ^ 0x80000000;
            local_20 = 0x43300000;
            fVar1 = (float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,uStack_1c) -
                                                   DOUBLE_803e44f8));
            fVar3 = FLOAT_803e44f0;
            if ((fVar1 <= FLOAT_803e44f0) && (fVar3 = fVar1, fVar1 < FLOAT_803e44f4)) {
              fVar3 = FLOAT_803e44f4;
            }
            piVar8[1] = (int)(FLOAT_803e44f0 - fVar3);
          }
          else {
            FUN_8017fd10(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,
                         *(undefined2 *)(&DAT_803dca00 + (*(byte *)(iVar7 + 0x1b) & 3) * 2));
            *(undefined *)((int)piVar8 + 0xf) = 1;
            uVar5 = FUN_80022264(300,600);
            *(short *)(piVar8 + 3) = (short)uVar5;
          }
          if (param_9[0x50] != 0) {
            FUN_8003042c((double)(float)piVar8[1],param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
          }
          FUN_800303fc((double)(float)piVar8[1],(int)param_9);
        }
        else if (-1 < cVar2) {
          FUN_8017fa4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar7
                       ,(int)piVar8);
        }
      }
      else if (cVar2 == '\x04') {
        FUN_8017f88c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     iVar7,piVar8,param_12,param_13,param_14,param_15,param_16);
      }
      else if (cVar2 < '\x04') {
        uVar5 = (uint)*(byte *)(param_9 + 0x1b) + (uint)DAT_803dc070;
        if (0xfe < uVar5) {
          uVar5 = 0xff;
          *(undefined *)((int)piVar8 + 0xf) = 0;
          uStack_1c = (uint)*(ushort *)(iVar7 + 0x18);
          local_20 = 0x43300000;
          (**(code **)(*DAT_803dd72c + 100))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4500),
                     *(undefined4 *)(iVar7 + 0x14));
        }
        *(char *)(param_9 + 0x1b) = (char)uVar5;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
      }
      FUN_8002fb40((double)(float)piVar8[2],(double)FLOAT_803dc074);
    }
    else {
      iVar7 = FUN_80036868((int)param_9,&uStack_40,&iStack_48,&uStack_44,&local_30,&uStack_2c,
                           local_28);
      if ((iVar7 != 0) && (iVar7 != 0x10)) {
        local_30 = local_30 + FLOAT_803dda58;
        local_28[0] = local_28[0] + FLOAT_803dda5c;
        FUN_8009a468(param_9,auStack_3c,1,(int *)0x0);
        FUN_8000bb38((uint)param_9,0x47b);
        FUN_8002b070((int)param_9);
      }
    }
  }
  else {
    *piVar8 = 0;
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801802dc
 * EN v1.0 Address: 0x801802DC
 * EN v1.0 Size: 392b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801802dc(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80180464
 * EN v1.0 Address: 0x80180464
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180464(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0xb8) + 1) != '\0') {
    FUN_8003709c(param_1,0x4b);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801804a0
 * EN v1.0 Address: 0x801804A0
 * EN v1.0 Size: 136b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801804a0(int param_1,undefined4 param_2,byte *param_3,int param_4,int param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80180528
 * EN v1.0 Address: 0x80180528
 * EN v1.0 Size: 620b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180528(undefined4 param_1,undefined4 param_2,byte *param_3,int param_4,int param_5)
{
  uint uVar1;
  int iVar2;
  byte bVar7;
  int *piVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar8;
  byte *pbVar9;
  undefined8 uVar10;
  int local_28 [10];
  
  uVar10 = FUN_8028683c();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  pbVar8 = (byte *)uVar10;
  uVar1 = FUN_80020078(0x4e5);
  if ((uVar1 != 0) && (iVar2 = FUN_8002ba84(), iVar2 != 0)) {
    if (*pbVar8 == 0) {
      bVar7 = FUN_800dbf88((float *)(iVar4 + 0xc),(undefined *)0x0);
      *pbVar8 = bVar7;
      if (*pbVar8 == 0) goto LAB_80180758;
      piVar3 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_28);
      param_3 = pbVar8;
      for (param_4 = 0; param_4 < local_28[0]; param_4 = param_4 + 1) {
        iVar2 = *piVar3;
        if ((*(char *)(iVar2 + 0x19) == '$') && (*(char *)(iVar2 + 3) == '\0')) {
          param_5 = 0;
          iVar5 = 4;
          do {
            if (*(byte *)(iVar2 + param_5 + 4) == *pbVar8) {
              *(undefined4 *)(param_3 + 4) = *(undefined4 *)(iVar2 + 0x14);
              param_3 = param_3 + 4;
              break;
            }
            param_5 = param_5 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        piVar3 = piVar3 + 1;
      }
    }
    iVar4 = FUN_8005a288((double)FLOAT_803e4538,(float *)(iVar4 + 0xc));
    if (iVar4 == 0) {
      iVar4 = FUN_8002bac4();
      uVar1 = FUN_800dbf88((float *)(iVar4 + 0xc),(undefined *)0x0);
      bVar7 = (byte)param_5;
      if (uVar1 != 0) {
        if (uVar1 == *pbVar8) goto LAB_80180758;
        iVar2 = 0;
        pbVar9 = pbVar8;
        do {
          bVar7 = (byte)param_5;
          if (*(int *)(pbVar9 + 4) == 0) break;
          iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))();
          if ((((iVar5 != 0) &&
               (((int)*(short *)(iVar5 + 0x30) == 0xffffffff ||
                (uVar6 = FUN_80020078((int)*(short *)(iVar5 + 0x30)), uVar6 != 0)))) &&
              (((int)*(short *)(iVar5 + 0x32) == 0xffffffff ||
               (uVar6 = FUN_80020078((int)*(short *)(iVar5 + 0x32)), uVar6 == 0)))) &&
             ((((*(byte *)(iVar5 + 4) == uVar1 || (*(byte *)(iVar5 + 5) == uVar1)) ||
               (*(byte *)(iVar5 + 6) == uVar1)) || (*(byte *)(iVar5 + 7) == uVar1))))
          goto LAB_80180758;
          bVar7 = (byte)param_5;
          pbVar9 = pbVar9 + 4;
          iVar2 = iVar2 + 1;
        } while (iVar2 < 0x18);
      }
      FUN_800dbcd8((float *)(iVar4 + 0xc),(uint)*pbVar8,param_3,param_4,bVar7);
    }
  }
LAB_80180758:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180794
 * EN v1.0 Address: 0x80180794
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180794(int param_1)
{
  uint uVar1;
  int iVar2;
  char cVar3;
  
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a);
  if ((((uVar1 == 0xffffffff) || (uVar1 = FUN_80020078(uVar1), uVar1 != 0)) &&
      (iVar2 = FUN_8002ba84(), iVar2 != 0)) &&
     (cVar3 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x44))(), cVar3 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80041110();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180890
 * EN v1.0 Address: 0x80180890
 * EN v1.0 Size: 436b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180890(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8002ba84();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (iVar2 != 0) {
    iVar3 = FUN_8013930c(iVar2);
    uVar1 = countLeadingZeros(param_1 - iVar3);
    if ((uVar1 >> 5 == 0) && ((int)*(short *)(iVar5 + 0x1e) != 0xffffffff)) {
      FUN_800201ac((int)*(short *)(iVar5 + 0x1e),0);
    }
    if (((int)*(short *)(iVar5 + 0x20) == 0xffffffff) ||
       (uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x20)), uVar4 != 0)) {
      if ((uVar1 >> 5 == 0) ||
         (dVar6 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18)),
         (double)FLOAT_803e4540 <= dVar6)) {
        iVar5 = FUN_8012f000();
        if (iVar5 == -1) {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0;
        }
        else {
          *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0x10;
        }
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) &&
           (*(int *)(param_1 + 0x74) != 0)) {
          FUN_80041110();
        }
        if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,3);
        }
      }
      else if ((int)*(short *)(iVar5 + 0x1e) != 0xffffffff) {
        FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180a44
 * EN v1.0 Address: 0x80180A44
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180a44(int param_1)
{
  char in_r8;
  
  if (((in_r8 != '\0') && (*(char *)(*(int *)(param_1 + 0xb8) + 0x1b) != '\0')) &&
     (*(char *)(*(int *)(param_1 + 0xb8) + 0x1c) == '\0')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180a94
 * EN v1.0 Address: 0x80180A94
 * EN v1.0 Size: 140b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180a94(int *param_1)
{
  int iVar1;
  int iVar2;
  int aiStack_60 [22];
  
  iVar2 = param_1[0x2e];
  iVar1 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x2,aiStack_60,param_1,8,0xffffffff,0xff,
                       0);
  if (iVar1 != 0) {
    *(undefined *)(iVar2 + 0x1a) = 1;
  }
  param_1[0x20] = param_1[3];
  param_1[0x21] = param_1[4];
  param_1[0x22] = param_1[5];
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80180b20
 * EN v1.0 Address: 0x80180B20
 * EN v1.0 Size: 1764b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80180b20(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar9;
  float *pfVar10;
  double dVar11;
  undefined8 uVar12;
  double dVar13;
  uint local_48;
  undefined4 *local_44;
  ushort local_40 [4];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined8 local_28;
  longlong local_20;
  
  puVar2 = (ushort *)FUN_80286840();
  pfVar10 = *(float **)(puVar2 + 0x5c);
  iVar9 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002bac4();
  while (iVar4 = FUN_800375e4((int)puVar2,&local_48,(uint *)0x0,(uint *)0x0), iVar4 != 0) {
    if (local_48 == 0x7000b) {
      FUN_8000bb38((uint)puVar2,0x4e);
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
      in_r7 = 0xffffffff;
      in_r8 = 0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(puVar2,0x51a,0,1);
      FUN_800201ac((int)*(short *)(pfVar10 + 3),1);
      iVar4 = (**(code **)(*DAT_803dd72c + 0x8c))();
      uVar5 = *(byte *)(iVar4 + 9) + 1;
      if (*(byte *)(iVar4 + 10) < uVar5) {
        uVar5 = (uint)*(byte *)(iVar4 + 10);
      }
      *(char *)(iVar4 + 9) = (char)uVar5;
      *(undefined *)(pfVar10 + 7) = 1;
    }
  }
  if ((*(char *)((int)pfVar10 + 0x1b) == '\0') || (*(char *)(pfVar10 + 7) == '\x01')) {
    if (*(char *)((int)pfVar10 + 0x1b) == '\0') {
      uVar5 = FUN_80020078((int)*(short *)((int)pfVar10 + 0xe));
      *(char *)((int)pfVar10 + 0x1b) = (char)uVar5;
      *(undefined2 *)(pfVar10 + 2) = 0;
    }
  }
  else {
    dVar13 = (double)*(float *)(puVar2 + 0x14);
    if ((double)FLOAT_803e4550 < dVar13) {
      *(float *)(puVar2 + 0x14) = (float)((double)FLOAT_803e4554 * (double)FLOAT_803dc074 + dVar13);
    }
    *(undefined *)((int)pfVar10 + 0x1a) = 0;
    if (-1 < *(char *)((int)pfVar10 + 0x1e)) {
      dVar13 = (double)*(float *)(puVar2 + 8);
      iVar6 = FUN_80065fcc((double)*(float *)(puVar2 + 6),dVar13,(double)*(float *)(puVar2 + 10),
                           puVar2,&local_44,0,0);
      param_3 = (double)FLOAT_803e4558;
      iVar4 = -1;
      iVar8 = 0;
      puVar7 = local_44;
      if (0 < iVar6) {
        do {
          dVar13 = (double)*(float *)*puVar7;
          dVar11 = (double)(float)(dVar13 - (double)*(float *)(puVar2 + 8));
          if (dVar11 < (double)FLOAT_803e455c) {
            dVar11 = -dVar11;
          }
          if (dVar11 < param_3) {
            iVar4 = iVar8;
            param_3 = dVar11;
          }
          puVar7 = puVar7 + 1;
          iVar8 = iVar8 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (iVar4 != -1) {
        *(byte *)((int)pfVar10 + 0x1e) = *(byte *)((int)pfVar10 + 0x1e) & 0x7f | 0x80;
        pfVar10[1] = *(float *)local_44[iVar4];
        *(float *)(puVar2 + 0x14) = FLOAT_803e455c;
      }
      if (-1 < *(char *)((int)pfVar10 + 0x1e)) {
        pfVar10[1] = *(float *)(iVar9 + 0xc);
        *(byte *)((int)pfVar10 + 0x1e) = *(byte *)((int)pfVar10 + 0x1e) & 0x7f | 0x80;
      }
    }
    if (*(float *)(puVar2 + 8) < pfVar10[1]) {
      *(float *)(puVar2 + 8) = pfVar10[1];
      *(float *)(puVar2 + 0x14) = FLOAT_803e455c;
    }
    if ((*(short *)(pfVar10 + 2) == 0) && (*(short *)((int)pfVar10 + 10) == 0)) {
      dVar13 = (double)FLOAT_803dc074;
      iVar9 = FUN_8002fb40((double)*pfVar10,dVar13);
      if ((iVar9 == 0) && (*(char *)((int)pfVar10 + 0x1a) == '\0')) {
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 0x12) * FLOAT_803dc074 + *(float *)(puVar2 + 6)
        ;
        dVar13 = (double)*(float *)(puVar2 + 0x16);
        *(float *)(puVar2 + 10) =
             (float)(dVar13 * (double)FLOAT_803dc074 + (double)*(float *)(puVar2 + 10));
      }
      else {
        FUN_8000bb38((uint)puVar2,0x4c);
        (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51f,0,2,0xffffffff,0);
        in_r7 = 0xffffffff;
        in_r8 = 0;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(puVar2,0x51f,0,2);
        uVar5 = FUN_80022264(0,4);
        *(char *)(pfVar10 + 6) = (char)uVar5;
        fVar1 = FLOAT_803e455c;
        if (*(char *)((int)pfVar10 + 0x1d) == '\0') {
          *(float *)(puVar2 + 0x12) = FLOAT_803e455c;
          *(float *)(puVar2 + 0x16) = fVar1;
        }
        else {
          *(float *)(puVar2 + 0x12) = FLOAT_803e4560;
          local_34 = FLOAT_803e455c;
          *(float *)(puVar2 + 0x16) = FLOAT_803e455c;
          local_30 = local_34;
          local_2c = local_34;
          local_38 = FLOAT_803e4548;
          local_40[2] = 0;
          local_40[1] = 0;
          local_40[0] = *puVar2;
          FUN_80021b8c(local_40,(float *)(puVar2 + 0x12));
        }
        if (*(char *)((int)pfVar10 + 0x19) != '\0') {
          *(undefined2 *)((int)pfVar10 + 10) = 0xfa;
        }
      }
      iVar9 = FUN_80036974((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar9 == 0xe) {
        *(undefined *)((int)pfVar10 + 0x19) = 1;
        FUN_8000bb38((uint)puVar2,0x4d);
      }
    }
    else {
      if (*(short *)(pfVar10 + 2) != 0) {
        local_28 = (double)(longlong)(int)FLOAT_803dc074;
        *(short *)(pfVar10 + 2) = *(short *)(pfVar10 + 2) - (short)(int)FLOAT_803dc074;
        if (*(short *)(pfVar10 + 2) < 1) {
          *(undefined2 *)(pfVar10 + 2) = 0;
        }
      }
      if (*(short *)((int)pfVar10 + 10) != 0) {
        local_28 = (double)(longlong)(int)FLOAT_803dc074;
        *(short *)((int)pfVar10 + 10) = *(short *)((int)pfVar10 + 10) - (short)(int)FLOAT_803dc074;
        if (*(short *)((int)pfVar10 + 10) < 1) {
          *(undefined2 *)((int)pfVar10 + 10) = 0;
          *(undefined *)((int)pfVar10 + 0x19) = 0;
        }
      }
    }
    if (*(char *)(pfVar10 + 6) == '\x04') {
      if (*(char *)((int)pfVar10 + 0x1a) != '\0') {
        *puVar2 = *puVar2 + 0x8001;
        *(undefined *)(pfVar10 + 6) = 0;
      }
      param_3 = (double)FLOAT_803e4564;
      dVar13 = (double)FLOAT_803dc074;
      local_28 = (double)CONCAT44(0x43300000,(int)(short)*puVar2 ^ 0x80000000);
      iVar9 = (int)(param_3 * dVar13 + (double)(float)(local_28 - DOUBLE_803e4570));
      local_20 = (longlong)iVar9;
      *puVar2 = (ushort)iVar9;
    }
    fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(puVar2 + 8);
    if (fVar1 < FLOAT_803e455c) {
      fVar1 = -fVar1;
    }
    if (((fVar1 < FLOAT_803e4568) &&
        (dVar11 = (double)FUN_80021754((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc)),
        dVar11 < (double)FLOAT_803e456c)) && (uVar5 = FUN_8029698c(iVar3), uVar5 != 0)) {
      uVar5 = FUN_80020078(0xcc0);
      if (uVar5 == 0) {
        *(undefined2 *)(pfVar10 + 4) = 0xffff;
        uVar12 = FUN_80035ff8((int)puVar2);
        FUN_800379bc(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                     (uint)puVar2,(uint)(pfVar10 + 4),in_r7,in_r8,in_r9,in_r10);
        FUN_800201ac(0xcc0,1);
      }
      else {
        iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
        if (*(byte *)(iVar3 + 9) < *(byte *)(iVar3 + 10)) {
          FUN_8000bb38((uint)puVar2,0x4e);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          FUN_800201ac((int)*(short *)(pfVar10 + 3),1);
          iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
          uVar5 = *(byte *)(iVar3 + 9) + 1;
          if (*(byte *)(iVar3 + 10) < uVar5) {
            uVar5 = (uint)*(byte *)(iVar3 + 10);
          }
          *(char *)(iVar3 + 9) = (char)uVar5;
          *(undefined *)(pfVar10 + 7) = 1;
          *(undefined *)(puVar2 + 0x1b) = 1;
        }
      }
      if (*(int *)(puVar2 + 0x2a) != 0) {
        FUN_80035ff8((int)puVar2);
      }
    }
    *(float *)(puVar2 + 8) = *(float *)(puVar2 + 8) + *(float *)(puVar2 + 0x14);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80181204
 * EN v1.0 Address: 0x80181204
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80181204(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80181328
 * EN v1.0 Address: 0x80181328
 * EN v1.0 Size: 1672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80181328(void)
{
  ushort *puVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar7;
  int iVar6;
  byte bVar8;
  undefined4 uVar9;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  int iVar11;
  float *pfVar12;
  undefined8 extraout_f1;
  double dVar13;
  undefined8 extraout_f1_00;
  double dVar14;
  double dVar15;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_68 [2];
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
  puVar1 = (ushort *)FUN_80286838();
  pfVar12 = *(float **)(puVar1 + 0x5c);
  iVar11 = *(int *)(puVar1 + 0x26);
  iVar2 = FUN_8002bac4();
  iVar10 = *(int *)(puVar1 + 0x26);
  local_68[0] = DAT_803e4580;
  pfVar12[0x47] = pfVar12[0x47] + FLOAT_803dc074;
  bVar8 = *(byte *)(pfVar12 + 0x42);
  if (bVar8 == 2) {
LAB_801814d8:
    if (pfVar12[0x47] <= FLOAT_803e4584) {
      iVar2 = (int)(FLOAT_803e458c * (pfVar12[0x47] / FLOAT_803e4584));
      local_60 = (double)(longlong)iVar2;
      *(char *)(puVar1 + 0x1b) = (char)iVar2;
      goto LAB_80181980;
    }
    *(undefined *)(puVar1 + 0x1b) = 0xff;
    *(undefined *)(pfVar12 + 0x42) = 3;
  }
  else {
    if (bVar8 < 2) {
      if (bVar8 == 0) {
        local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar11 + 0x20));
        fVar3 = FLOAT_803e4584 * (float)(local_60 - DOUBLE_803e45b0);
        if (pfVar12[0x47] < fVar3) goto LAB_80181980;
        pfVar12[0x47] = pfVar12[0x47] - fVar3;
        *(undefined *)(pfVar12 + 0x42) = 1;
      }
      *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(iVar10 + 8);
      *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(iVar10 + 0xc);
      *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(iVar10 + 0x10);
      dVar14 = (double)*(float *)(puVar1 + 8);
      dVar15 = (double)*(float *)(puVar1 + 10);
      (**(code **)(*DAT_803dd71c + 0x14))((double)*(float *)(puVar1 + 6),local_68,1,0xffffffff);
      fVar3 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x54))(fVar3,0);
      fVar4 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x54))(fVar4,0);
      fVar5 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      bVar7 = FUN_800dac0c(extraout_f1,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar12,fVar3,
                           fVar4,fVar5,in_r7,in_r8,in_r9,in_r10);
      if (bVar7) goto LAB_80181980;
      *(undefined *)(pfVar12 + 0x42) = 2;
      pfVar12[0x45] = FLOAT_803e4588;
      goto LAB_801814d8;
    }
    if (3 < bVar8) goto LAB_80181980;
  }
  uVar9 = 0;
  iVar6 = FUN_80036974((int)puVar1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar6 == 0) {
    bVar8 = FUN_80296ba8(iVar2);
    if (bVar8 != 0) {
      dVar14 = FUN_80021730((float *)(iVar2 + 0xc),(float *)(puVar1 + 6));
      in_f4 = DOUBLE_803e45b0;
      fVar3 = FLOAT_803e4590;
      uStack_54 = (uint)*(byte *)(iVar11 + 0x23);
      local_60 = (double)CONCAT44(0x43300000,uStack_54);
      local_58 = 0x43300000;
      if (dVar14 < (double)((float)(local_60 - DOUBLE_803e45b0) *
                           (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b0))) {
        uStack_54 = (uint)*(byte *)(iVar10 + 0x19);
        local_58 = 0x43300000;
        pfVar12[0x45] =
             pfVar12[0x45] +
             (FLOAT_803e4590 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b0) *
             FLOAT_803dc074) / FLOAT_803e4594;
        if (fVar3 * pfVar12[0x44] < pfVar12[0x45]) {
          pfVar12[0x45] = fVar3 * pfVar12[0x44];
        }
        goto LAB_80181668;
      }
    }
    uStack_54 = FUN_80022264(-(uint)*(byte *)(iVar10 + 0x19),(uint)*(byte *)(iVar10 + 0x19) << 1);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    pfVar12[0x45] =
         pfVar12[0x45] +
         ((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b8) * FLOAT_803dc074) /
         FLOAT_803e4594;
    if (FLOAT_803e4588 <= pfVar12[0x45]) {
      if (pfVar12[0x44] < pfVar12[0x45]) {
        pfVar12[0x45] = pfVar12[0x44];
      }
    }
    else {
      pfVar12[0x45] = FLOAT_803e4588;
    }
  }
  else {
    pfVar12[0x45] = FLOAT_803e4590 * pfVar12[0x44];
  }
LAB_80181668:
  dVar15 = (double)pfVar12[0x45];
  dVar14 = (double)pfVar12[0x44];
  if ((double)(float)(dVar14 * (double)FLOAT_803e4598) <= dVar15) {
    if (dVar15 <= (double)(float)((double)(float)((double)FLOAT_803e45a4 * dVar14) *
                                 (double)FLOAT_803e4598)) {
      if ((puVar1[0x50] == 1) && (FLOAT_803e45a8 < pfVar12[0x43])) {
        FUN_8003042c((double)FLOAT_803e4588,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,puVar1,0,0,
                     uVar9,in_r7,in_r8,in_r9,in_r10);
        FUN_8002f66c((int)puVar1,0x3c);
        pfVar12[0x43] = FLOAT_803e4588;
      }
      pfVar12[0x46] = (FLOAT_803e45ac * pfVar12[0x45]) / pfVar12[0x44];
    }
    else {
      if ((puVar1[0x50] == 0) && (FLOAT_803e45a8 < pfVar12[0x43])) {
        FUN_8003042c((double)FLOAT_803e4588,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,puVar1,1,0,
                     uVar9,in_r7,in_r8,in_r9,in_r10);
        FUN_8002f66c((int)puVar1,0x3c);
        pfVar12[0x43] = FLOAT_803e4588;
      }
      pfVar12[0x46] = FLOAT_803e45ac;
    }
  }
  else {
    if ((puVar1[0x50] == 0) && (FLOAT_803e459c < pfVar12[0x43])) {
      FUN_8003042c((double)FLOAT_803e4588,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,puVar1,1,0,
                   uVar9,in_r7,in_r8,in_r9,in_r10);
      FUN_8002f66c((int)puVar1,0x3c);
      pfVar12[0x43] = FLOAT_803e4588;
    }
    pfVar12[0x46] = FLOAT_803e45a0;
  }
  if (FLOAT_803e4588 != pfVar12[0x45]) {
    fVar3 = pfVar12[0x45] * FLOAT_803dc074;
    dVar16 = (double)(fVar3 * fVar3);
    dVar13 = FUN_80021730(pfVar12 + 0x1a,(float *)(puVar1 + 6));
    for (iVar2 = 0; (dVar13 < dVar16 && (iVar2 < 5)); iVar2 = iVar2 + 1) {
      FUN_80010340((double)FLOAT_803e4590,pfVar12);
      dVar13 = FUN_80021730(pfVar12 + 0x1a,(float *)(puVar1 + 6));
    }
    if (pfVar12[4] != 0.0) {
      iVar2 = *DAT_803dd71c;
      (**(code **)(iVar2 + 0x54))(pfVar12[0x29],0);
      fVar3 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      iVar2 = FUN_800da4c8(extraout_f1_00,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar12,fVar3,
                           iVar2,uVar9,in_r7,in_r8,in_r9,in_r10);
      if (iVar2 != 0) {
        *(undefined *)(pfVar12 + 0x42) = 0;
        pfVar12[0x47] = FLOAT_803e4588;
        *(undefined *)(puVar1 + 0x1b) = 0;
        goto LAB_80181980;
      }
    }
    dVar16 = (double)(pfVar12[0x1a] - *(float *)(puVar1 + 6));
    uStack_54 = (uint)*(byte *)(iVar11 + 0x22);
    local_58 = 0x43300000;
    dVar13 = (double)((pfVar12[0x1b] +
                      (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b0)) -
                     *(float *)(puVar1 + 8));
    dVar15 = (double)(pfVar12[0x1c] - *(float *)(puVar1 + 10));
    dVar14 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                         (double)(float)(dVar16 * dVar16 +
                                                        (double)(float)(dVar13 * dVar13))));
    *(float *)(puVar1 + 6) = (float)(dVar16 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 6);
    *(float *)(puVar1 + 8) = (float)(dVar13 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 8);
    *(float *)(puVar1 + 10) = (float)(dVar15 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 10);
    iVar2 = FUN_80021884();
    iVar10 = (int)(short)(ushort)iVar2 - (uint)*puVar1;
    if (0x8000 < iVar10) {
      iVar10 = iVar10 + -0xffff;
    }
    if (iVar10 < -0x8000) {
      iVar10 = iVar10 + 0xffff;
    }
    if (iVar10 < 0x181) {
      if (iVar10 < -0x180) {
        *puVar1 = *puVar1 - 0x180;
      }
      else {
        *puVar1 = (ushort)iVar2;
      }
    }
    else {
      *puVar1 = *puVar1 + 0x180;
    }
  }
  FUN_8002fb40((double)pfVar12[0x46],(double)FLOAT_803dc074);
  pfVar12[0x43] = pfVar12[0x43] + FLOAT_803dc074;
LAB_80181980:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801819b0
 * EN v1.0 Address: 0x801819B0
 * EN v1.0 Size: 120b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801819b0(int param_1,int param_2)
{
  double dVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  fVar2 = FLOAT_803e45c0;
  dVar1 = DOUBLE_803e45b0;
  *(float *)(param_1 + 8) =
       *(float *)(*(int *)(param_1 + 0x50) + 4) *
       ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x18)) - DOUBLE_803e45b0) /
       FLOAT_803e45c0);
  *(undefined *)(iVar3 + 0x108) = 1;
  *(float *)(iVar3 + 0x110) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - dVar1) / fVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80181a28
 * EN v1.0 Address: 0x80181A28
 * EN v1.0 Size: 552b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80181a28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  bool bVar6;
  int *piVar4;
  ushort uVar5;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  float *pfVar10;
  undefined4 in_r10;
  double dVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  int local_48;
  uint uStack_44;
  int iStack_40;
  int local_3c;
  undefined auStack_38 [12];
  float local_2c;
  undefined4 uStack_28;
  float local_24 [9];
  
  uVar13 = FUN_80286840();
  puVar2 = (ushort *)((ulonglong)uVar13 >> 0x20);
  pfVar10 = local_24;
  iVar3 = FUN_80036868((int)puVar2,&local_3c,&iStack_40,&uStack_44,&local_2c,&uStack_28,pfVar10);
  if (iVar3 != 0) {
    if (iVar3 == 0x10) {
      FUN_8002b128(puVar2,300);
    }
    else {
      local_2c = local_2c + FLOAT_803dda58;
      local_24[0] = local_24[0] + FLOAT_803dda5c;
      if (*(char *)(param_11 + 0x20) != '\0') {
        if (iVar3 != 5) {
          FUN_8009a468(puVar2,auStack_38,4,(int *)0x0);
          bVar6 = FUN_8000b5f0(0,0x37e);
          if (!bVar6) {
            FUN_8000bb38((uint)puVar2,0x37e);
          }
          goto LAB_80181c38;
        }
        piVar4 = FUN_80037048(0x10,&local_48);
        for (iVar3 = 0; iVar3 < local_48; iVar3 = iVar3 + 1) {
          uVar5 = FUN_80036074(*piVar4);
          if (uVar5 != 0) {
            param_2 = (double)*(float *)(*piVar4 + 0x10);
            if ((((double)*(float *)(puVar2 + 8) < param_2) &&
                (param_2 < (double)(float)((double)*(float *)(puVar2 + 8) + (double)FLOAT_803dca10))
                ) && (dVar11 = (double)FUN_80021754((float *)(*piVar4 + 0x18),
                                                    (float *)(puVar2 + 0xc)),
                     dVar11 < (double)FLOAT_803dca0c)) {
              FUN_80036548(*piVar4,local_3c,'\x05',1,0);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      FUN_8009a468(puVar2,auStack_38,1,(int *)0x0);
      uVar7 = 0;
      uVar8 = 0;
      uVar9 = 1;
      uVar12 = FUN_8002ad08(puVar2,0xf,200,0,0,1);
      bVar6 = FUN_8000b5f0(0,*(short *)(param_11 + 0x10));
      if (!bVar6) {
        uVar12 = FUN_8000bb38((uint)puVar2,*(ushort *)(param_11 + 0x10));
      }
      *(undefined2 *)(param_11 + 10) = 0x32;
      *(undefined *)(param_11 + 9) = 0;
      FUN_80181c50(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,(int)uVar13
                   ,param_11,uVar7,uVar8,uVar9,pfVar10,in_r10);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      fVar1 = FLOAT_803e45d0;
      *(float *)(puVar2 + 0x12) = FLOAT_803e45d0;
      *(float *)(puVar2 + 0x16) = fVar1;
      FUN_80035ea4((int)puVar2);
      if (DAT_803dca08 != 0) {
        FUN_80035ff8((int)puVar2);
      }
    }
  }
LAB_80181c38:
  FUN_8028688c();
  return;
}
