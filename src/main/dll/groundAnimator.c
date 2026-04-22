#include "ghidra_import.h"
#include "main/dll/groundAnimator.h"

extern undefined8 FUN_8000bb38();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021754();
extern undefined4 FUN_800217c8();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern int FUN_8002e1f4();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036f50();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_8003b9ec();
extern int FUN_80065800();
extern undefined4 FUN_80099c40();
extern undefined4 FUN_8011f6d0();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_8029725c();
extern uint FUN_802979fc();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd740;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4454;
extern f32 FLOAT_803e4458;
extern f32 FLOAT_803e445c;
extern f32 FLOAT_803e4460;
extern f32 FLOAT_803e446c;
extern f32 FLOAT_803e4470;
extern f32 FLOAT_803e4474;
extern f32 FLOAT_803e4478;
extern f32 FLOAT_803e447c;
extern f32 FLOAT_803e4480;
extern f32 FLOAT_803e4484;
extern f32 FLOAT_803e4488;
extern f32 FLOAT_803e448c;
extern f32 FLOAT_803e4490;
extern f32 FLOAT_803e4494;
extern f32 FLOAT_803e4498;

/*
 * --INFO--
 *
 * Function: FUN_8017d134
 * EN v1.0 Address: 0x8017D134
 * EN v1.0 Size: 244b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017d134(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  *(undefined *)(param_3 + 0x56) = 0;
  if (*(short *)(param_1 + 0xb4) != -1) {
    if (((*pbVar4 != 4) && (uVar2 = *pbVar4 + 1, uVar2 < 4)) &&
       (uVar1 = (uint)*(short *)(iVar3 + uVar2 * 2 + 0x20), uVar1 != 0xffffffff)) {
      uVar1 = FUN_80020078(uVar1);
      uVar2 = countLeadingZeros((int)(uint)*(byte *)(iVar3 + 0x30) >> (uVar2 & 0x3f) & 1);
      if (uVar2 >> 5 == uVar1) {
        (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(short *)(param_1 + 0xb4));
      }
    }
    pbVar4[1] = pbVar4[1] | 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d228
 * EN v1.0 Address: 0x8017D228
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d228(int param_1)
{
  FUN_8003709c(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d24c
 * EN v1.0 Address: 0x8017D24C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d24c(int param_1)
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
 * Function: FUN_8017d280
 * EN v1.0 Address: 0x8017D280
 * EN v1.0 Size: 376b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d280(int param_1)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((pbVar6[1] & 1) != 0) {
    uVar1 = countLeadingZeros((int)(uint)*(byte *)(iVar5 + 0x30) >> (*pbVar6 + 4 & 0x3f) & 1);
    FUN_800201ac((int)*(short *)(iVar5 + (uint)*pbVar6 * 2 + 0x18),uVar1 >> 5);
    pbVar6[1] = pbVar6[1] & 0xfe;
    *pbVar6 = *pbVar6 + 1;
  }
  if (*pbVar6 != 4) {
    uVar1 = (uint)*(short *)(iVar5 + (uint)*pbVar6 * 2 + 0x20);
    if (uVar1 == 0xffffffff) {
      *pbVar6 = 4;
    }
    else {
      uVar2 = FUN_80020078(uVar1);
      uVar1 = countLeadingZeros((int)(uint)*(byte *)(iVar5 + 0x30) >> (*pbVar6 & 0x3f) & 1);
      if ((uVar1 >> 5 == uVar2) &&
         (iVar3 = (int)*(char *)(iVar5 + (uint)*pbVar6 + 0x2c), iVar3 != -1)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(iVar3,param_1,0xffffffff);
      }
    }
  }
  iVar3 = *pbVar6 - 1;
  iVar4 = iVar5 + iVar3 * 2;
  while (((-1 < iVar3 && ((int)*(short *)(iVar4 + 0x18) != 0xffffffff)) &&
         (uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x18)),
         ((int)(uint)*(byte *)(iVar5 + 0x30) >> (iVar3 + 4U & 0x3f) & 1U) == uVar1))) {
    *pbVar6 = *pbVar6 - 1;
    iVar4 = iVar4 + -2;
    iVar3 = iVar3 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d3f8
 * EN v1.0 Address: 0x8017D3F8
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d3f8(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017d4e8
 * EN v1.0 Address: 0x8017D4E8
 * EN v1.0 Size: 236b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017d4e8(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  *(undefined *)(param_3 + 0x56) = 0;
  if (*(short *)(param_1 + 0xb4) != -1) {
    uVar2 = (uint)*pbVar4;
    if ((((9 < uVar2) || (uVar2 < 8)) && (uVar2 + 1 < 8)) &&
       (((uVar1 = (uint)*(short *)(iVar3 + (uVar2 + 1) * 2 + 0x28), uVar1 != 0xffffffff &&
         (uVar1 != (int)*(short *)(iVar3 + uVar2 * 2 + 0x28))) &&
        (uVar2 = FUN_80020078(uVar1), uVar2 != 0)))) {
      (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(short *)(param_1 + 0xb4));
    }
    pbVar4[1] = pbVar4[1] | 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d5d4
 * EN v1.0 Address: 0x8017D5D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d5d4(int param_1)
{
  FUN_8003709c(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d5f8
 * EN v1.0 Address: 0x8017D5F8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d5f8(int param_1)
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
 * Function: FUN_8017d62c
 * EN v1.0 Address: 0x8017D62C
 * EN v1.0 Size: 420b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d62c(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((pbVar4[1] & 1) != 0) {
    uVar1 = (uint)*(short *)(iVar3 + (uint)*pbVar4 * 2 + 0x18);
    if (uVar1 != 0xffffffff) {
      FUN_800201ac(uVar1,1);
    }
    pbVar4[1] = pbVar4[1] & 0xfe;
    *pbVar4 = *pbVar4 + 1;
  }
  uVar1 = (uint)*pbVar4;
  if (uVar1 == 9) {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar3 + 0x3c));
    (**(code **)(*DAT_803dd6d4 + 0x48))
              (*(undefined *)(iVar3 + 0x3a),param_1,*(undefined *)(iVar3 + 0x3b));
  }
  else {
    if (uVar1 < 9) {
      if (7 < uVar1) goto LAB_8017d768;
    }
    else if (uVar1 < 0xb) goto LAB_8017d768;
    uVar1 = (uint)*(short *)(iVar3 + uVar1 * 2 + 0x28);
    if (uVar1 == 0xffffffff) {
      *pbVar4 = 8;
    }
    else {
      uVar1 = FUN_80020078(uVar1);
      if ((uVar1 != 0) && (iVar2 = (int)*(char *)(iVar3 + (uint)*pbVar4 + 0x40), iVar2 != -1)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(iVar2,param_1,0xffffffff);
      }
    }
  }
LAB_8017d768:
  iVar2 = *pbVar4 - 1;
  iVar3 = iVar3 + iVar2 * 2;
  while (((-1 < iVar2 && ((int)*(short *)(iVar3 + 0x18) != 0xffffffff)) &&
         (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18)), uVar1 == 0))) {
    *pbVar4 = *pbVar4 - 1;
    iVar3 = iVar3 + -2;
    iVar2 = iVar2 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d7d0
 * EN v1.0 Address: 0x8017D7D0
 * EN v1.0 Size: 276b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d7d0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017d8e4
 * EN v1.0 Address: 0x8017D8E4
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d8e4(int param_1)
{
  FUN_8003709c(param_1,4);
  (**(code **)(*DAT_803dd740 + 0x10))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d92c
 * EN v1.0 Address: 0x8017D92C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d92c(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)in_r8);
  if (iVar2 != 0) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d9ac
 * EN v1.0 Address: 0x8017D9AC
 * EN v1.0 Size: 784b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d9ac(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  int local_28;
  int local_24;
  float local_20 [5];
  
  uVar4 = *(undefined4 *)(param_1 + 0xb8);
  local_20[0] = FLOAT_803e4454;
  iVar1 = (**(code **)(*DAT_803dd740 + 8))(param_1,*(undefined4 *)(param_1 + 0xb8));
  if (iVar1 == 0) {
    if ((*(uint *)(param_1 + 0xf4) & 1) != 0) {
      iVar1 = FUN_8002e1f4(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar3 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar3 != param_1) && (*(short *)(iVar3 + 0x46) == 499)) &&
           (dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
           dVar5 < (double)FLOAT_803e4458)) {
          iVar3 = *(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c);
          if ((int)*(short *)(param_1 + 0x46) == *(char *)(iVar3 + 0x19) + 500) {
            if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
            }
          }
          else if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
            FUN_800201ac((int)*(short *)(iVar3 + 0x1e),0);
          }
          *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0xc);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x10);
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x14);
        }
      }
    }
    iVar1 = FUN_8002bac4();
    uVar2 = FUN_802979fc(iVar1);
    if ((uVar2 & 0x4000) == 0) {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,1);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
    }
    else {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,0);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 2;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffe;
  }
  else {
    if ((*(uint *)(param_1 + 0xf4) & 2) != 0) {
      iVar1 = FUN_8002e1f4(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar3 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar3 != param_1) && (*(short *)(iVar3 + 0x46) == 499)) &&
           ((dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
            dVar5 < (double)FLOAT_803e4458 &&
            (uVar2 = (uint)*(short *)(*(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c) + 0x1e),
            uVar2 != 0xffffffff)))) {
          FUN_800201ac(uVar2,0);
        }
      }
    }
    iVar1 = FUN_8002bac4();
    FUN_80036f50(0x10,param_1,local_20);
    uVar2 = FUN_802979fc(iVar1);
    if (((uVar2 & 0x4000) == 0) || (local_20[0] <= FLOAT_803e445c)) {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,1);
    }
    else {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,0);
      FUN_8011f6d0(5);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 1;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017dcbc
 * EN v1.0 Address: 0x8017DCBC
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017dcbc(short *param_1,int param_2)
{
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  param_1[0x7a] = 0;
  param_1[0x7b] = 0;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  (**(code **)(*DAT_803dd740 + 4))(param_1,*(undefined4 *)(param_1 + 0x5c),0x32);
  FUN_800372f8((int)param_1,4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017ddac
 * EN v1.0 Address: 0x8017DDAC
 * EN v1.0 Size: 668b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ddac(uint param_1,int param_2)
{
  undefined2 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  double dVar8;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (param_2 == 1) {
    uVar1 = 2;
  }
  else {
    if (param_2 < 1) {
      if (-1 < param_2) {
        uVar1 = 2;
        goto LAB_8017de10;
      }
    }
    else if (param_2 < 3) {
      uVar1 = 2;
      goto LAB_8017de10;
    }
    uVar1 = 0;
  }
LAB_8017de10:
  *(undefined2 *)(iVar4 + 0x38) = uVar1;
  *(undefined *)(iVar4 + 0x3a) = 4;
  *(float *)(iVar4 + 8) = FLOAT_803dc074;
  *(float *)(iVar4 + 0xc) = FLOAT_803dc074;
  uVar2 = FUN_80022264(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x48) = (short)uVar2;
  uVar2 = FUN_80022264(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x4a) = (short)uVar2;
  *(undefined2 *)(iVar4 + 0x4c) = 0x2000;
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar6 = (double)*(float *)(param_1 + 0x10);
  dVar7 = (double)*(float *)(param_1 + 0x14);
  iVar3 = FUN_80065800(dVar5,dVar6,dVar7,param_1,(float *)(iVar4 + 0x30),0);
  if (iVar3 == 0) {
    iVar4 = *(int *)(param_1 + 0xb8);
    if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
      if (*(int *)(param_1 + 0x54) != 0) {
        FUN_80035ff8(param_1);
      }
      *(byte *)(iVar4 + 0x5a) = *(byte *)(iVar4 + 0x5a) | 2;
    }
    else {
      FUN_8002cc9c(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
    }
  }
  else {
    dVar5 = (double)*(float *)(iVar4 + 0x40);
    dVar6 = FUN_80293900(-(double)((float)((double)FLOAT_803e4470 * dVar5) *
                                   *(float *)(iVar4 + 0x30) - FLOAT_803e446c));
    dVar7 = (double)(float)((double)FLOAT_803e4474 * dVar5);
    dVar5 = dVar7;
    if (dVar7 < (double)FLOAT_803e446c) {
      dVar5 = -dVar7;
    }
    if ((double)FLOAT_803e4478 < dVar5) {
      dVar8 = (double)(float)((double)(float)((double)FLOAT_803e447c - dVar6) / dVar7);
      dVar5 = (double)(float)((double)(float)((double)FLOAT_803e447c + dVar6) / dVar7);
      if ((double)FLOAT_803e446c < dVar8) {
        dVar5 = dVar8;
      }
    }
    else {
      dVar5 = (double)FLOAT_803e4460;
    }
    *(float *)(iVar4 + 0x50) = (float)dVar5;
    if (FLOAT_803e446c <= *(float *)(iVar4 + 0x28)) {
      dVar6 = (double)FLOAT_803e4480;
      *(float *)(iVar4 + 0x30) =
           (float)(dVar6 * (double)(FLOAT_803e4470 * *(float *)(iVar4 + 0x24)) +
                  (double)*(float *)(iVar4 + 0x30));
    }
    else {
      dVar6 = (double)FLOAT_803e4470;
      *(float *)(iVar4 + 0x30) =
           -(float)(dVar6 * (double)*(float *)(iVar4 + 0x24) - (double)*(float *)(iVar4 + 0x30));
    }
    if ((double)FLOAT_803e446c < (double)*(float *)(iVar4 + 0x30)) {
      *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)(param_1 + 0x10);
      *(float *)(iVar4 + 0x34) = *(float *)(param_1 + 0x10) - *(float *)(iVar4 + 0x30);
      if (*(int *)(param_1 + 0x54) != 0) {
        FUN_80035ff8(param_1);
      }
      FUN_8000bb38(param_1,0x52);
    }
    else {
      iVar3 = *(int *)(param_1 + 0xb8);
      if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
        if (*(int *)(param_1 + 0x54) != 0) {
          FUN_80035ff8(param_1);
        }
        *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
      }
      else {
        FUN_8002cc9c((double)*(float *)(iVar4 + 0x30),dVar6,dVar7,dVar5,in_f5,in_f6,in_f7,in_f8,
                     param_1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e048
 * EN v1.0 Address: 0x8017E048
 * EN v1.0 Size: 380b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e048(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  int iVar1;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  double dVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar1 = FUN_8002bac4();
  dVar4 = (double)FUN_80021754((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
  if ((dVar4 < (double)FLOAT_803e4484) &&
     (dVar4 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18)),
     dVar4 < (double)FLOAT_803e4488)) {
    uVar2 = FUN_80020078(0x90f);
    if (uVar2 == 0) {
      uVar5 = (**(code **)(*DAT_803dd6d4 + 0x7c))(0x444,0,0);
      *(undefined2 *)(iVar3 + 0x5c) = 0xffff;
      *(undefined2 *)(iVar3 + 0x5e) = 0;
      *(float *)(iVar3 + 0x60) = FLOAT_803e4460;
      FUN_800379bc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x7000a,
                   param_9,iVar3 + 0x5c,in_r7,in_r8,in_r9,in_r10);
      FUN_800201ac(0x90f,1);
      *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 4;
    }
    else {
      FUN_8029725c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                   (uint)*(ushort *)(iVar3 + 0x38));
      FUN_80099c40((double)FLOAT_803e4460,param_9,0xff,0x28);
      uVar5 = FUN_8000bb38(param_9,0x58);
      iVar1 = *(int *)(param_9 + 0xb8);
      if ((*(ushort *)(param_9 + 6) & 0x2000) == 0) {
        if (*(int *)(param_9 + 0x54) != 0) {
          FUN_80035ff8(param_9);
        }
        *(byte *)(iVar1 + 0x5a) = *(byte *)(iVar1 + 0x5a) | 2;
      }
      else {
        FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e1c4
 * EN v1.0 Address: 0x8017E1C4
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e1c4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e1f4
 * EN v1.0 Address: 0x8017E1F4
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e1f4(int param_1)
{
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x5a) & 2) == 0) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e22c
 * EN v1.0 Address: 0x8017E22C
 * EN v1.0 Size: 608b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e22c(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  fVar1 = FLOAT_803e446c;
  dVar5 = (double)FLOAT_803e446c;
  dVar6 = (double)*(float *)(param_3 + 0x40);
  if (dVar5 == dVar6) {
    uVar4 = 1;
  }
  else {
    fVar2 = *(float *)(param_3 + 0x30);
    if (dVar5 <= (double)(fVar2 - (float)((double)*(float *)(param_3 + 0x2c) - param_1))) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar7 = (double)*(float *)(param_3 + 0x44);
      if (dVar5 == dVar7) {
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)FLOAT_803e4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)FLOAT_803e4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < FLOAT_803e446c) {
          fVar2 = -fVar1;
        }
        fVar3 = FLOAT_803e4460;
        if (FLOAT_803e4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (FLOAT_803e446c < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
        *(float *)(param_3 + 0x30) = FLOAT_803e446c;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *param_2 = *(undefined2 *)(param_3 + 0x48);
        param_2[1] = *(undefined2 *)(param_3 + 0x4a);
        param_2[2] = *(undefined2 *)(param_3 + 0x4c);
        *(float *)(param_3 + 0x44) = -*(float *)(param_3 + 0x28);
        if ((*(byte *)(param_3 + 0x5a) & 8) == 0) {
          FUN_8000bb38((uint)param_2,0x407);
          *(byte *)(param_3 + 0x5a) = *(byte *)(param_3 + 0x5a) | 8;
        }
        uVar4 = 1;
      }
      else if ((double)FLOAT_803e448c <= dVar7) {
        dVar6 = (double)(float)(dVar6 + (double)*(float *)(param_3 + 0x3c));
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)FLOAT_803e4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)FLOAT_803e4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < FLOAT_803e446c) {
          fVar2 = -fVar1;
        }
        fVar3 = FLOAT_803e4460;
        if (FLOAT_803e4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (FLOAT_803e446c < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x44) = *(float *)(param_3 + 0x44) * FLOAT_803e4490;
        uVar4 = 0;
      }
      else {
        *(float *)(param_2 + 8) = *(float *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x40) = fVar1;
        *(float *)(param_3 + 0x44) = fVar1;
        uVar4 = 1;
      }
    }
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e48c
 * EN v1.0 Address: 0x8017E48C
 * EN v1.0 Size: 620b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e48c(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (FLOAT_803e446c == *(float *)(param_3 + 0x3c)) {
    if (FLOAT_803e446c <
        *(float *)(param_3 + 0x30) - (float)((double)*(float *)(param_3 + 0x2c) - param_1)) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar6 = (double)*(float *)(param_3 + 0x40);
      dVar7 = (double)*(float *)(param_3 + 0x44);
      dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                          (double)((float)((double)FLOAT_803e4470 * dVar6) *
                                                  *(float *)(param_3 + 0x30))));
      fVar1 = (float)((double)FLOAT_803e4474 * dVar6);
      fVar2 = fVar1;
      if (fVar1 < FLOAT_803e446c) {
        fVar2 = -fVar1;
      }
      fVar3 = FLOAT_803e4460;
      if (FLOAT_803e4478 < fVar2) {
        fVar2 = (float)(-dVar7 - dVar5) / fVar1;
        fVar3 = (float)(-dVar7 + dVar5) / fVar1;
        if (FLOAT_803e446c < fVar2) {
          fVar3 = fVar2;
        }
      }
      *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
      *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
      *(float *)(param_3 + 0x30) = FLOAT_803e446c;
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
      *param_2 = *(undefined2 *)(param_3 + 0x48);
      param_2[1] = *(undefined2 *)(param_3 + 0x4a);
      param_2[2] = *(undefined2 *)(param_3 + 0x4c);
      *(float *)(param_3 + 0x44) =
           FLOAT_803e4474 * *(float *)(param_3 + 0x40) * fVar3 + *(float *)(param_3 + 0x44);
      *(undefined4 *)(param_3 + 0x3c) = *(undefined4 *)(param_3 + 0x28);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_2 + 6),(double)*(float *)(param_3 + 0x34),
                 (double)*(float *)(param_2 + 10),param_2);
      uVar4 = 0;
    }
  }
  else if ((float)(param_1 - (double)*(float *)(param_3 + 0x2c)) < FLOAT_803e446c) {
    *(float *)(param_2 + 8) = (float)param_1;
    uVar4 = 1;
  }
  else {
    dVar7 = (double)(*(float *)(param_3 + 0x40) + *(float *)(param_3 + 0x3c));
    dVar6 = (double)*(float *)(param_3 + 0x44);
    dVar5 = FUN_80293900((double)(float)(dVar6 * dVar6 -
                                        (double)((float)((double)FLOAT_803e4470 * dVar7) *
                                                *(float *)(param_3 + 0x30))));
    fVar1 = (float)((double)FLOAT_803e4474 * dVar7);
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e446c) {
      fVar2 = -fVar1;
    }
    fVar3 = FLOAT_803e4460;
    if (FLOAT_803e4478 < fVar2) {
      fVar2 = (float)(-dVar6 - dVar5) / fVar1;
      fVar3 = (float)(-dVar6 + dVar5) / fVar1;
      if (FLOAT_803e446c < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
    *(float *)(param_3 + 0x3c) = FLOAT_803e4494;
    *(float *)(param_3 + 0x44) = FLOAT_803e4498;
    uVar4 = 0;
  }
  return uVar4;
}
