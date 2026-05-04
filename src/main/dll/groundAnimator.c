#include "ghidra_import.h"
#include "main/dll/groundAnimator.h"

extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_8003b818();
extern int FUN_800632d8();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8011e868();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80294d60();
extern uint FUN_80294db4();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd740;
extern f32 lbl_803DC074;
extern f32 lbl_803E4454;
extern f32 lbl_803E4458;
extern f32 lbl_803E445C;
extern f32 lbl_803E4460;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4488;
extern f32 lbl_803E448C;
extern f32 lbl_803E4490;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;

/*
 * --INFO--
 *
 * Function: FUN_8017d0d4
 * EN v1.0 Address: 0x8017D0D4
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D134
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017d0d4(int param_1,undefined4 param_2,int param_3)
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
      uVar1 = FUN_80017690(uVar1);
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
 * Function: FUN_8017d1bc
 * EN v1.0 Address: 0x8017D1BC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D228
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d1bc(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d1e0
 * EN v1.0 Address: 0x8017D1E0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D24C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d1e0(int param_1)
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
 * Function: FUN_8017d208
 * EN v1.0 Address: 0x8017D208
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017D280
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d208(int param_1)
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
    FUN_80017698((int)*(short *)(iVar5 + (uint)*pbVar6 * 2 + 0x18),uVar1 >> 5);
    pbVar6[1] = pbVar6[1] & 0xfe;
    *pbVar6 = *pbVar6 + 1;
  }
  if (*pbVar6 != 4) {
    uVar1 = (uint)*(short *)(iVar5 + (uint)*pbVar6 * 2 + 0x20);
    if (uVar1 == 0xffffffff) {
      *pbVar6 = 4;
    }
    else {
      uVar2 = FUN_80017690(uVar1);
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
         (uVar1 = FUN_80017690((int)*(short *)(iVar4 + 0x18)),
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
 * Function: FUN_8017d39c
 * EN v1.0 Address: 0x8017D39C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D3F8
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d39c(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017d3a0
 * EN v1.0 Address: 0x8017D3A0
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D4E8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017d3a0(int param_1,undefined4 param_2,int param_3)
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
        (uVar2 = FUN_80017690(uVar1), uVar2 != 0)))) {
      (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(short *)(param_1 + 0xb4));
    }
    pbVar4[1] = pbVar4[1] | 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d488
 * EN v1.0 Address: 0x8017D488
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D5D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d488(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d4ac
 * EN v1.0 Address: 0x8017D4AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D5F8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d4ac(int param_1)
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
 * Function: FUN_8017d4d4
 * EN v1.0 Address: 0x8017D4D4
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8017D62C
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d4d4(int param_1)
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
      FUN_80017698(uVar1,1);
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
      uVar1 = FUN_80017690(uVar1);
      if ((uVar1 != 0) && (iVar2 = (int)*(char *)(iVar3 + (uint)*pbVar4 + 0x40), iVar2 != -1)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(iVar2,param_1,0xffffffff);
      }
    }
  }
LAB_8017d768:
  iVar2 = *pbVar4 - 1;
  iVar3 = iVar3 + iVar2 * 2;
  while (((-1 < iVar2 && ((int)*(short *)(iVar3 + 0x18) != 0xffffffff)) &&
         (uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x18)), uVar1 == 0))) {
    *pbVar4 = *pbVar4 - 1;
    iVar3 = iVar3 + -2;
    iVar2 = iVar2 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d67c
 * EN v1.0 Address: 0x8017D67C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D7D0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d67c(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017d680
 * EN v1.0 Address: 0x8017D680
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8017D8E4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d680(int param_1)
{
  ObjGroup_RemoveObject(param_1,4);
  (**(code **)(*DAT_803dd740 + 0x10))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d6cc
 * EN v1.0 Address: 0x8017D6CC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8017D92C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d6cc(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)in_r8);
  if (iVar2 != 0) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017d730
 * EN v1.0 Address: 0x8017D730
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8017D9AC
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017d730(int param_1)
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
  local_20[0] = lbl_803E4454;
  iVar1 = (**(code **)(*DAT_803dd740 + 8))(param_1,*(undefined4 *)(param_1 + 0xb8));
  if (iVar1 == 0) {
    if ((*(uint *)(param_1 + 0xf4) & 1) != 0) {
      iVar1 = FUN_80017b00(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar3 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar3 != param_1) && (*(short *)(iVar3 + 0x46) == 499)) &&
           (dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
           dVar5 < (double)lbl_803E4458)) {
          iVar3 = *(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c);
          if ((int)*(short *)(param_1 + 0x46) == *(char *)(iVar3 + 0x19) + 500) {
            if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
              FUN_80017698((int)*(short *)(iVar3 + 0x1e),1);
            }
          }
          else if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
            FUN_80017698((int)*(short *)(iVar3 + 0x1e),0);
          }
          *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0xc);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x10);
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x14);
        }
      }
    }
    iVar1 = FUN_80017a98();
    uVar2 = FUN_80294db4(iVar1);
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
      iVar1 = FUN_80017b00(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar3 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar3 != param_1) && (*(short *)(iVar3 + 0x46) == 499)) &&
           ((dVar5 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
            dVar5 < (double)lbl_803E4458 &&
            (uVar2 = (uint)*(short *)(*(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c) + 0x1e),
            uVar2 != 0xffffffff)))) {
          FUN_80017698(uVar2,0);
        }
      }
    }
    iVar1 = FUN_80017a98();
    ObjGroup_FindNearestObject(0x10,param_1,local_20);
    uVar2 = FUN_80294db4(iVar1);
    if (((uVar2 & 0x4000) == 0) || (local_20[0] <= lbl_803E445C)) {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,1);
    }
    else {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,0);
      FUN_8011e868(5);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 1;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017daa0
 * EN v1.0 Address: 0x8017DAA0
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8017DCBC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017daa0(short *param_1,int param_2)
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
  ObjGroup_AddObject((int)param_1,4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017db40
 * EN v1.0 Address: 0x8017DB40
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x8017DDAC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017db40(uint param_1,int param_2)
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
  *(float *)(iVar4 + 8) = lbl_803DC074;
  *(float *)(iVar4 + 0xc) = lbl_803DC074;
  uVar2 = FUN_80017760(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x48) = (short)uVar2;
  uVar2 = FUN_80017760(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x4a) = (short)uVar2;
  *(undefined2 *)(iVar4 + 0x4c) = 0x2000;
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar6 = (double)*(float *)(param_1 + 0x10);
  dVar7 = (double)*(float *)(param_1 + 0x14);
  iVar3 = FUN_800632d8(dVar5,dVar6,dVar7,param_1,(float *)(iVar4 + 0x30),0);
  if (iVar3 == 0) {
    iVar4 = *(int *)(param_1 + 0xb8);
    if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
      if (*(int *)(param_1 + 0x54) != 0) {
        ObjHits_DisableObject(param_1);
      }
      *(byte *)(iVar4 + 0x5a) = *(byte *)(iVar4 + 0x5a) | 2;
    }
    else {
      FUN_80017ac8(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
    }
  }
  else {
    dVar5 = (double)*(float *)(iVar4 + 0x40);
    dVar6 = FUN_80293900(-(double)((float)((double)lbl_803E4470 * dVar5) *
                                   *(float *)(iVar4 + 0x30) - lbl_803E446C));
    dVar7 = (double)(float)((double)lbl_803E4474 * dVar5);
    dVar5 = dVar7;
    if (dVar7 < (double)lbl_803E446C) {
      dVar5 = -dVar7;
    }
    if ((double)lbl_803E4478 < dVar5) {
      dVar8 = (double)(float)((double)(float)((double)lbl_803E447C - dVar6) / dVar7);
      dVar5 = (double)(float)((double)(float)((double)lbl_803E447C + dVar6) / dVar7);
      if ((double)lbl_803E446C < dVar8) {
        dVar5 = dVar8;
      }
    }
    else {
      dVar5 = (double)lbl_803E4460;
    }
    *(float *)(iVar4 + 0x50) = (float)dVar5;
    if (lbl_803E446C <= *(float *)(iVar4 + 0x28)) {
      dVar6 = (double)lbl_803E4480;
      *(float *)(iVar4 + 0x30) =
           (float)(dVar6 * (double)(lbl_803E4470 * *(float *)(iVar4 + 0x24)) +
                  (double)*(float *)(iVar4 + 0x30));
    }
    else {
      dVar6 = (double)lbl_803E4470;
      *(float *)(iVar4 + 0x30) =
           -(float)(dVar6 * (double)*(float *)(iVar4 + 0x24) - (double)*(float *)(iVar4 + 0x30));
    }
    if ((double)lbl_803E446C < (double)*(float *)(iVar4 + 0x30)) {
      *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)(param_1 + 0x10);
      *(float *)(iVar4 + 0x34) = *(float *)(param_1 + 0x10) - *(float *)(iVar4 + 0x30);
      if (*(int *)(param_1 + 0x54) != 0) {
        ObjHits_DisableObject(param_1);
      }
      FUN_80006824(param_1,0x52);
    }
    else {
      iVar3 = *(int *)(param_1 + 0xb8);
      if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
        if (*(int *)(param_1 + 0x54) != 0) {
          ObjHits_DisableObject(param_1);
        }
        *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
      }
      else {
        FUN_80017ac8((double)*(float *)(iVar4 + 0x30),dVar6,dVar7,dVar5,in_f5,in_f6,in_f7,in_f8,
                     param_1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017de58
 * EN v1.0 Address: 0x8017DE58
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8017E048
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017de58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
  iVar1 = FUN_80017a98();
  dVar4 = (double)FUN_80017710((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
  if ((dVar4 < (double)lbl_803E4484) &&
     (dVar4 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18)),
     dVar4 < (double)lbl_803E4488)) {
    uVar2 = FUN_80017690(0x90f);
    if (uVar2 == 0) {
      uVar5 = (**(code **)(*DAT_803dd6d4 + 0x7c))(0x444,0,0);
      *(undefined2 *)(iVar3 + 0x5c) = 0xffff;
      *(undefined2 *)(iVar3 + 0x5e) = 0;
      *(float *)(iVar3 + 0x60) = lbl_803E4460;
      ObjMsg_SendToObject(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x7000a,
                   param_9,iVar3 + 0x5c,in_r7,in_r8,in_r9,in_r10);
      FUN_80017698(0x90f,1);
      *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 4;
    }
    else {
      FUN_80294d60(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                   (uint)*(ushort *)(iVar3 + 0x38));
      FUN_80081118((double)lbl_803E4460,param_9,0xff,0x28);
      uVar5 = FUN_80006824(param_9,0x58);
      iVar1 = *(int *)(param_9 + 0xb8);
      if ((*(ushort *)(param_9 + 6) & 0x2000) == 0) {
        if (*(int *)(param_9 + 0x54) != 0) {
          ObjHits_DisableObject(param_9);
        }
        *(byte *)(iVar1 + 0x5a) = *(byte *)(iVar1 + 0x5a) | 2;
      }
      else {
        FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e0f8
 * EN v1.0 Address: 0x8017E0F8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8017E1C4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e0f8(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e12c
 * EN v1.0 Address: 0x8017E12C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8017E1F4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e12c(int param_1)
{
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x5a) & 2) == 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e15c
 * EN v1.0 Address: 0x8017E15C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x8017E22C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e15c(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  fVar1 = lbl_803E446C;
  dVar5 = (double)lbl_803E446C;
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
                                            (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)lbl_803E4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C) {
          fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (lbl_803E446C < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
        *(float *)(param_3 + 0x30) = lbl_803E446C;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *param_2 = *(undefined2 *)(param_3 + 0x48);
        param_2[1] = *(undefined2 *)(param_3 + 0x4a);
        param_2[2] = *(undefined2 *)(param_3 + 0x4c);
        *(float *)(param_3 + 0x44) = -*(float *)(param_3 + 0x28);
        if ((*(byte *)(param_3 + 0x5a) & 8) == 0) {
          FUN_80006824((uint)param_2,0x407);
          *(byte *)(param_3 + 0x5a) = *(byte *)(param_3 + 0x5a) | 8;
        }
        uVar4 = 1;
      }
      else if ((double)lbl_803E448C <= dVar7) {
        dVar6 = (double)(float)(dVar6 + (double)*(float *)(param_3 + 0x3c));
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)lbl_803E4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C) {
          fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (lbl_803E446C < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x44) = *(float *)(param_3 + 0x44) * lbl_803E4490;
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
 * Function: FUN_8017e3c0
 * EN v1.0 Address: 0x8017E3C0
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x8017E48C
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e3c0(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (lbl_803E446C == *(float *)(param_3 + 0x3c)) {
    if (lbl_803E446C <
        *(float *)(param_3 + 0x30) - (float)((double)*(float *)(param_3 + 0x2c) - param_1)) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar6 = (double)*(float *)(param_3 + 0x40);
      dVar7 = (double)*(float *)(param_3 + 0x44);
      dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                          (double)((float)((double)lbl_803E4470 * dVar6) *
                                                  *(float *)(param_3 + 0x30))));
      fVar1 = (float)((double)lbl_803E4474 * dVar6);
      fVar2 = fVar1;
      if (fVar1 < lbl_803E446C) {
        fVar2 = -fVar1;
      }
      fVar3 = lbl_803E4460;
      if (lbl_803E4478 < fVar2) {
        fVar2 = (float)(-dVar7 - dVar5) / fVar1;
        fVar3 = (float)(-dVar7 + dVar5) / fVar1;
        if (lbl_803E446C < fVar2) {
          fVar3 = fVar2;
        }
      }
      *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
      *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
      *(float *)(param_3 + 0x30) = lbl_803E446C;
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
      *param_2 = *(undefined2 *)(param_3 + 0x48);
      param_2[1] = *(undefined2 *)(param_3 + 0x4a);
      param_2[2] = *(undefined2 *)(param_3 + 0x4c);
      *(float *)(param_3 + 0x44) =
           lbl_803E4474 * *(float *)(param_3 + 0x40) * fVar3 + *(float *)(param_3 + 0x44);
      *(undefined4 *)(param_3 + 0x3c) = *(undefined4 *)(param_3 + 0x28);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_2 + 6),(double)*(float *)(param_3 + 0x34),
                 (double)*(float *)(param_2 + 10),param_2);
      uVar4 = 0;
    }
  }
  else if ((float)(param_1 - (double)*(float *)(param_3 + 0x2c)) < lbl_803E446C) {
    *(float *)(param_2 + 8) = (float)param_1;
    uVar4 = 1;
  }
  else {
    dVar7 = (double)(*(float *)(param_3 + 0x40) + *(float *)(param_3 + 0x3c));
    dVar6 = (double)*(float *)(param_3 + 0x44);
    dVar5 = FUN_80293900((double)(float)(dVar6 * dVar6 -
                                        (double)((float)((double)lbl_803E4470 * dVar7) *
                                                *(float *)(param_3 + 0x30))));
    fVar1 = (float)((double)lbl_803E4474 * dVar7);
    fVar2 = fVar1;
    if (fVar1 < lbl_803E446C) {
      fVar2 = -fVar1;
    }
    fVar3 = lbl_803E4460;
    if (lbl_803E4478 < fVar2) {
      fVar2 = (float)(-dVar6 - dVar5) / fVar1;
      fVar3 = (float)(-dVar6 + dVar5) / fVar1;
      if (lbl_803E446C < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
    *(float *)(param_3 + 0x3c) = lbl_803E4494;
    *(float *)(param_3 + 0x44) = lbl_803E4498;
    uVar4 = 0;
  }
  return uVar4;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_8017D374(void) {}
void fn_8017D378(void) {}
void wm_column_hitDetect(void) {}
void wm_column_release(void) {}
void wm_column_initialise(void) {}
void appleontree_setScale(void) {}

/* 8b "li r3, N; blr" returners. */
int wm_column_getExtraSize(void) { return 0xa; }
int wm_column_func08(void) { return 0x0; }
int appleontree_getExtraSize(void) { return 0x64; }

/* Pattern wrappers. */
u8 appleontree_modelMtxFn(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x3a); }
