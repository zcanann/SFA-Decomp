#include "ghidra_import.h"
#include "main/dll/DR/DRpushcart.h"

extern undefined4 FUN_80006824();
extern double FUN_80006a38();
extern undefined4 FUN_80006ac8();
extern undefined4 FUN_80006acc();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006b74();
extern int FUN_80006b7c();
extern undefined4 FUN_80006bb4();
extern uint FUN_80006c00();
extern undefined4 FUN_80006c88();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_800176d0();
extern uint FUN_80017730();
extern uint FUN_80017760();
extern int FUN_8001792c();
extern undefined4 FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800632e8();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern undefined4 FUN_80081028();
extern undefined4 FUN_80081030();
extern undefined4 FUN_80081038();
extern undefined4 FUN_800810f4();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8011eb38();
extern undefined4 FUN_801f4f9c();
extern undefined4 FUN_801f4fa0();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern int FUN_80286838();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined2 FUN_80294d20();
extern undefined4 FUN_80294d28();
extern uint countLeadingZeros();

extern undefined4 DAT_803adcc8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803de8d8;
extern f64 DOUBLE_803e6698;
extern f64 DOUBLE_803e66f0;
extern f32 lbl_803DC074;
extern f32 lbl_803E6670;
extern f32 lbl_803E6674;
extern f32 lbl_803E6688;
extern f32 lbl_803E66B8;
extern f32 lbl_803E66BC;
extern f32 lbl_803E66C0;
extern f32 lbl_803E66C8;
extern f32 lbl_803E66CC;
extern f32 lbl_803E66D0;
extern f32 lbl_803E66D4;
extern f32 lbl_803E66D8;
extern f32 lbl_803E66DC;
extern f32 lbl_803E66E0;
extern f32 lbl_803E66E4;
extern f32 lbl_803E66E8;
extern f32 lbl_803E66F8;

/*
 * --INFO--
 *
 * Function: FUN_801e76a0
 * EN v1.0 Address: 0x801E76A0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E7714
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e76a0(int param_1)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0xcef);
  if (uVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar1 = FUN_80017690(0xad3);
    if (uVar1 == 0) {
      FUN_80017698(0xad3,1);
      iVar3 = *(int *)(iVar3 + 0x9b4);
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x24))(iVar3,1,2);
    }
    uVar2 = 2;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7724
 * EN v1.0 Address: 0x801E7724
 * EN v1.0 Size: 1032b
 * EN v1.1 Address: 0x801E7794
 * EN v1.1 Size: 1096b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801e7724(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  char local_18;
  undefined auStack_17 [7];
  
  iVar7 = *(int *)(param_1 + 0xb8);
  if (param_3 == 0x14) {
    FUN_80006bb4(0,auStack_17,&local_18);
    if (local_18 < '\0') {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9d0) + -1;
      FUN_80006824(0,0xf3);
    }
    else if ('\0' < local_18) {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9d0) + 1;
      FUN_80006824(0,0xf3);
    }
    if (*(short *)(iVar7 + 0x9c8) < *(short *)(iVar7 + 0x9d0)) {
      *(short *)(iVar7 + 0x9d0) = *(short *)(iVar7 + 0x9c8);
    }
    iVar3 = (int)*(short *)(iVar7 + 0x9cc) << 1;
    if (iVar3 < *(short *)(iVar7 + 0x9d0)) {
      *(short *)(iVar7 + 0x9d0) = (short)iVar3;
    }
    else {
      iVar3 = (int)*(short *)(iVar7 + 0x9cc) >> 1;
      if (*(short *)(iVar7 + 0x9d0) < iVar3) {
        *(short *)(iVar7 + 0x9d0) = (short)iVar3;
      }
    }
    iVar8 = (int)*(short *)(iVar7 + 0x9d0);
    piVar4 = (int *)FUN_80039520(param_1,8);
    iVar3 = iVar8 >> 0x1f;
    iVar1 = iVar8 / 10 + iVar3;
    *piVar4 = (iVar8 + (iVar1 - (iVar1 >> 0x1f)) * -10) * 0x100;
    piVar4 = (int *)FUN_80039520(param_1,7);
    iVar1 = iVar8 / 10 + iVar3;
    iVar1 = iVar1 - (iVar1 >> 0x1f);
    iVar2 = iVar1 / 10 + (iVar1 >> 0x1f);
    *piVar4 = (iVar1 + (iVar2 - (iVar2 >> 0x1f)) * -10) * 0x100;
    iVar3 = iVar8 / 100 + iVar3;
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    if (9 < iVar3) {
      iVar3 = 9;
    }
    piVar4 = (int *)FUN_80039520(param_1,6);
    *piVar4 = iVar3 << 8;
  }
  else if (param_3 == 0x17) {
    FUN_80006bb4(0,auStack_17,&local_18);
    if (local_18 < '\0') {
      *(char *)(iVar7 + 0x9d5) = *(char *)(iVar7 + 0x9d5) + -1;
      FUN_80006824(0,0xf3);
    }
    else if ('\0' < local_18) {
      *(char *)(iVar7 + 0x9d5) = *(char *)(iVar7 + 0x9d5) + '\x01';
      FUN_80006824(0,0xf3);
    }
    if (*(short *)(iVar7 + 0x9c8) < (short)(ushort)*(byte *)(iVar7 + 0x9d5)) {
      *(char *)(iVar7 + 0x9d5) = (char)*(short *)(iVar7 + 0x9c8);
    }
    if (*(byte *)(iVar7 + 0x9d5) < 0xb) {
      if (*(byte *)(iVar7 + 0x9d5) == 0) {
        *(undefined *)(iVar7 + 0x9d5) = 1;
      }
    }
    else {
      *(undefined *)(iVar7 + 0x9d5) = 10;
    }
    uVar5 = (uint)*(byte *)(iVar7 + 0x9d5);
    piVar4 = (int *)FUN_80039520(param_1,8);
    *piVar4 = (uVar5 % 10) * 0x100;
    piVar4 = (int *)FUN_80039520(param_1,7);
    *piVar4 = ((uVar5 / 10) % 10) * 0x100;
    uVar5 = uVar5 / 100;
    if (9 < uVar5) {
      uVar5 = 9;
    }
    piVar4 = (int *)FUN_80039520(param_1,6);
    *piVar4 = uVar5 << 8;
    uVar5 = FUN_80006c00(0);
    if ((uVar5 & 0x200) != 0) {
      *(byte *)(iVar7 + 0x9d4) = *(byte *)(iVar7 + 0x9d4) | 0x10;
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
      return 1;
    }
  }
  uVar5 = FUN_80006c00(0);
  if ((uVar5 & 0x100) == 0) {
    uVar5 = 0;
  }
  else {
    if (*(short *)(iVar7 + 0x9d0) < *(short *)(iVar7 + 0x9ce)) {
      if (*(byte *)(iVar7 + 0x9d2) < 2) {
        cVar6 = '\0';
      }
      else {
        cVar6 = '\x02';
      }
    }
    else {
      cVar6 = '\x01';
    }
    if (param_3 == 0x15) {
      if (cVar6 == '\x01') {
        (**(code **)(**(int **)(*(int *)(iVar7 + 0x9b4) + 0x68) + 0x48))();
      }
      uVar5 = countLeadingZeros(1 - cVar6);
      uVar5 = uVar5 >> 5;
    }
    else {
      if (param_3 < 0x15) {
        if (0x13 < param_3) {
          if (cVar6 == '\0') {
            *(char *)(iVar7 + 0x9d2) = *(char *)(iVar7 + 0x9d2) + '\x01';
          }
          uVar5 = countLeadingZeros((int)cVar6);
          return uVar5 >> 5;
        }
      }
      else if (param_3 < 0x17) {
        uVar5 = countLeadingZeros(2 - cVar6);
        return uVar5 >> 5;
      }
      uVar5 = 0;
    }
  }
  return uVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7b2c
 * EN v1.0 Address: 0x801E7B2C
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801E7BDC
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e7b2c(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar1 + 0x9d4) & 2) == 0) {
    FUN_8011e800(0);
  }
  else {
    FUN_80006b54(0x11,0x1e);
    FUN_80006b50();
    FUN_8011eb38(1);
    FUN_80017698(0x626,1);
    (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x4c))
              (*(int *)(iVar1 + 0x9b4),*(undefined *)(iVar1 + 0x9d5));
    (**(code **)(*DAT_803dd6f4 + 4))(0,0xf5,0,0,0);
  }
  *(undefined *)(iVar1 + 0x9d4) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7be4
 * EN v1.0 Address: 0x801E7BE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E7C90
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e7be4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,char param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e7be8
 * EN v1.0 Address: 0x801E7BE8
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801E823C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801e7be8(ushort *param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  
  fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 6);
  fVar2 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 10);
  dVar5 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  if ((double)lbl_803E66BC < dVar5) {
    uVar3 = FUN_80017730();
    if (param_3 == 0) {
      iVar4 = (uVar3 & 0xffff) - (uint)*param_1;
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      if (iVar4 < 0x2001) {
        if (iVar4 < -0x2000) {
          iVar4 = iVar4 + 0x2000;
        }
        else {
          iVar4 = 0;
        }
      }
      else {
        iVar4 = iVar4 + -0x2000;
      }
      *param_1 = (ushort)(int)((float)((double)CONCAT44(0x43300000,iVar4 >> 3 ^ 0x80000000) -
                                      DOUBLE_803e6698) * lbl_803DC074 +
                              (float)((double)CONCAT44(0x43300000,(int)(short)*param_1 ^ 0x80000000)
                                     - DOUBLE_803e6698));
    }
    else {
      *param_1 = (ushort)uVar3;
    }
  }
  return dVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_801e7d3c
 * EN v1.0 Address: 0x801E7D3C
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x801E83B8
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e7d3c(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
  int iVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  undefined2 *puVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar9;
  float local_28 [2];
  longlong local_20;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  uVar4 = FUN_80017ae8();
  if ((uVar4 & 0xff) != 0) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar3 + 0xac),6,1);
    dVar7 = (double)*(float *)(iVar3 + 0x10);
    dVar8 = (double)*(float *)(iVar3 + 0x14);
    FUN_800632e8((double)*(float *)(iVar3 + 0xc),dVar7,dVar8,iVar3,local_28,0);
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      puVar5 = FUN_80017aa4(0x24,0x47f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
      uVar4 = FUN_80017760(0xffffff80,0x7f);
      *(char *)(puVar5 + 0xc) = (char)uVar4;
      fVar2 = *(float *)(iVar3 + 0x10);
      iVar1 = (int)((double)fVar2 - (double)local_28[0]);
      local_20 = (longlong)iVar1;
      puVar5[0xd] = (short)iVar1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      *(undefined *)(puVar5 + 2) = 0x10;
      *(undefined *)(puVar5 + 3) = 6;
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)((int)uVar9 + 0x9b4);
      FUN_80017ae4((double)fVar2,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,puVar5,5,
                   *(undefined *)(iVar3 + 0xac),0xffffffff,*(uint **)(iVar3 + 0x30),param_6,param_7,
                   param_8);
    }
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      puVar5 = FUN_80017aa4(0x24,0x47f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
      uVar4 = FUN_80017760(0xffffff80,0x7f);
      *(char *)(puVar5 + 0xc) = (char)uVar4;
      fVar2 = *(float *)(iVar3 + 0x10);
      iVar1 = (int)((double)fVar2 - (double)local_28[0]);
      local_20 = (longlong)iVar1;
      puVar5[0xd] = (short)iVar1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      *(undefined *)(puVar5 + 2) = 0x10;
      *(undefined *)(puVar5 + 3) = 6;
      *(undefined *)((int)puVar5 + 0x19) = 1;
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)((int)uVar9 + 0x9b4);
      FUN_80017ae4((double)fVar2,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,puVar5,5,
                   *(undefined *)(iVar3 + 0xac),0xffffffff,*(uint **)(iVar3 + 0x30),param_6,param_7,
                   param_8);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E7FEC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E85B4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void shopkeeper_render(int param_1)
{
  FUN_80006ac8(*(uint *)(*(int *)(param_1 + 0xb8) + 0x9b0));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8014
 * EN v1.0 Address: 0x801E8014
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E85DC
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8014(short *param_1)
{
  char in_r8;
  int iVar1;
  float local_18 [4];
  
  iVar1 = *(int *)(param_1 + 0x5c);
  local_18[0] = lbl_803E6670;
  if ((*(short *)(iVar1 + 0x274) != 7) && (in_r8 != '\0')) {
    FUN_8003b818((int)param_1);
    FUN_801149bc(param_1,iVar1 + 0x35c,0);
  }
  if ((*(byte *)(iVar1 + 0x9d4) & 0x20) != 0) {
    (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7ef,local_18,0x50,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e80b0
 * EN v1.0 Address: 0x801E80B0
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801E8680
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e80b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  int iVar1;
  undefined4 uVar2;
  undefined2 uVar3;
  int iVar4;
  float local_18 [3];
  
  iVar1 = FUN_80017a98();
  iVar4 = *(int *)(param_9 + 0x5c);
  local_18[0] = lbl_803E66B8;
  *(byte *)(iVar4 + 0x9d4) = *(byte *)(iVar4 + 0x9d4) & 0xdf;
  if ((double)lbl_803E6674 < (double)*(float *)(iVar4 + 0x9c4)) {
    FUN_80006c88((double)*(float *)(iVar4 + 0x9c4),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,0x433);
    *(float *)(iVar4 + 0x9c4) = *(float *)(iVar4 + 0x9c4) - lbl_803DC074;
    if (*(float *)(iVar4 + 0x9c4) < lbl_803E6674) {
      *(float *)(iVar4 + 0x9c4) = lbl_803E6674;
    }
  }
  if ((*(byte *)(iVar4 + 0x9d4) & 4) != 0) {
    FUN_801e7be8(param_9,iVar1,1);
  }
  *(undefined4 *)(param_9 + 4) = *(undefined4 *)(*(int *)(param_9 + 0x28) + 4);
  if (*(int *)(iVar4 + 0x9b4) == 0) {
    uVar2 = ObjGroup_FindNearestObject(9,param_9,local_18);
    *(undefined4 *)(iVar4 + 0x9b4) = uVar2;
  }
  uVar3 = FUN_80294d20(iVar1);
  *(undefined2 *)(iVar4 + 0x9c8) = uVar3;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)lbl_803DC074,(double)lbl_803DC074,param_9,iVar4,&DAT_803adcc8,&DAT_803de8d8
            );
  FUN_801150ac();
  FUN_8003b280((int)param_9,iVar4 + 0x980);
  *(undefined *)(param_9 + 0x1b) = *(undefined *)(iVar4 + 0x9d6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8274
 * EN v1.0 Address: 0x801E8274
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E87C4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8274(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e8278
 * EN v1.0 Address: 0x801E8278
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801E891C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8278(int param_1)
{
  if (*(char *)(param_1 + 0x37) == -1) {
    FUN_8025cce8(0,1,0,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  FUN_8006f8fc(1,3,0);
  FUN_8006f8a4(1);
  FUN_8025c754(7,0,0,7,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8300
 * EN v1.0 Address: 0x801E8300
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801E89A0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8300(void)
{
  float fVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  byte bVar9;
  int iVar10;
  double in_f31;
  double dVar11;
  double in_ps31_1;
  float local_88;
  float local_84;
  float local_80;
  int local_7c;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar3 = FUN_80286838();
  iVar10 = *(int *)(iVar3 + 0xb8);
  bVar2 = false;
  if ((*(byte *)(iVar10 + 0xe8) >> 6 & 1) == 0) {
    FUN_800810f4((double)lbl_803E66C8,(double)lbl_803E66D0,iVar3,5,1,1,0x14,0,0);
  }
  else {
    FUN_800810f4((double)lbl_803E66C8,(double)lbl_803E66CC,iVar3,5,1,1,0x14,0,0);
  }
  piVar4 = (int *)FUN_80017a54(iVar3);
  iVar5 = FUN_8001792c(*piVar4,0);
  *(undefined *)(iVar5 + 0x43) = 0x7f;
  FUN_8003b818(iVar3);
  for (bVar9 = 0; bVar9 < 10; bVar9 = bVar9 + 1) {
    iVar5 = iVar10 + (uint)bVar9 * 4;
    if (*(float **)(iVar5 + 0x98) == (float *)0x0) {
      if ((!bVar2) && (iVar6 = FUN_800176d0(), iVar6 == 0)) {
        local_88 = *(float *)(iVar3 + 0xc);
        local_84 = *(float *)(iVar3 + 0x10);
        local_80 = *(float *)(iVar3 + 0x14);
        fVar1 = lbl_803E66DC;
        if ((*(byte *)(iVar10 + 0xe8) >> 6 & 1) != 0) {
          fVar1 = lbl_803E66D8;
        }
        dVar11 = (double)fVar1;
        local_7c = iVar3;
        uVar7 = FUN_80017760(0,2000);
        local_50 = (double)CONCAT44(0x43300000,uVar7 - 1000 ^ 0x80000000);
        local_88 = (float)(dVar11 * (double)(float)(local_50 - DOUBLE_803e66f0) + (double)local_88);
        uVar7 = FUN_80017760(0,2000);
        uStack_44 = uVar7 - 1000 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                                   DOUBLE_803e66f0) + (double)local_84);
        uVar7 = FUN_80017760(0,2000);
        uStack_3c = uVar7 - 1000 ^ 0x80000000;
        local_40 = 0x43300000;
        local_80 = (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                   DOUBLE_803e66f0) + (double)local_80);
        uVar8 = FUN_80081030((double)lbl_803E66E0,(double)lbl_803E66E4,iVar3 + 0xc,&local_88,
                             0x14,0x40,0);
        *(undefined4 *)(iVar5 + 0x98) = uVar8;
        *(float *)(iVar5 + 0xc0) = lbl_803E66E8;
        bVar2 = true;
      }
    }
    else {
      FUN_80081028(*(float **)(iVar5 + 0x98));
      iVar6 = FUN_800176d0();
      if (iVar6 == 0) {
        *(float *)(iVar5 + 0xc0) = *(float *)(iVar5 + 0xc0) + lbl_803DC074;
        iVar6 = (int)(lbl_803E66D4 + *(float *)(iVar5 + 0xc0));
        local_50 = (double)(longlong)iVar6;
        *(short *)(*(int *)(iVar5 + 0x98) + 0x20) = (short)iVar6;
        if (0x14 < *(ushort *)(*(uint *)(iVar5 + 0x98) + 0x20)) {
          FUN_80081038(*(uint *)(iVar5 + 0x98));
          *(undefined4 *)(iVar5 + 0x98) = 0;
        }
      }
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8514
 * EN v1.0 Address: 0x801E8514
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E8C50
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8514(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (((*(byte *)(iVar2 + 0x97) >> 6 & 1) == 0) &&
     (iVar1 = (**(code **)(**(int **)(*(int *)(iVar2 + 0x90) + 0x68) + 0x2c))
                        (*(int *)(iVar2 + 0x90),*(undefined *)(*(int *)(param_1 + 0x4c) + 0x19)),
     iVar1 != 0)) {
    *(byte *)(iVar2 + 0x97) = *(byte *)(iVar2 + 0x97) & 0x7f | 0x80;
  }
  FUN_8011e800(0);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x90) + 0x68) + 0x40))(*(int *)(iVar2 + 0x90),0xffffffff)
  ;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e85b0
 * EN v1.0 Address: 0x801E85B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E8CE4
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e85b0(undefined2 *param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801e85b8
 * EN v1.0 Address: 0x801E85B8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801E8EA8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e85b8(int param_1)
{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  if (*(short *)(param_1 + 0x46) == 0x468) {
    iVar3 = *(int *)(param_1 + 0xb8);
    for (bVar2 = 0; bVar2 < 10; bVar2 = bVar2 + 1) {
      uVar1 = *(uint *)(iVar3 + (uint)bVar2 * 4 + 0x98);
      if (uVar1 != 0) {
        FUN_80081038(uVar1);
      }
    }
    ObjGroup_RemoveObject(param_1,0x4f);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e8658
 * EN v1.0 Address: 0x801E8658
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801E8F48
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8658(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    if (*(short *)(param_1 + 0x46) == 0x468) {
      FUN_801e8300();
    }
    else {
      FUN_8003b818(param_1);
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void shopkeeper_hitDetect(void) {}
void shopkeeper_release(void) {}
void shopitem_hitDetect(void) {}
void shopitem_release(void) {}
void shopitem_initialise(void) {}
void spscarab_render(void) {}
void spscarab_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int shopkeeper_getExtraSize(void) { return 0x9d8; }
int shopkeeper_func08(void) { return 0x0; }
int shopitem_getExtraSize(void) { return 0xec; }
int shopitem_func08(void) { return 0x0; }
int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_func08(void) { return 0x0; }

extern void fn_8000DB90(int x, int y);
#pragma scheduling off
void spscarab_free(int x) { fn_8000DB90(x, 0x406); }
#pragma scheduling reset
