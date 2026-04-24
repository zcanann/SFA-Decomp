#include "ghidra_import.h"
#include "main/dll/mmshrine/shrine.h"

extern undefined8 FUN_80008cbc();
extern undefined4 FUN_80009a94();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001f448();
extern void* FUN_8001f58c();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002e1f4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80043604();
extern int FUN_8004832c();
extern undefined8 FUN_80088f20();
extern undefined4 FUN_8009a010();
extern undefined4 FUN_8011f9b8();
extern undefined4 FUN_801c4c18();
extern undefined4 FUN_801c50c4();
extern undefined4 FUN_801d84c4();
extern undefined4 FUN_801d8650();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern uint FUN_80296cb4();

extern undefined4 DAT_803dc071;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f4;
extern f64 DOUBLE_803e5bd0;
extern f64 DOUBLE_803e5c08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5bd8;
extern f32 FLOAT_803e5be8;

/*
 * --INFO--
 *
 * Function: FUN_801c533c
 * EN v1.0 Address: 0x801C52D8
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x801C533C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c533c(int param_1)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if ((puVar1[6] & 0x20) != 0) {
    FUN_8011f9b8(0);
    puVar1[6] = puVar1[6] & 0xffffffdf;
  }
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
    *puVar1 = 0;
  }
  FUN_8000a538((int *)0xd8,0);
  FUN_8000a538((int *)0xd9,0);
  FUN_8000a538((int *)0x8,0);
  FUN_8000a538((int *)0xa,0);
  FUN_800201ac(0xefa,0);
  FUN_800201ac(0xcbb,1);
  FUN_800201ac(0xe82,0);
  FUN_800201ac(0xe83,0);
  FUN_800201ac(0xe84,0);
  FUN_800201ac(0xe85,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c5418
 * EN v1.0 Address: 0x801C53B0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C5418
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5418(void)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5be8,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5be8,*piVar2,'\x01');
    }
    FUN_8003b9ec(iVar1);
    FUN_8009a010((double)FLOAT_803e5be8,(double)FLOAT_803e5be8,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c54d4
 * EN v1.0 Address: 0x801C5448
 * EN v1.0 Size: 1236b
 * EN v1.1 Address: 0x801C54D4
 * EN v1.1 Size: 952b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c54d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar3 = FUN_8002bac4();
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar7 = FUN_80088f20(7,'\x01');
    uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3
                         ,0x20d,0,in_r7,in_r8,in_r9,in_r10);
    uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3
                         ,0x20e,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3,0x222,0
                 ,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
  }
  iVar4 = FUN_8004832c(0x20);
  FUN_80043604(iVar4,1,0);
  FUN_801c4c18(param_9);
  FUN_801d84c4(iVar6 + 0x18,8,-1,-1,0xae6,(int *)0xa);
  FUN_801d8650(iVar6 + 0x18,4,-1,-1,0xcbb,(int *)0x8);
  FUN_801d84c4(iVar6 + 0x18,0x10,-1,-1,0xcbb,(int *)0xc4);
  bVar1 = *(byte *)(iVar6 + 0x24);
  if (bVar1 == 3) {
    (**(code **)(*DAT_803dd6d4 + 0x4c))((int)(short)param_9[0x5a]);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_9,0xffffffff);
    *(undefined *)(iVar6 + 0x24) = 4;
    FUN_800201ac(0xae6,0);
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if ((*(uint *)(iVar6 + 0x18) & 1) != 0) {
        param_9[3] = param_9[3] | 0x4000;
        *param_9 = 0;
        *(undefined *)(iVar6 + 0x24) = 2;
        *(uint *)(iVar6 + 0x18) = *(uint *)(iVar6 + 0x18) & 0xfffffffe;
        FUN_800201ac(0xae6,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      }
    }
    else if (bVar1 == 0) {
      fVar2 = *(float *)(iVar6 + 0x14) - FLOAT_803dc074;
      *(float *)(iVar6 + 0x14) = fVar2;
      if (fVar2 <= FLOAT_803e5bd8) {
        FUN_8000bb38((uint)param_9,0x343);
        uVar5 = FUN_80022264(500,1000);
        *(float *)(iVar6 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e5bd0);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        *(undefined *)(iVar6 + 0x24) = 1;
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x4c,0,0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_8000a538((int *)0xd8,1);
      }
    }
    else {
      uVar5 = FUN_80296cb4(iVar3,4);
      if (uVar5 == 0) {
        FUN_80009a94(3);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      *(undefined *)(iVar6 + 0x24) = 5;
      FUN_800201ac(0xae6,0);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(iVar6 + 0x24) = 0;
    *(uint *)(iVar6 + 0x18) = *(uint *)(iVar6 + 0x18) & 0xfffffffe;
    param_9[3] = param_9[3] & 0xbfff;
    FUN_800201ac(299,0);
    FUN_800201ac(0xae4,0);
    FUN_800201ac(0xae5,0);
    FUN_800201ac(0xae6,0);
  }
  else if (bVar1 < 5) {
    *(undefined *)(iVar6 + 0x24) = 5;
    FUN_800201ac(0xae6,0);
    FUN_800201ac(0xae4,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c588c
 * EN v1.0 Address: 0x801C591C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C588C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c588c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c5964
 * EN v1.0 Address: 0x801C5920
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801C5964
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5964(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  undefined8 uVar1;
  
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_9 + 0xb8));
  uVar1 = (**(code **)(*DAT_803dd6f4 + 8))(param_9,0xffff,0,0,0);
  if ((*(int *)(param_9 + 200) != 0) && (param_10 == 0)) {
    FUN_8002cc9c(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c59f4
 * EN v1.0 Address: 0x801C5A34
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C59F4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c59f4(int param_1)
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
 * Function: FUN_801c5a28
 * EN v1.0 Address: 0x801C5A5C
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x801C5A28
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5a28(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  int local_28;
  int local_24 [6];
  
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_24[2] = (int)DAT_803dc071;
    local_24[1] = 0x43300000;
    local_24[0] = (**(code **)(*DAT_803dd6d4 + 0x14))
                            ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) -
                                            DOUBLE_803e5c08));
    if ((local_24[0] != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar4 = (int)*(char *)(*(int *)(param_9 + 0xb8) + 0x57);
      iVar5 = 0;
      uVar6 = extraout_f1;
      piVar1 = (int *)FUN_8002e1f4(local_24,&local_28);
      iVar3 = 0;
      for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar4) {
          iVar5 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar4 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar5 != 0)) && (*(short *)(iVar5 + 0xb4) != -1)) {
        *(undefined2 *)(iVar5 + 0xb4) = 0xffff;
        uVar6 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar4);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      FUN_8002cc9c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}
