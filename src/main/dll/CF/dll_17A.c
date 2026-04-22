#include "ghidra_import.h"
#include "main/dll/CF/dll_17A.h"

extern uint FUN_80020078();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_8003b9ec();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e4a50;
extern f64 DOUBLE_803e4a68;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4a4c;
extern f32 FLOAT_803e4a58;
extern f32 FLOAT_803e4a5c;
extern f32 FLOAT_803e4a60;

/*
 * --INFO--
 *
 * Function: FUN_8018da3c
 * EN v1.0 Address: 0x8018DA3C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018da3c(int param_1)
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
 * Function: FUN_8018da70
 * EN v1.0 Address: 0x8018DA70
 * EN v1.0 Size: 144b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018da70(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  FUN_8002fb40((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x1b)) -
                               DOUBLE_803e4a50) / FLOAT_803e4a4c),(double)FLOAT_803dc074);
  uVar1 = (uint)*(short *)(iVar2 + 0x20);
  if (uVar1 != 0xffffffff) {
    uVar1 = FUN_80020078(uVar1);
    if (uVar1 == 0) {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x36) = 0xff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018db00
 * EN v1.0 Address: 0x8018DB00
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018db00(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  double dVar3;
  
  param_9[3] = param_9[3] | 2;
  uVar2 = *(byte *)(param_10 + 0x1c) ^ 0x80000000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a68);
  if ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a68) < FLOAT_803e4a58) {
    fVar1 = FLOAT_803e4a58;
  }
  dVar3 = (double)(fVar1 * FLOAT_803e4a5c);
  *(float *)(param_9 + 4) = (float)((double)*(float *)(*(int *)(param_9 + 0x28) + 4) * dVar3);
  *param_9 = (short)((*(byte *)(param_10 + 0x1d) & 0x3f) << 10);
  if (*(float **)(param_9 + 0x32) != (float *)0x0) {
    **(float **)(param_9 + 0x32) = (float)((double)**(float **)(param_9 + 0x28) * dVar3);
  }
  *(undefined *)((int)param_9 + 0xad) = *(undefined *)(param_10 + 0x18);
  if (*(char *)(*(int *)(param_9 + 0x28) + 0x55) <= *(char *)((int)param_9 + 0xad)) {
    *(undefined *)((int)param_9 + 0xad) = 0;
  }
  FUN_8003042c((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_10 + 0x1a)) -
                               DOUBLE_803e4a50) * FLOAT_803e4a60),dVar3,param_3,param_4,param_5,
               param_6,param_7,param_8,param_9,(uint)*(byte *)(param_10 + 0x19),0,param_12,param_13,
               param_14,param_15,param_16);
  if ((int)*(short *)(param_10 + 0x20) != 0xffffffff) {
    uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x20));
    if (uVar2 == 0) {
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0xff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018dc74
 * EN v1.0 Address: 0x8018DC74
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018dc74(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018dca4
 * EN v1.0 Address: 0x8018DCA4
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018dca4(void)
{
  int iVar1;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (((in_r8 != '\0') && (*(short *)(iVar1 + 0x46) != 0x1b8)) &&
     (((in_r8 != '\0' && (*(short *)(iVar1 + 0x46) != 0x6bf)) ||
      (uVar2 = FUN_80020078((int)*(short *)(*(int *)(iVar1 + 0xb8) + 0x3a)), uVar2 != 0)))) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018dd40
 * EN v1.0 Address: 0x8018DD40
 * EN v1.0 Size: 280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018dd40(undefined4 param_1,undefined4 param_2,int param_3)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar2 = FUN_80286840();
  sVar1 = *(short *)(iVar2 + 0x46);
  if (((sVar1 != 0xae) && (0xad < sVar1)) && (sVar1 == 0x2b7)) {
    uVar3 = FUN_80020078((int)*(short *)(*(int *)(iVar2 + 0xb8) + 0x3a));
    if (uVar3 != 0) {
      *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
    }
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
      if (*(char *)(param_3 + iVar4 + 0x81) == '\x01') {
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x44,0,2,0xffffffff,0);
      }
      *(undefined *)(param_3 + iVar4 + 0x81) = 0;
    }
  }
  FUN_8028688c();
  return;
}
