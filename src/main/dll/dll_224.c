#include "ghidra_import.h"
#include "main/dll/dll_224.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e69c();
extern undefined4 FUN_80014acc();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_8003042c();
extern int FUN_80036974();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_8009a468();

extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4 DAT_803de814;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803de818;
extern f32 FLOAT_803e5928;
extern f32 FLOAT_803e5930;
extern f32 FLOAT_803e5940;
extern f32 FLOAT_803e5944;
extern f32 FLOAT_803e5948;

/*
 * --INFO--
 *
 * Function: FUN_801be4d4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BE4D4
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801be4d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e5930;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801be530
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801BE530
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801be530(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 in_r10;
  undefined8 uVar5;
  uint uStack_38;
  int local_34;
  int local_30;
  undefined auStack_2c [12];
  float local_20;
  undefined4 local_1c;
  float local_18;
  
  iVar1 = FUN_80036974(param_9,&local_30,&local_34,&uStack_38);
  if (iVar1 != 0) {
    iVar2 = *(int *)(*(int *)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4) + 0x50) +
            local_34 * 0x10;
    local_20 = FLOAT_803dda58 + *(float *)(iVar2 + 4);
    local_1c = *(undefined4 *)(iVar2 + 8);
    local_18 = FLOAT_803dda5c + *(float *)(iVar2 + 0xc);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x4b2,auStack_2c,0x200001,0xffffffff,0);
    uVar3 = 0xffffffff;
    uVar4 = 0;
    iVar2 = *DAT_803dd708;
    (**(code **)(iVar2 + 8))(param_9,0x4b3,auStack_2c,0x200001);
    FUN_8009a468(param_9,auStack_2c,3,(int *)0x0);
    FUN_8000bb38(param_9,0x18a);
    FUN_80014acc((double)FLOAT_803e5940);
    if (*(char *)(param_10 + 0x354) == '\0') {
      FUN_8000bb38(param_9,0x18c);
    }
    else {
      FUN_8000bb38(param_9,0x18b);
    }
    FUN_8000e69c((double)FLOAT_803e5944);
    if (FLOAT_803e5928 == FLOAT_803de818) {
      *(undefined *)(param_10 + 0x27a) = 1;
      *(undefined *)(param_10 + 0x346) = 0;
      *(char *)(param_10 + 0x34f) = (char)iVar1;
      *(char *)(param_10 + 0x354) = *(char *)(param_10 + 0x354) + -1;
      DAT_803de814 = DAT_803de814 + '\x01';
      FUN_800201ac(0x20c,(int)DAT_803de814);
      if ((DAT_803de814 == '\x03') || (DAT_803de814 == '\a')) {
        FLOAT_803de818 = FLOAT_803e5948;
      }
      else {
        FLOAT_803de818 = FLOAT_803e5928;
      }
      uVar5 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
      *(undefined2 *)(param_10 + 0x270) = 1;
      FUN_800379bc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_30,0xe0001,
                   param_9,0,uVar3,uVar4,iVar2,in_r10);
    }
  }
  return;
}
