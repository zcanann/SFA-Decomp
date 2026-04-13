// Function: FUN_801acd44
// Entry: 801acd44
// Size: 560 bytes

void FUN_801acd44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_r4;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(int *)(param_9 + 0xf4) == 0) {
    uVar5 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0xa3,0,param_13,param_14,param_15,param_16);
    uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x9e,0,param_13,param_14,param_15,param_16);
    param_11 = 0x104;
    param_12 = 0;
    FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x104
                 ,0,param_13,param_14,param_15,param_16);
    param_1 = (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
    *(undefined4 *)(param_9 + 0xf4) = 1;
    param_10 = extraout_r4;
  }
  bVar1 = *(byte *)(iVar4 + 0xc);
  if (bVar1 == 2) {
    uVar2 = FUN_80020078(0x3a3);
    if (uVar2 != 0) {
      FUN_801ac5d0(param_9);
    }
  }
  else if ((bVar1 < 2) && (bVar1 != 0)) {
    FUN_801ac7fc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                 param_11,param_12,param_13,param_14,param_15,param_16);
  }
  *(uint *)(iVar4 + 4) = *(uint *)(iVar4 + 4) & 0xfffffffe;
  if (FLOAT_803e5374 < *(float *)(iVar4 + 0x10)) {
    uVar5 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x351);
    *(float *)(iVar4 + 0x10) = *(float *)(iVar4 + 0x10) - FLOAT_803dc074;
    if (*(float *)(iVar4 + 0x10) < FLOAT_803e5374) {
      *(float *)(iVar4 + 0x10) = FLOAT_803e5374;
    }
  }
  iVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar3 == 0) {
    if ((*(short *)(iVar4 + 10) != 0x1a) &&
       (*(undefined2 *)(iVar4 + 10) = 0x1a, (*(uint *)(iVar4 + 4) & 8) != 0)) {
      FUN_8000a538((int *)0x1a,1);
    }
  }
  else if ((*(short *)(iVar4 + 10) != -1) &&
          (*(undefined2 *)(iVar4 + 10) = 0xffff, (*(uint *)(iVar4 + 4) & 8) != 0)) {
    FUN_8000a538((int *)0x1a,0);
  }
  FUN_801d84c4(iVar4 + 4,2,0x2c1,0x238,0x1ed,(int *)0xb2);
  FUN_801d84c4(iVar4 + 4,0x10,0x1ba,0x1b9,0x1d6,(int *)0xb4);
  FUN_801d84c4(iVar4 + 4,4,-1,-1,0x3a0,(int *)0xe9);
  FUN_801d84c4(iVar4 + 4,8,-1,-1,0x3a1,(int *)(int)*(short *)(iVar4 + 10));
  return;
}

