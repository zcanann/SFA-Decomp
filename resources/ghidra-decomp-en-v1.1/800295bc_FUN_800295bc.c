// Function: FUN_800295bc
// Entry: 800295bc
// Size: 140 bytes

int * FUN_800295bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                  undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                  byte *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                  uint *param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int *piVar2;
  undefined8 extraout_f1;
  undefined8 uVar3;
  
  uVar1 = countLeadingZeros(1 - (uint)*param_9);
  uVar1 = uVar1 >> 5;
  piVar2 = (int *)FUN_80025ba8();
  uVar3 = FUN_80024f8c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar2,
                       piVar2[0xb],uVar1,param_11,param_13,param_14,param_15,param_16);
  if (piVar2[0xc] != 0) {
    FUN_80024f8c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar2,piVar2[0xc],
                 uVar1,param_11,param_13,param_14,param_15,param_16);
  }
  FUN_80028f84((int)param_9,(int)piVar2);
  param_9[8] = 0;
  param_9[9] = 0;
  param_9[10] = 0;
  param_9[0xb] = 0;
  FUN_80242114((uint)param_9,*(int *)(param_9 + 0xc));
  return piVar2;
}

