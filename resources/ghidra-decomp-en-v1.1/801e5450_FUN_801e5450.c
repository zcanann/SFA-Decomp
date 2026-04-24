// Function: FUN_801e5450
// Entry: 801e5450
// Size: 172 bytes

void FUN_801e5450(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  uint uVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(code **)(param_9 + 0x5e) = FUN_801e50b0;
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  param_9[0x58] = param_9[0x58] | 0x6000;
  *(undefined *)(*(int *)(param_9 + 0x5c) + 4) = 0;
  uVar1 = FUN_80020078(0x75);
  if (uVar1 == 0) {
    FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                 0x58,0,0,0,in_r9,in_r10);
    FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                 0x6d,0,0,0,in_r9,in_r10);
  }
  return;
}

