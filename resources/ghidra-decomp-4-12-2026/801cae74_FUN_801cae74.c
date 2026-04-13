// Function: FUN_801cae74
// Entry: 801cae74
// Size: 132 bytes

void FUN_801cae74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  if ((*(int *)(param_9 + 0xf4) != 0) &&
     (*(int *)(param_9 + 0xf4) = *(int *)(param_9 + 0xf4) + -1, *(int *)(param_9 + 0xf4) == 0)) {
    uVar1 = FUN_80088f20(7,'\x01');
    uVar1 = FUN_80008cbc(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xd1,0,
                         in_r7,in_r8,in_r9,in_r10);
    uVar1 = FUN_80008cbc(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xd6,0,
                         in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x222,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  return;
}

