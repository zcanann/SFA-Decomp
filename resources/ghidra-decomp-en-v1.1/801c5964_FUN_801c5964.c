// Function: FUN_801c5964
// Entry: 801c5964
// Size: 144 bytes

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

