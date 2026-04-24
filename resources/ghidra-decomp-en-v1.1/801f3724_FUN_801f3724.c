// Function: FUN_801f3724
// Entry: 801f3724
// Size: 116 bytes

void FUN_801f3724(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  if ((param_10 == 0) && (**(int **)(param_9 + 0xb8) != 0)) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 **(int **)(param_9 + 0xb8));
  }
  (**(code **)(*DAT_803dd6fc + 0x18))(param_9);
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
  return;
}

