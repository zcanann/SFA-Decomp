// Function: FUN_8016c324
// Entry: 8016c324
// Size: 196 bytes

void FUN_8016c324(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  undefined8 uVar1;
  
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_9 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_9,0xffff,0,0,0);
  FUN_8000da9c(param_9);
  uVar1 = FUN_8000b7dc(param_9,0x7f);
  if ((*(short *)(param_9 + 0x46) == 0x774) && (*(char *)(param_9 + 0xeb) != '\0')) {
    FUN_8002cc9c(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    FUN_80037da8(param_9,*(int *)(param_9 + 200));
  }
  if (param_10 != 0) {
    FUN_80080484();
  }
  return;
}

