// Function: FUN_80244000
// Entry: 80244000
// Size: 96 bytes

void FUN_80244000(int param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_80245d78();
  FUN_80245d78(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = param_2;
  *(undefined4 *)(param_1 + 0x14) = param_3;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  return;
}

