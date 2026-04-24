// Function: FUN_801a93f4
// Entry: 801a93f4
// Size: 224 bytes

void FUN_801a93f4(uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 == 0) {
    *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    if (*(int *)(param_1 + 0xf4) < 0) {
      uVar1 = FUN_80022264(0x46,0xf0);
      *(uint *)(param_1 + 0xf4) = uVar1;
      uVar1 = FUN_80022264(0x1e,0x3c);
      *(uint *)(param_1 + 0xf8) = uVar1;
    }
    if (*(int *)(param_1 + 0xf8) != 0) {
      *(uint *)(param_1 + 0xf8) = *(int *)(param_1 + 0xf8) - (uint)DAT_803dc070;
      if (*(int *)(param_1 + 0xf8) < 1) {
        *(undefined4 *)(param_1 + 0xf8) = 0;
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x724,0,2,0xffffffff,0);
        FUN_8000da78(param_1,0x450);
      }
    }
  }
  return;
}

