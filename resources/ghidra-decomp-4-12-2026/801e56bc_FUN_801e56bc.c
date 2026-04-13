// Function: FUN_801e56bc
// Entry: 801e56bc
// Size: 136 bytes

void FUN_801e56bc(int param_1)

{
  uint uVar1;
  
  if (((*(short *)(param_1 + 0x46) == 0x173) && (*(int *)(param_1 + 0xf4) == 0)) &&
     (uVar1 = FUN_80020078(0xa4b), uVar1 != 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  return;
}

