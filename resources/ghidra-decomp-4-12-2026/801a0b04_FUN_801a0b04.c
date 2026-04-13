// Function: FUN_801a0b04
// Entry: 801a0b04
// Size: 108 bytes

void FUN_801a0b04(int param_1)

{
  uint uVar1;
  
  if ((*(int *)(param_1 + 0xf4) != 0) && (uVar1 = FUN_80020078(0x50), uVar1 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  *(undefined4 *)(param_1 + 0xf4) = 0;
  return;
}

