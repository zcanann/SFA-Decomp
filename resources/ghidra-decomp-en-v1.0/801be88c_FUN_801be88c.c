// Function: FUN_801be88c
// Entry: 801be88c
// Size: 108 bytes

void FUN_801be88c(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,uVar1,1);
  if (DAT_803ddb90 != 0) {
    FUN_8001f384();
  }
  return;
}

