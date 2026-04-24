// Function: FUN_80168ba0
// Entry: 80168ba0
// Size: 92 bytes

void FUN_80168ba0(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,uVar1,0x20);
  return;
}

