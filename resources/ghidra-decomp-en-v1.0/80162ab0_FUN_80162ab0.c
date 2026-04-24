// Function: FUN_80162ab0
// Entry: 80162ab0
// Size: 92 bytes

void FUN_80162ab0(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,uVar1,0);
  return;
}

