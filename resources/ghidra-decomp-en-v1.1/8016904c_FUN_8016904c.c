// Function: FUN_8016904c
// Entry: 8016904c
// Size: 92 bytes

void FUN_8016904c(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,0x20);
  return;
}

