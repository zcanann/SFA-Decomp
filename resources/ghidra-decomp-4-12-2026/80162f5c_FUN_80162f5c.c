// Function: FUN_80162f5c
// Entry: 80162f5c
// Size: 92 bytes

void FUN_80162f5c(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,0);
  return;
}

