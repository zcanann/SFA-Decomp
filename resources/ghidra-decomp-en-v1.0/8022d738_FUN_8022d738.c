// Function: FUN_8022d738
// Entry: 8022d738
// Size: 24 bytes

uint FUN_8022d738(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(1 - (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x478));
  return uVar1 >> 5;
}

