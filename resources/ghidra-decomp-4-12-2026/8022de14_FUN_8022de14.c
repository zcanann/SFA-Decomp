// Function: FUN_8022de14
// Entry: 8022de14
// Size: 24 bytes

uint FUN_8022de14(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(4 - (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x478));
  return uVar1 >> 5;
}

