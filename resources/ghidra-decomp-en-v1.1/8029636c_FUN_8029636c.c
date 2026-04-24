// Function: FUN_8029636c
// Entry: 8029636c
// Size: 24 bytes

uint FUN_8029636c(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(*(byte *)(*(int *)(param_1 + 0xb8) + 0x3f0) >> 1 & 1);
  return uVar1 >> 5;
}

