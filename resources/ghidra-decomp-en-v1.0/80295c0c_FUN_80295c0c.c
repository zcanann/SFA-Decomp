// Function: FUN_80295c0c
// Entry: 80295c0c
// Size: 24 bytes

uint FUN_80295c0c(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(*(byte *)(*(int *)(param_1 + 0xb8) + 0x3f0) >> 1 & 1);
  return uVar1 >> 5;
}

