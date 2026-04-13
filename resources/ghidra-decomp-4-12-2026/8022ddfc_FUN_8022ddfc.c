// Function: FUN_8022ddfc
// Entry: 8022ddfc
// Size: 24 bytes

uint FUN_8022ddfc(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(1 - (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x478));
  return uVar1 >> 5;
}

