// Function: FUN_8029641c
// Entry: 8029641c
// Size: 24 bytes

uint FUN_8029641c(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(0x13 - *(short *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

