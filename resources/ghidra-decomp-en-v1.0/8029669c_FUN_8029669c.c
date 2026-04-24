// Function: FUN_8029669c
// Entry: 8029669c
// Size: 24 bytes

uint FUN_8029669c(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(7 - *(short *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

