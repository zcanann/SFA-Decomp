// Function: FUN_80295cbc
// Entry: 80295cbc
// Size: 24 bytes

uint FUN_80295cbc(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(0x13 - *(short *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

