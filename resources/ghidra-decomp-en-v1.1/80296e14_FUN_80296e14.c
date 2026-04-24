// Function: FUN_80296e14
// Entry: 80296e14
// Size: 24 bytes

uint FUN_80296e14(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(6 - *(short *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

