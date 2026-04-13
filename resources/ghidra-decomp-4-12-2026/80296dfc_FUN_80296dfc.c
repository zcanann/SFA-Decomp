// Function: FUN_80296dfc
// Entry: 80296dfc
// Size: 24 bytes

uint FUN_80296dfc(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(7 - *(short *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

