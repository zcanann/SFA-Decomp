// Function: FUN_802966b4
// Entry: 802966b4
// Size: 24 bytes

uint FUN_802966b4(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(6 - *(short *)(*(int *)(param_1 + 0xb8) + 0x274));
  return uVar1 >> 5;
}

