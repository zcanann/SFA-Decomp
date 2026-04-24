// Function: FUN_802846e4
// Entry: 802846e4
// Size: 32 bytes

uint FUN_802846e4(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(1 - (uint)*(byte *)(DAT_803defc4 + param_1 * 0xf4 + 0xec));
  return uVar1 >> 5;
}

