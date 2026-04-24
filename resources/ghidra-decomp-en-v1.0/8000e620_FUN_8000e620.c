// Function: FUN_8000e620
// Entry: 8000e620
// Size: 48 bytes

uint FUN_8000e620(void)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(1 - (char)(&DAT_8033822d)[(uint)DAT_803dc88d * 0x60]);
  return uVar1 >> 5 & 0xff;
}

