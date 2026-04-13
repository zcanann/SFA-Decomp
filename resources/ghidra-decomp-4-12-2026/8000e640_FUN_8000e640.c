// Function: FUN_8000e640
// Entry: 8000e640
// Size: 48 bytes

uint FUN_8000e640(void)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(1 - (char)(&DAT_80338e8d)[(uint)DAT_803dd50d * 0x60]);
  return uVar1 >> 5 & 0xff;
}

