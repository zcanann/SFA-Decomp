// Function: FUN_8029698c
// Entry: 8029698c
// Size: 20 bytes

uint FUN_8029698c(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(*(ushort *)(param_1 + 0xb0) & 0x1000);
  return uVar1 >> 5;
}

