// Function: FUN_8029622c
// Entry: 8029622c
// Size: 20 bytes

uint FUN_8029622c(int param_1)

{
  uint uVar1;
  
  uVar1 = countLeadingZeros(*(ushort *)(param_1 + 0xb0) & 0x1000);
  return uVar1 >> 5;
}

