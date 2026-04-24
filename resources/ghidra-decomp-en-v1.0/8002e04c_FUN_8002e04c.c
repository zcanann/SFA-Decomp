// Function: FUN_8002e04c
// Entry: 8002e04c
// Size: 48 bytes

uint FUN_8002e04c(void)

{
  uint uVar1;
  
  uVar1 = FUN_800430ac(0);
  uVar1 = countLeadingZeros(uVar1 & 0x100000);
  return uVar1 >> 5;
}

