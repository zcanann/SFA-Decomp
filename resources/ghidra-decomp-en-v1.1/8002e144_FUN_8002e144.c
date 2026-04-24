// Function: FUN_8002e144
// Entry: 8002e144
// Size: 48 bytes

uint FUN_8002e144(void)

{
  uint uVar1;
  
  uVar1 = FUN_800431a4();
  uVar1 = countLeadingZeros(uVar1 & 0x100000);
  return uVar1 >> 5;
}

