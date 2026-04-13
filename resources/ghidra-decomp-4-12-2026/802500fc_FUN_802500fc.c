// Function: FUN_802500fc
// Entry: 802500fc
// Size: 20 bytes

uint FUN_802500fc(void)

{
  uint uVar1;
  
  uVar1 = DAT_cc006c00;
  return uVar1 >> 6 & 1 ^ 1;
}

