// Function: FUN_80244b20
// Entry: 80244b20
// Size: 48 bytes

uint FUN_80244b20(void)

{
  uint uVar1;
  
  if (DAT_800030e2 == '\0') {
    uVar1 = read_volatile_4(DAT_cc003024);
    uVar1 = uVar1 >> 3;
  }
  else {
    uVar1 = 0x80000000;
  }
  return uVar1;
}

