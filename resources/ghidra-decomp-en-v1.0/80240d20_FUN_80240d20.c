// Function: FUN_80240d20
// Entry: 80240d20
// Size: 20 bytes

uint FUN_80240d20(void)

{
  uint uVar1;
  
  uVar1 = read_volatile_4(DAT_cc006024);
  return uVar1 & 0xff;
}

