// Function: FUN_80252544
// Entry: 80252544
// Size: 124 bytes

uint FUN_80252544(int param_1)

{
  uint uVar1;
  
  FUN_8024377c();
  uVar1 = read_volatile_4(DAT_cc006438);
  uVar1 = uVar1 >> (3 - param_1) * 8;
  if (((uVar1 & 8) != 0) && ((*(uint *)(&DAT_8032e254 + param_1 * 4) & 0x80) == 0)) {
    *(uint *)(&DAT_8032e254 + param_1 * 4) = 8;
  }
  FUN_802437a4();
  return uVar1;
}

