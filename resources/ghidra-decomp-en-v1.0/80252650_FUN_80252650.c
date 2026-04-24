// Function: FUN_80252650
// Entry: 80252650
// Size: 156 bytes

uint FUN_80252650(uint param_1)

{
  uint uVar1;
  
  uVar1 = DAT_8032e244;
  if (param_1 != 0) {
    FUN_8024377c();
    uVar1 = DAT_8032e244 & ~(param_1 >> 0x1c) | param_1 >> 0x18 & (param_1 >> 0x1c | 0x3fffff0);
    write_volatile_4(DAT_cc006438,0x80000000);
    write_volatile_4(DAT_cc006430,uVar1);
    DAT_8032e244 = uVar1;
    FUN_802437a4();
  }
  return uVar1;
}

