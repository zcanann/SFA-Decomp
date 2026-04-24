// Function: FUN_802526ec
// Entry: 802526ec
// Size: 108 bytes

uint FUN_802526ec(uint param_1)

{
  uint uVar1;
  
  uVar1 = DAT_8032e244;
  if (param_1 != 0) {
    FUN_8024377c();
    uVar1 = DAT_8032e244 & ~(param_1 >> 0x18 & 0xf0);
    write_volatile_4(DAT_cc006430,uVar1);
    DAT_8032e244 = uVar1;
    FUN_802437a4();
  }
  return uVar1;
}

