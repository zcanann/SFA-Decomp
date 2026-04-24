// Function: FUN_80252db4
// Entry: 80252db4
// Size: 156 bytes

uint FUN_80252db4(uint param_1)

{
  uint uVar1;
  
  uVar1 = DAT_8032ee9c;
  if (param_1 != 0) {
    FUN_80243e74();
    uVar1 = DAT_8032ee9c & ~(param_1 >> 0x1c) | param_1 >> 0x18 & (param_1 >> 0x1c | 0x3fffff0);
    DAT_cc006438 = 0x80000000;
    DAT_cc006430 = uVar1;
    DAT_8032ee9c = uVar1;
    FUN_80243e9c();
  }
  return uVar1;
}

