// Function: FUN_80252e50
// Entry: 80252e50
// Size: 108 bytes

uint FUN_80252e50(uint param_1)

{
  uint uVar1;
  
  uVar1 = DAT_8032ee9c;
  if (param_1 != 0) {
    FUN_80243e74();
    uVar1 = DAT_8032ee9c & ~(param_1 >> 0x18 & 0xf0);
    DAT_cc006430 = uVar1;
    DAT_8032ee9c = uVar1;
    FUN_80243e9c();
  }
  return uVar1;
}

