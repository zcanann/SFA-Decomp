// Function: FUN_80252ca8
// Entry: 80252ca8
// Size: 124 bytes

uint FUN_80252ca8(int param_1)

{
  uint uVar1;
  
  FUN_80243e74();
  uVar1 = DAT_cc006438;
  uVar1 = uVar1 >> (3 - param_1) * 8;
  if (((uVar1 & 8) != 0) && ((*(uint *)(&DAT_8032eeac + param_1 * 4) & 0x80) == 0)) {
    *(uint *)(&DAT_8032eeac + param_1 * 4) = 8;
  }
  FUN_80243e9c();
  return uVar1;
}

