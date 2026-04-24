// Function: FUN_80282e7c
// Entry: 80282e7c
// Size: 108 bytes

int FUN_80282e7c(uint param_1)

{
  uint uVar1;
  
  uVar1 = param_1 & 0xfff;
  if (uVar1 < 0x400) {
    return (int)*(short *)(&DAT_80330028 + uVar1 * 2);
  }
  if (uVar1 < 0x800) {
    return (int)*(short *)(&DAT_80330028 + (0x3ff - (param_1 & 0x3ff)) * 2);
  }
  if (uVar1 < 0xc00) {
    return -(int)*(short *)(&DAT_80330028 + (param_1 & 0x3ff) * 2);
  }
  return -(int)*(short *)(&DAT_80330028 + (0x3ff - (param_1 & 0x3ff)) * 2);
}

