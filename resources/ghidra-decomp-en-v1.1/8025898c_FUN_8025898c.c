// Function: FUN_8025898c
// Entry: 8025898c
// Size: 120 bytes

void FUN_8025898c(int param_1,int param_2)

{
  uint uVar1;
  
  if (param_1 == 1) {
    DAT_803dd210[2] = (short)param_2;
    uVar1 = countLeadingZeros((uint)(ushort)DAT_803dd210[2]);
    *DAT_803dd210 = (short)(uVar1 >> 5);
    DAT_803dd210[1] = 1;
    if (DAT_803dd210[2] == 0) {
      return;
    }
    *(uint *)(DAT_803dd210 + 0x27a) = *(uint *)(DAT_803dd210 + 0x27a) | 8;
    return;
  }
  if (param_1 < 1) {
    return;
  }
  if (2 < param_1) {
    return;
  }
  *(char *)((int)DAT_803dd210 + 0x4f1) = '\x01' - (param_2 == 0);
  return;
}

