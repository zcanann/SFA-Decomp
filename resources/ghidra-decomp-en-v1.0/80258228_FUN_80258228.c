// Function: FUN_80258228
// Entry: 80258228
// Size: 120 bytes

void FUN_80258228(int param_1,int param_2)

{
  uint uVar1;
  
  if (param_1 == 1) {
    DAT_803dc5a8[2] = (short)param_2;
    uVar1 = countLeadingZeros((uint)(ushort)DAT_803dc5a8[2]);
    *DAT_803dc5a8 = (short)(uVar1 >> 5);
    DAT_803dc5a8[1] = 1;
    if (DAT_803dc5a8[2] == 0) {
      return;
    }
    *(uint *)(DAT_803dc5a8 + 0x27a) = *(uint *)(DAT_803dc5a8 + 0x27a) | 8;
    return;
  }
  if (param_1 < 1) {
    return;
  }
  if (2 < param_1) {
    return;
  }
  *(char *)((int)DAT_803dc5a8 + 0x4f1) = '\x01' - (param_2 == 0);
  return;
}

