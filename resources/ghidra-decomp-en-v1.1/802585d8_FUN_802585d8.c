// Function: FUN_802585d8
// Entry: 802585d8
// Size: 140 bytes

void FUN_802585d8(int param_1,uint param_2,uint param_3)

{
  byte bVar1;
  int iVar2;
  
  if (param_1 == 0x19) {
    param_1 = 10;
  }
  bVar1 = (char)param_1 - 9;
  DAT_cc008000._0_1_ = 8;
  DAT_cc008000._0_1_ = bVar1 | 0xa0;
  iVar2 = param_1 + -0x15;
  DAT_cc008000 = param_2 & 0x3fffffff;
  if ((-1 < iVar2) && (iVar2 < 4)) {
    *(uint *)(DAT_803dd210 + iVar2 * 4 + 0x88) = param_2 & 0x3fffffff;
  }
  DAT_cc008000._0_1_ = 8;
  DAT_cc008000._0_1_ = bVar1 | 0xb0;
  iVar2 = param_1 + -0x15;
  DAT_cc008000 = param_3 & 0xff;
  if (iVar2 < 0) {
    return;
  }
  if (3 < iVar2) {
    return;
  }
  *(uint *)(DAT_803dd210 + iVar2 * 4 + 0x98) = param_3 & 0xff;
  return;
}

