// Function: FUN_802592d8
// Entry: 802592d8
// Size: 68 bytes

void FUN_802592d8(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x204) =
       *(uint *)(DAT_803dd210 + 0x204) & 0xfff7ffff | (param_1 & 0xff) << 0x13;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = 0xfe080000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x204);
  return;
}

