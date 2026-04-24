// Function: FUN_8025bb48
// Entry: 8025bb48
// Size: 468 bytes

void FUN_8025bb48(int param_1,uint param_2,int param_3)

{
  if (param_1 == 2) {
    *(uint *)(DAT_803dd210 + 300) = *(uint *)(DAT_803dd210 + 300) & 0xfffffff0 | param_2;
    *(uint *)(DAT_803dd210 + 300) = *(uint *)(DAT_803dd210 + 300) & 0xffffff0f | param_3 << 4;
    *(uint *)(DAT_803dd210 + 300) = *(uint *)(DAT_803dd210 + 300) & 0xffffff | 0x26000000;
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 300);
  }
  else if (param_1 < 2) {
    if (param_1 == 0) {
      *(uint *)(DAT_803dd210 + 0x128) = *(uint *)(DAT_803dd210 + 0x128) & 0xfffffff0 | param_2;
      *(uint *)(DAT_803dd210 + 0x128) = *(uint *)(DAT_803dd210 + 0x128) & 0xffffff0f | param_3 << 4;
      *(uint *)(DAT_803dd210 + 0x128) = *(uint *)(DAT_803dd210 + 0x128) & 0xffffff | 0x25000000;
      DAT_cc008000._0_1_ = 0x61;
      DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x128);
    }
    else if (-1 < param_1) {
      *(uint *)(DAT_803dd210 + 0x128) = *(uint *)(DAT_803dd210 + 0x128) & 0xfffff0ff | param_2 << 8;
      *(uint *)(DAT_803dd210 + 0x128) =
           *(uint *)(DAT_803dd210 + 0x128) & 0xffff0fff | param_3 << 0xc;
      *(uint *)(DAT_803dd210 + 0x128) = *(uint *)(DAT_803dd210 + 0x128) & 0xffffff | 0x25000000;
      DAT_cc008000._0_1_ = 0x61;
      DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x128);
    }
  }
  else if (param_1 < 4) {
    *(uint *)(DAT_803dd210 + 300) = *(uint *)(DAT_803dd210 + 300) & 0xfffff0ff | param_2 << 8;
    *(uint *)(DAT_803dd210 + 300) = *(uint *)(DAT_803dd210 + 300) & 0xffff0fff | param_3 << 0xc;
    *(uint *)(DAT_803dd210 + 300) = *(uint *)(DAT_803dd210 + 300) & 0xffffff | 0x26000000;
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 300);
  }
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

