// Function: FUN_8025bd1c
// Entry: 8025bd1c
// Size: 312 bytes

void FUN_8025bd1c(int param_1,int param_2,uint param_3)

{
  if (param_1 == 2) {
    *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xffff8fff | param_3 << 0xc;
    *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xfffc7fff | param_2 << 0xf;
  }
  else if (param_1 < 2) {
    if (param_1 == 0) {
      *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xfffffff8 | param_3;
      *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xffffffc7 | param_2 << 3;
    }
    else if (-1 < param_1) {
      *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xfffffe3f | param_3 << 6;
      *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xfffff1ff | param_2 << 9;
    }
  }
  else if (param_1 < 4) {
    *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xffe3ffff | param_3 << 0x12
    ;
    *(uint *)(DAT_803dd210 + 0x120) = *(uint *)(DAT_803dd210 + 0x120) & 0xff1fffff | param_2 << 0x15
    ;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x120);
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 3;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

