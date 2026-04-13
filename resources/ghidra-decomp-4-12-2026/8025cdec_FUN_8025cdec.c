// Function: FUN_8025cdec
// Entry: 8025cdec
// Size: 64 bytes

void FUN_8025cdec(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x1d0) =
       *(uint *)(DAT_803dd210 + 0x1d0) & 0xfffffff7 | (param_1 & 0xff) << 3;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d0);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

