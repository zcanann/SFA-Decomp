// Function: FUN_8025ce6c
// Entry: 8025ce6c
// Size: 120 bytes

void FUN_8025ce6c(uint param_1,int param_2,uint param_3)

{
  *(uint *)(DAT_803dd210 + 0x1d8) = *(uint *)(DAT_803dd210 + 0x1d8) & 0xfffffffe | param_1 & 0xff;
  *(uint *)(DAT_803dd210 + 0x1d8) = *(uint *)(DAT_803dd210 + 0x1d8) & 0xfffffff1 | param_2 << 1;
  *(uint *)(DAT_803dd210 + 0x1d8) =
       *(uint *)(DAT_803dd210 + 0x1d8) & 0xffffffef | (param_3 & 0xff) << 4;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d8);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

