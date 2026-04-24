// Function: FUN_8025db88
// Entry: 8025db88
// Size: 68 bytes

void FUN_8025db88(int param_1,int param_2)

{
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (param_1 + 0x156U >> 1 & 0x7ff003ff | (param_2 + 0x156U >> 1) << 10) & 0xffffff |
                 0x59000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

