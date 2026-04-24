// Function: FUN_8025b94c
// Entry: 8025b94c
// Size: 156 bytes

void FUN_8025b94c(int param_1,uint param_2,int param_3,int param_4,int param_5,int param_6,
                 int param_7,uint param_8,byte param_9,int param_10)

{
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = ((((((((param_2 & 0xfffffff3 | param_3 << 2) & 0xffffff8f | param_4 << 4) &
                       0xfffffe7f | param_10 << 7) & 0xffffe1ff | param_5 << 9) & 0xffff1fff |
                    param_6 << 0xd) & 0xfff8ffff | param_7 << 0x10) & 0xfff7ffff |
                  (uint)param_9 << 0x13) & 0xffefffff | (param_8 & 0xff) << 0x14) & 0xffffff |
                 (param_1 + 0x10) * 0x1000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

