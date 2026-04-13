// Function: FUN_8025c2a8
// Entry: 8025c2a8
// Size: 192 bytes

void FUN_8025c2a8(int param_1,uint param_2,int param_3,int param_4,uint param_5,int param_6)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dd210 + param_1 * 4 + 0x130);
  *puVar1 = (param_2 & 1) << 0x12 | *puVar1 & 0xfffbffff;
  if ((int)param_2 < 2) {
    *puVar1 = *puVar1 & 0xffcfffff | param_4 << 0x14;
    *puVar1 = *puVar1 & 0xfffcffff | param_3 << 0x10;
  }
  else {
    *puVar1 = (param_2 & 6) << 0x13 | *puVar1 & 0xffcfffff;
    *puVar1 = *puVar1 & 0xfffcffff | 0x30000;
  }
  *puVar1 = *puVar1 & 0xfff7ffff | (param_5 & 0xff) << 0x13;
  *puVar1 = *puVar1 & 0xff3fffff | param_6 << 0x16;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

