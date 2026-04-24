// Function: FUN_8025c1a4
// Entry: 8025c1a4
// Size: 128 bytes

void FUN_8025c1a4(int param_1,int param_2,int param_3,int param_4,uint param_5)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dd210 + param_1 * 4 + 0x130);
  *puVar1 = *puVar1 & 0xffff0fff | param_2 << 0xc;
  *puVar1 = *puVar1 & 0xfffff0ff | param_3 << 8;
  *puVar1 = *puVar1 & 0xffffff0f | param_4 << 4;
  *puVar1 = *puVar1 & 0xfffffff0 | param_5;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

