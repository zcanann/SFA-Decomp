// Function: FUN_8025c224
// Entry: 8025c224
// Size: 132 bytes

void FUN_8025c224(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dd210 + param_1 * 4 + 0x170);
  *puVar1 = *puVar1 & 0xffff1fff | param_2 << 0xd;
  *puVar1 = *puVar1 & 0xffffe3ff | param_3 << 10;
  *puVar1 = *puVar1 & 0xfffffc7f | param_4 << 7;
  *puVar1 = *puVar1 & 0xffffff8f | param_5 << 4;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

