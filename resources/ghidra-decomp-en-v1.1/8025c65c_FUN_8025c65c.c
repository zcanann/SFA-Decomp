// Function: FUN_8025c65c
// Entry: 8025c65c
// Size: 88 bytes

void FUN_8025c65c(int param_1,uint param_2,int param_3)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dd210 + param_1 * 4 + 0x170);
  *puVar1 = *puVar1 & 0xfffffffc | param_2;
  *puVar1 = *puVar1 & 0xfffffff3 | param_3 << 2;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

