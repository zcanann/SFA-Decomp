// Function: FUN_8025c6b4
// Entry: 8025c6b4
// Size: 160 bytes

void FUN_8025c6b4(int param_1,uint param_2,int param_3,uint param_4,int param_5)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = (uint *)(DAT_803dd210 + param_1 * 8 + 0x1b0);
  *puVar2 = *puVar2 & 0xfffffffc | param_2;
  *puVar2 = *puVar2 & 0xfffffff3 | param_3 << 2;
  DAT_cc008000._0_1_ = 0x61;
  puVar1 = (uint *)(DAT_803dd210 + (param_1 * 2 + 1) * 4 + 0x1b0);
  DAT_cc008000 = *puVar2;
  *puVar1 = *puVar1 & 0xfffffffc | param_4;
  *puVar1 = *puVar1 & 0xfffffff3 | param_5 << 2;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

