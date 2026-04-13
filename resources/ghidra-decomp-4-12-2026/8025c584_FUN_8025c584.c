// Function: FUN_8025c584
// Entry: 8025c584
// Size: 108 bytes

void FUN_8025c584(uint param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dd210 + ((int)param_1 >> 1) * 4 + 0x1b0);
  if ((param_1 & 1) == 0) {
    *puVar1 = *puVar1 & 0xfffffe0f | param_2 << 4;
  }
  else {
    *puVar1 = *puVar1 & 0xfff83fff | param_2 << 0xe;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

