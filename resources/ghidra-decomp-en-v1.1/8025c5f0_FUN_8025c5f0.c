// Function: FUN_8025c5f0
// Entry: 8025c5f0
// Size: 108 bytes

void FUN_8025c5f0(uint param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dd210 + ((int)param_1 >> 1) * 4 + 0x1b0);
  if ((param_1 & 1) == 0) {
    *puVar1 = *puVar1 & 0xffffc1ff | param_2 << 9;
  }
  else {
    *puVar1 = *puVar1 & 0xff07ffff | param_2 << 0x13;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *puVar1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

