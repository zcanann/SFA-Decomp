// Function: FUN_80258944
// Entry: 80258944
// Size: 72 bytes

void FUN_80258944(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x204) = *(uint *)(DAT_803dd210 + 0x204) & 0xfffffff0 | param_1 & 0xff;
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = 0x103f;
  DAT_cc008000 = param_1 & 0xff;
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 4;
  return;
}

