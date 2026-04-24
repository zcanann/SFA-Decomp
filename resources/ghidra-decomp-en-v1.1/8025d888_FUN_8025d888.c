// Function: FUN_8025d888
// Entry: 8025d888
// Size: 60 bytes

void FUN_8025d888(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x80) = *(uint *)(DAT_803dd210 + 0x80) & 0xffffffc0 | param_1;
  FUN_8025dbf4(0);
  return;
}

