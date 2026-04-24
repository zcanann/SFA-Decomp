// Function: FUN_80259288
// Entry: 80259288
// Size: 80 bytes

void FUN_80259288(int param_1)

{
  if (param_1 == 2) {
    param_1 = 1;
  }
  else if ((param_1 < 2) && (0 < param_1)) {
    param_1 = 2;
  }
  *(uint *)(DAT_803dd210 + 0x204) = *(uint *)(DAT_803dd210 + 0x204) & 0xffff3fff | param_1 << 0xe;
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 4;
  return;
}

