// Function: FUN_80259674
// Entry: 80259674
// Size: 44 bytes

void FUN_80259674(int param_1)

{
  *(uint *)(DAT_803dd210 + 0x1ec) = *(uint *)(DAT_803dd210 + 0x1ec) & 0xffffcfff | param_1 << 0xc;
  *(uint *)(DAT_803dd210 + 0x1fc) = *(uint *)(DAT_803dd210 + 0x1fc) & 0xffffcfff;
  return;
}

