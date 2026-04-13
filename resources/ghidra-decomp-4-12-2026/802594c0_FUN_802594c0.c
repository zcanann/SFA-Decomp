// Function: FUN_802594c0
// Entry: 802594c0
// Size: 68 bytes

void FUN_802594c0(uint param_1)

{
  *(undefined4 *)(DAT_803dd210 + 0x1e8) = 0;
  *(uint *)(DAT_803dd210 + 0x1e8) =
       *(uint *)(DAT_803dd210 + 0x1e8) & 0xfffffc00 | (int)((param_1 & 0x7fff) << 1) >> 5;
  *(uint *)(DAT_803dd210 + 0x1e8) = *(uint *)(DAT_803dd210 + 0x1e8) & 0xffffff | 0x4d000000;
  return;
}

