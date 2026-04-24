// Function: FUN_80258d5c
// Entry: 80258d5c
// Size: 68 bytes

void FUN_80258d5c(uint param_1)

{
  *(undefined4 *)(DAT_803dc5a8 + 0x1e8) = 0;
  *(uint *)(DAT_803dc5a8 + 0x1e8) =
       *(uint *)(DAT_803dc5a8 + 0x1e8) & 0xfffffc00 | (int)((param_1 & 0x7fff) << 1) >> 5;
  *(uint *)(DAT_803dc5a8 + 0x1e8) = *(uint *)(DAT_803dc5a8 + 0x1e8) & 0xffffff | 0x4d000000;
  return;
}

