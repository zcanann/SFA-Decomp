// Function: FUN_802565ec
// Entry: 802565ec
// Size: 40 bytes

void FUN_802565ec(void)

{
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xfffffffe | 1;
  *(short *)(DAT_803de0ac + 2) = (short)*(undefined4 *)(DAT_803dc5a8 + 8);
  return;
}

