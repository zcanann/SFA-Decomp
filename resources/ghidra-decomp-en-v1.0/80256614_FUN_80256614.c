// Function: FUN_80256614
// Entry: 80256614
// Size: 36 bytes

void FUN_80256614(void)

{
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xfffffffe;
  *(short *)(DAT_803de0ac + 2) = (short)*(undefined4 *)(DAT_803dc5a8 + 8);
  return;
}

