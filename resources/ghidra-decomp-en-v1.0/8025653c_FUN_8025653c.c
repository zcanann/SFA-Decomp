// Function: FUN_8025653c
// Entry: 8025653c
// Size: 100 bytes

void FUN_8025653c(void)

{
  FUN_8024377c();
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xfffffffd;
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xffffffdf;
  *(short *)(DAT_803de0ac + 2) = (short)*(undefined4 *)(DAT_803dc5a8 + 8);
  DAT_803de0d4 = 0;
  FUN_802437a4();
  return;
}

