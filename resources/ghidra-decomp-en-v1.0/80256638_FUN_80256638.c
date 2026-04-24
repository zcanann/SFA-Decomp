// Function: FUN_80256638
// Entry: 80256638
// Size: 68 bytes

void FUN_80256638(char param_1)

{
  *(uint *)(DAT_803dc5a8 + 8) =
       *(uint *)(DAT_803dc5a8 + 8) & 0xffffffef | (uint)(param_1 != '\0') << 4;
  *(short *)(DAT_803de0ac + 2) = (short)*(undefined4 *)(DAT_803dc5a8 + 8);
  return;
}

