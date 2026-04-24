// Function: FUN_8025931c
// Entry: 8025931c
// Size: 28 bytes

void FUN_8025931c(int param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x1ec) = *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xfffffe7f | param_1 << 7;
  return;
}

