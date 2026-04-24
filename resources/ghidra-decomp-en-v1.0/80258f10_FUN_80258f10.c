// Function: FUN_80258f10
// Entry: 80258f10
// Size: 44 bytes

void FUN_80258f10(int param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x1ec) = *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xffffcfff | param_1 << 0xc;
  *(uint *)(DAT_803dc5a8 + 0x1fc) = *(uint *)(DAT_803dc5a8 + 0x1fc) & 0xffffcfff;
  return;
}

