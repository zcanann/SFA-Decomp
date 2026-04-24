// Function: FUN_8025c2a0
// Entry: 8025c2a0
// Size: 52 bytes

void FUN_8025c2a0(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x204) =
       *(uint *)(DAT_803dc5a8 + 0x204) & 0xffffc3ff | ((param_1 & 0xff) - 1) * 0x400;
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 4;
  return;
}

