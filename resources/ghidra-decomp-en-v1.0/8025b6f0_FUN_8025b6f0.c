// Function: FUN_8025b6f0
// Entry: 8025b6f0
// Size: 44 bytes

void FUN_8025b6f0(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x204) =
       *(uint *)(DAT_803dc5a8 + 0x204) & 0xfff8ffff | (param_1 & 0xff) << 0x10;
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 6;
  return;
}

