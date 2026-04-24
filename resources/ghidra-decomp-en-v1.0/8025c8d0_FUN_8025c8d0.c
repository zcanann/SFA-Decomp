// Function: FUN_8025c8d0
// Entry: 8025c8d0
// Size: 64 bytes

void FUN_8025c8d0(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x1d0) =
       *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffffffb | (param_1 & 0xff) << 2;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d0));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

