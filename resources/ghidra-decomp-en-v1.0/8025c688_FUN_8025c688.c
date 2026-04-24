// Function: FUN_8025c688
// Entry: 8025c688
// Size: 64 bytes

void FUN_8025c688(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x1d0) =
       *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffffff7 | (param_1 & 0xff) << 3;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d0));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

