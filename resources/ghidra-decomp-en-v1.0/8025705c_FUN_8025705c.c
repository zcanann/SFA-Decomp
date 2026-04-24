// Function: FUN_8025705c
// Entry: 8025705c
// Size: 84 bytes

void FUN_8025705c(void)

{
  write_volatile_1(DAT_cc008000,8);
  write_volatile_1(DAT_cc008000,0x50);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x14));
  write_volatile_1(DAT_cc008000,8);
  write_volatile_1(DAT_cc008000,0x60);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x18));
  FUN_80256820();
  return;
}

