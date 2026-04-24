// Function: FUN_80258bb8
// Entry: 80258bb8
// Size: 36 bytes

void FUN_80258bb8(void)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x204));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

