// Function: FUN_80259638
// Entry: 80259638
// Size: 56 bytes

void FUN_80259638(void)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0x550003ff);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0x560003ff);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

