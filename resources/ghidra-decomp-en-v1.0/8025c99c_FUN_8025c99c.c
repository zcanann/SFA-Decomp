// Function: FUN_8025c99c
// Entry: 8025c99c
// Size: 128 bytes

void FUN_8025c99c(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dc5a8 + 0x7c) =
       *(uint *)(DAT_803dc5a8 + 0x7c) & 0xffbfffff | (param_2 & 0xff) << 0x16;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x7c));
  FUN_8025b878();
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1 & 0xff | 0x68000000);
  FUN_8025b878();
  return;
}

