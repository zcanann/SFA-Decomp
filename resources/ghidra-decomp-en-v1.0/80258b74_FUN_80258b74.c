// Function: FUN_80258b74
// Entry: 80258b74
// Size: 68 bytes

void FUN_80258b74(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x204) =
       *(uint *)(DAT_803dc5a8 + 0x204) & 0xfff7ffff | (param_1 & 0xff) << 0x13;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0xfe080000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x204));
  return;
}

