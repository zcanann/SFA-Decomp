// Function: FUN_8025c910
// Entry: 8025c910
// Size: 84 bytes

void FUN_8025c910(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dc5a8 + 0x1d4) = param_2 & 0xff | *(uint *)(DAT_803dc5a8 + 0x1d4) & 0xffffff00;
  *(uint *)(DAT_803dc5a8 + 0x1d4) =
       *(uint *)(DAT_803dc5a8 + 0x1d4) & 0xfffffeff | (param_1 & 0xff) << 8;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d4));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

