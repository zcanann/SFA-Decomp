// Function: FUN_8025c780
// Entry: 8025c780
// Size: 64 bytes

void FUN_8025c780(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x1dc) =
       *(uint *)(DAT_803dc5a8 + 0x1dc) & 0xffffffbf | (param_1 & 0xff) << 6;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1dc));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

