// Function: FUN_8025b3e4
// Entry: 8025b3e4
// Size: 468 bytes

void FUN_8025b3e4(int param_1,uint param_2,int param_3)

{
  if (param_1 == 2) {
    *(uint *)(DAT_803dc5a8 + 300) = *(uint *)(DAT_803dc5a8 + 300) & 0xfffffff0 | param_2;
    *(uint *)(DAT_803dc5a8 + 300) = *(uint *)(DAT_803dc5a8 + 300) & 0xffffff0f | param_3 << 4;
    *(uint *)(DAT_803dc5a8 + 300) = *(uint *)(DAT_803dc5a8 + 300) & 0xffffff | 0x26000000;
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 300));
  }
  else if (param_1 < 2) {
    if (param_1 == 0) {
      *(uint *)(DAT_803dc5a8 + 0x128) = *(uint *)(DAT_803dc5a8 + 0x128) & 0xfffffff0 | param_2;
      *(uint *)(DAT_803dc5a8 + 0x128) = *(uint *)(DAT_803dc5a8 + 0x128) & 0xffffff0f | param_3 << 4;
      *(uint *)(DAT_803dc5a8 + 0x128) = *(uint *)(DAT_803dc5a8 + 0x128) & 0xffffff | 0x25000000;
      write_volatile_1(DAT_cc008000,0x61);
      write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x128));
    }
    else if (-1 < param_1) {
      *(uint *)(DAT_803dc5a8 + 0x128) = *(uint *)(DAT_803dc5a8 + 0x128) & 0xfffff0ff | param_2 << 8;
      *(uint *)(DAT_803dc5a8 + 0x128) =
           *(uint *)(DAT_803dc5a8 + 0x128) & 0xffff0fff | param_3 << 0xc;
      *(uint *)(DAT_803dc5a8 + 0x128) = *(uint *)(DAT_803dc5a8 + 0x128) & 0xffffff | 0x25000000;
      write_volatile_1(DAT_cc008000,0x61);
      write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x128));
    }
  }
  else if (param_1 < 4) {
    *(uint *)(DAT_803dc5a8 + 300) = *(uint *)(DAT_803dc5a8 + 300) & 0xfffff0ff | param_2 << 8;
    *(uint *)(DAT_803dc5a8 + 300) = *(uint *)(DAT_803dc5a8 + 300) & 0xffff0fff | param_3 << 0xc;
    *(uint *)(DAT_803dc5a8 + 300) = *(uint *)(DAT_803dc5a8 + 300) & 0xffffff | 0x26000000;
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 300));
  }
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

