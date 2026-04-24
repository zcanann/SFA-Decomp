// Function: FUN_80259338
// Entry: 80259338
// Size: 368 bytes

void FUN_80259338(uint param_1,byte param_2)

{
  bool bVar1;
  
  if (param_2 != 0) {
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(uint *)(DAT_803dc5a8 + 0x1d8) & 0xfffffff0 | 0xf);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffffffc);
  }
  bVar1 = false;
  if (param_2 == 0) {
    if ((*(uint *)(DAT_803dc5a8 + 0x1dc) & 7) != 3) goto LAB_802593c4;
  }
  if ((*(uint *)(DAT_803dc5a8 + 0x1dc) >> 6 & 1) == 1) {
    write_volatile_1(DAT_cc008000,0x61);
    bVar1 = true;
    write_volatile_4(0xcc008000,*(uint *)(DAT_803dc5a8 + 0x1dc) & 0xffffffbf);
  }
LAB_802593c4:
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1e0));
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1e4));
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1e8));
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1 >> 5 & 0xffffff | 0x4b000000);
  *(uint *)(DAT_803dc5a8 + 0x1ec) =
       *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xfffff7ff | (uint)param_2 << 0xb;
  *(uint *)(DAT_803dc5a8 + 0x1ec) = *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xffffbfff | 0x4000;
  *(uint *)(DAT_803dc5a8 + 0x1ec) = *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xffffff | 0x52000000;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1ec));
  if (param_2 != 0) {
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d8));
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d0));
  }
  if (bVar1) {
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1dc));
  }
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

