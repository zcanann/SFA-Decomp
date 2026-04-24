// Function: FUN_8025d514
// Entry: 8025d514
// Size: 2192 bytes

void FUN_8025d514(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(DAT_803dc5a8 + 0x4e4);
  if (iVar1 == 0x22) {
LAB_8025d54c:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0);
  }
  else if (iVar1 < 0x22) {
    if (iVar1 < 0xb) {
      if (-1 < iVar1) goto LAB_8025d54c;
    }
    else if (iVar1 < 0x1b) {
      write_volatile_1(DAT_cc008000,0x61);
      write_volatile_4(0xcc008000,0x23000000);
    }
    else {
      write_volatile_1(DAT_cc008000,0x61);
      write_volatile_4(0xcc008000,0x24000000);
    }
  }
  iVar1 = *(int *)(DAT_803dc5a8 + 0x4e8);
  if (iVar1 != 0x15) {
    if (0x14 < iVar1) goto LAB_8025d628;
    if (8 < iVar1) {
      if (iVar1 < 0x11) {
        *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f;
        write_volatile_1(DAT_cc008000,8);
        write_volatile_1(DAT_cc008000,0x20);
        write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
      }
      else {
        *(undefined2 *)(DAT_803de0ac + 6) = 0;
      }
      goto LAB_8025d628;
    }
    if (iVar1 < 0) goto LAB_8025d628;
  }
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0x67000000);
LAB_8025d628:
  *(undefined4 *)(DAT_803dc5a8 + 0x4e4) = param_1;
  switch(*(undefined4 *)(DAT_803dc5a8 + 0x4e4)) {
  case 0:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x273);
    break;
  case 1:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x14a);
    break;
  case 2:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x16b);
    break;
  case 3:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x84);
    break;
  case 4:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0xc6);
    break;
  case 5:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x210);
    break;
  case 6:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x252);
    break;
  case 7:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x231);
    break;
  case 8:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x1ad);
    break;
  case 9:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x1ce);
    break;
  case 10:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x153);
    break;
  case 0xb:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300ae7f);
    break;
  case 0xc:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x23008e7f);
    break;
  case 0xd:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x23009e7f);
    break;
  case 0xe:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x23001e7f);
    break;
  case 0xf:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300ac3f);
    break;
  case 0x10:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300ac7f);
    break;
  case 0x11:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300acbf);
    break;
  case 0x12:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300acff);
    break;
  case 0x13:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300ad3f);
    break;
  case 0x14:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300ad7f);
    break;
  case 0x15:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300adbf);
    break;
  case 0x16:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300adff);
    break;
  case 0x17:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300ae3f);
    break;
  case 0x18:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300a27f);
    break;
  case 0x19:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300a67f);
    break;
  case 0x1a:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2300aa7f);
    break;
  case 0x1b:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c0c6);
    break;
  case 0x1c:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c16b);
    break;
  case 0x1d:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c0e7);
    break;
  case 0x1e:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c108);
    break;
  case 0x1f:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c129);
    break;
  case 0x20:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c14a);
    break;
  case 0x21:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c1ad);
    break;
  case 0x22:
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x21);
  }
  *(undefined4 *)(DAT_803dc5a8 + 0x4e8) = param_2;
  switch(*(undefined4 *)(DAT_803dc5a8 + 0x4e8)) {
  case 0:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000042);
    break;
  case 1:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000084);
    break;
  case 2:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000063);
    break;
  case 3:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000129);
    break;
  case 4:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x6700014b);
    break;
  case 5:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x6700018d);
    break;
  case 6:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x670001cf);
    break;
  case 7:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000211);
    break;
  case 8:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000252);
    break;
  case 9:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x20;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 10:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x30;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0xb:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x40;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0xc:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x50;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0xd:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x60;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0xe:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x70;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0xf:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x90;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0x10:
    *(uint *)(DAT_803dc5a8 + 0x4ec) = *(uint *)(DAT_803dc5a8 + 0x4ec) & 0xffffff0f | 0x80;
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x20);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x4ec));
    break;
  case 0x11:
    *(undefined2 *)(DAT_803de0ac + 6) = 2;
    break;
  case 0x12:
    *(undefined2 *)(DAT_803de0ac + 6) = 3;
    break;
  case 0x13:
    *(undefined2 *)(DAT_803de0ac + 6) = 4;
    break;
  case 0x14:
    *(undefined2 *)(DAT_803de0ac + 6) = 5;
    break;
  case 0x15:
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x67000021);
  }
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

