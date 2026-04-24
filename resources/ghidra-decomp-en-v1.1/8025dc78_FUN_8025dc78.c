// Function: FUN_8025dc78
// Entry: 8025dc78
// Size: 2192 bytes

void FUN_8025dc78(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(DAT_803dd210 + 0x4e4);
  if (iVar1 == 0x22) {
LAB_8025dcb0:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0;
  }
  else if (iVar1 < 0x22) {
    if (iVar1 < 0xb) {
      if (-1 < iVar1) goto LAB_8025dcb0;
    }
    else if (iVar1 < 0x1b) {
      DAT_cc008000._0_1_ = 0x61;
      DAT_cc008000 = 0x23000000;
    }
    else {
      DAT_cc008000._0_1_ = 0x61;
      DAT_cc008000 = 0x24000000;
    }
  }
  iVar1 = *(int *)(DAT_803dd210 + 0x4e8);
  if (iVar1 != 0x15) {
    if (0x14 < iVar1) goto LAB_8025dd8c;
    if (8 < iVar1) {
      if (iVar1 < 0x11) {
        *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f;
        DAT_cc008000._0_1_ = 8;
        DAT_cc008000._0_1_ = 0x20;
        DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
      }
      else {
        *(undefined2 *)(DAT_803ded2c + 6) = 0;
      }
      goto LAB_8025dd8c;
    }
    if (iVar1 < 0) goto LAB_8025dd8c;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = 0x67000000;
LAB_8025dd8c:
  *(undefined4 *)(DAT_803dd210 + 0x4e4) = param_1;
  switch(*(undefined4 *)(DAT_803dd210 + 0x4e4)) {
  case 0:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x273;
    break;
  case 1:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x14a;
    break;
  case 2:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x16b;
    break;
  case 3:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x84;
    break;
  case 4:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0xc6;
    break;
  case 5:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x210;
    break;
  case 6:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x252;
    break;
  case 7:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x231;
    break;
  case 8:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x1ad;
    break;
  case 9:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x1ce;
    break;
  case 10:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x153;
    break;
  case 0xb:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300ae7f;
    break;
  case 0xc:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x23008e7f;
    break;
  case 0xd:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x23009e7f;
    break;
  case 0xe:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x23001e7f;
    break;
  case 0xf:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300ac3f;
    break;
  case 0x10:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300ac7f;
    break;
  case 0x11:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300acbf;
    break;
  case 0x12:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300acff;
    break;
  case 0x13:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300ad3f;
    break;
  case 0x14:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300ad7f;
    break;
  case 0x15:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300adbf;
    break;
  case 0x16:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300adff;
    break;
  case 0x17:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300ae3f;
    break;
  case 0x18:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300a27f;
    break;
  case 0x19:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300a67f;
    break;
  case 0x1a:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2300aa7f;
    break;
  case 0x1b:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c0c6;
    break;
  case 0x1c:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c16b;
    break;
  case 0x1d:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c0e7;
    break;
  case 0x1e:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c108;
    break;
  case 0x1f:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c129;
    break;
  case 0x20:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c14a;
    break;
  case 0x21:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c1ad;
    break;
  case 0x22:
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000 = 0x1006;
    DAT_cc008000 = 0x21;
  }
  *(undefined4 *)(DAT_803dd210 + 0x4e8) = param_2;
  switch(*(undefined4 *)(DAT_803dd210 + 0x4e8)) {
  case 0:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000042;
    break;
  case 1:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000084;
    break;
  case 2:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000063;
    break;
  case 3:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000129;
    break;
  case 4:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x6700014b;
    break;
  case 5:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x6700018d;
    break;
  case 6:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x670001cf;
    break;
  case 7:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000211;
    break;
  case 8:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000252;
    break;
  case 9:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x20;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 10:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x30;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0xb:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x40;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0xc:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x50;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0xd:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x60;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0xe:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x70;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0xf:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x90;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0x10:
    *(uint *)(DAT_803dd210 + 0x4ec) = *(uint *)(DAT_803dd210 + 0x4ec) & 0xffffff0f | 0x80;
    DAT_cc008000._0_1_ = 8;
    DAT_cc008000._0_1_ = 0x20;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x4ec);
    break;
  case 0x11:
    *(undefined2 *)(DAT_803ded2c + 6) = 2;
    break;
  case 0x12:
    *(undefined2 *)(DAT_803ded2c + 6) = 3;
    break;
  case 0x13:
    *(undefined2 *)(DAT_803ded2c + 6) = 4;
    break;
  case 0x14:
    *(undefined2 *)(DAT_803ded2c + 6) = 5;
    break;
  case 0x15:
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x67000021;
  }
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

