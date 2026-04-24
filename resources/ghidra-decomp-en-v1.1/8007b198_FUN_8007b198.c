// Function: FUN_8007b198
// Entry: 8007b198
// Size: 3440 bytes

void FUN_8007b198(double param_1,double param_2,double param_3,char param_4,char param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 local_128;
  undefined4 local_124;
  float fStack_120;
  float fStack_11c;
  float fStack_118;
  float local_114;
  int local_110;
  undefined4 local_10c;
  float afStack_108 [3];
  float local_fc;
  float afStack_d8 [3];
  float local_cc;
  float afStack_a8 [7];
  float local_8c;
  float afStack_78 [7];
  float local_5c;
  float afStack_48 [15];
  
  FUN_8000ef68((double)(float)(param_1 - (double)FLOAT_803dda58),param_2,
               (double)(float)(param_3 - (double)FLOAT_803dda5c),&fStack_118,&fStack_11c,&local_114,
               &fStack_120);
  local_114 = local_114 + FLOAT_803dfb64;
  iVar1 = FUN_80286718((double)(FLOAT_803dfb88 * local_114));
  local_10c = CONCAT31(local_10c._0_3_,(char)((uint)iVar1 >> 0x10));
  FUN_8006c86c(0);
  FUN_8006c754(&local_110);
  FUN_8004c460(local_110,1);
  FUN_8025c6b4(1,0,0,0,1);
  FUN_802475b8(afStack_78);
  local_5c = FLOAT_803dfbf8;
  FUN_8025d8c4(afStack_78,0x24,1);
  FUN_80258674(0,1,4,0x24,0,0x7d);
  FUN_802475b8(afStack_a8);
  local_8c = FLOAT_803dfbf8;
  FUN_8025d8c4(afStack_a8,0x2a,1);
  FUN_80258674(2,1,4,0x2a,0,0x7d);
  FUN_802475b8(afStack_d8);
  local_cc = FLOAT_803dfbfc;
  FUN_8025d8c4(afStack_d8,0x2d,1);
  FUN_80258674(3,1,4,0x2d,0,0x7d);
  FUN_802475b8(afStack_108);
  local_fc = FLOAT_803dfc00;
  FUN_8025d8c4(afStack_108,0x30,1);
  FUN_80258674(4,1,4,0x30,0,0x7d);
  FUN_80258674(5,1,4,0x3c,0,0x7d);
  FUN_802475b8(afStack_48);
  FUN_8025d8c4(afStack_48,0x27,1);
  FUN_80258674(1,1,4,0x27,0,0x7d);
  local_124 = local_10c;
  FUN_8025c510(0,(byte *)&local_124);
  FUN_8025c5f0(0,0x1c);
  local_128 = DAT_803dc2fc;
  FUN_8025c510(1,(byte *)&local_128);
  FUN_80258944(6);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  if (param_5 == '\0') {
    if (param_4 != '\0') {
      FUN_8025ca04(6);
    }
    else {
      FUN_8025c5f0(1,0x1c);
      FUN_8025ca04(7);
      FUN_8025be80(0);
      FUN_8025c828(0,1,1,0xff);
      FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
      FUN_8025c224(0,4,7,7,6);
      FUN_8025c65c(0,0,0);
      FUN_8025c2a8(0,0,0,0,1,3);
      FUN_8025c368(0,1,0,3,1,3);
    }
    uVar2 = (uint)(param_4 == '\0');
    FUN_8025be80(uVar2);
    FUN_8025c828(uVar2,1,1,0xff);
    FUN_8025c1a4(uVar2,0xf,0xf,0xf,0xf);
    FUN_8025c224(uVar2,6,7,7,4);
    FUN_8025c65c(uVar2,0,0);
    FUN_8025c2a8(uVar2,0,0,0,1,0);
    FUN_8025c368(uVar2,1,0,3,1,0);
    FUN_8025c584(uVar2 + 1,0xd);
    FUN_8025be80(uVar2 + 1);
    FUN_8025c828(uVar2 + 1,0,0,0xff);
    FUN_8025c1a4(uVar2 + 1,0xf,8,0xe,0xf);
    if (param_4 == '\0') {
      FUN_8025c224(uVar2 + 1,0,7,7,3);
    }
    else {
      FUN_8025c224(uVar2 + 1,7,7,7,0);
    }
    FUN_8025c65c(uVar2 + 1,0,0);
    FUN_8025c2a8(uVar2 + 1,0,0,0,0,0);
    FUN_8025c368(uVar2 + 1,0,0,3,1,0);
    FUN_8025c584(uVar2 + 2,0xd);
    FUN_8025be80(uVar2 + 2);
    FUN_8025c828(uVar2 + 2,2,0,0xff);
    FUN_8025c1a4(uVar2 + 2,0xf,8,0xe,0);
    FUN_8025c224(uVar2 + 2,7,7,7,0);
    FUN_8025c65c(uVar2 + 2,0,0);
    FUN_8025c2a8(uVar2 + 2,0,0,0,0,0);
    FUN_8025c368(uVar2 + 2,0,0,2,1,0);
    FUN_8025c584(uVar2 + 3,0xd);
    FUN_8025be80(uVar2 + 3);
    FUN_8025c828(uVar2 + 3,3,0,0xff);
    FUN_8025c1a4(uVar2 + 3,0xf,8,0xe,0);
    FUN_8025c224(uVar2 + 3,7,7,7,0);
    FUN_8025c65c(uVar2 + 3,0,0);
    FUN_8025c2a8(uVar2 + 3,0,0,0,0,0);
    FUN_8025c368(uVar2 + 3,0,0,2,1,0);
    FUN_8025c584(uVar2 + 4,0xd);
    FUN_8025be80(uVar2 + 4);
    FUN_8025c828(uVar2 + 4,4,0,0xff);
    FUN_8025c1a4(uVar2 + 4,0xf,8,0xe,0);
    FUN_8025c224(uVar2 + 4,7,7,7,0);
    FUN_8025c65c(uVar2 + 4,0,0);
    FUN_8025c2a8(uVar2 + 4,0,0,0,0,0);
    FUN_8025c368(uVar2 + 4,0,0,2,1,0);
    FUN_8025c584(uVar2 + 5,0xd);
    FUN_8025be80(uVar2 + 5);
    FUN_8025c828(uVar2 + 5,5,0,0xff);
    FUN_8025c1a4(uVar2 + 5,0xf,8,0xe,0);
    FUN_8025c224(uVar2 + 5,7,7,7,0);
    FUN_8025c65c(uVar2 + 5,0,0);
    FUN_8025c2a8(uVar2 + 5,0,0,3,1,0);
    FUN_8025c368(uVar2 + 5,0,0,2,1,0);
  }
  else {
    FUN_8025c5f0(1,0x1c);
    FUN_8025ca04(7);
    FUN_8025be80(0);
    FUN_8025c828(0,1,1,0xff);
    FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
    FUN_8025c224(0,4,7,7,6);
    FUN_8025c65c(0,0,0);
    FUN_8025c2a8(0,0,0,0,1,3);
    FUN_8025c368(0,1,0,0,1,3);
    FUN_8025be80(1);
    FUN_8025c828(1,1,1,0xff);
    FUN_8025c1a4(1,0xf,0xf,0xf,0xf);
    FUN_8025c224(1,6,7,7,4);
    FUN_8025c65c(1,0,0);
    FUN_8025c2a8(1,0,0,0,1,0);
    FUN_8025c368(1,1,0,0,1,0);
    FUN_8025c584(2,0xd);
    FUN_8025be80(2);
    FUN_8025c828(2,0,0,0xff);
    FUN_8025c1a4(2,0xf,8,0xe,0xf);
    FUN_8025c224(2,0,7,7,3);
    FUN_8025c65c(2,0,0);
    FUN_8025c2a8(2,0,0,0,0,0);
    FUN_8025c368(2,0,0,2,1,0);
    FUN_8025c584(3,0xd);
    FUN_8025be80(3);
    FUN_8025c828(3,2,0,0xff);
    FUN_8025c1a4(3,0xf,8,0xe,0);
    FUN_8025c224(3,7,7,7,0);
    FUN_8025c65c(3,0,0);
    FUN_8025c2a8(3,0,0,0,0,0);
    FUN_8025c368(3,0,0,2,1,0);
    FUN_8025c584(4,0xd);
    FUN_8025be80(4);
    FUN_8025c828(4,3,0,0xff);
    FUN_8025c1a4(4,0xf,8,0xe,0);
    FUN_8025c224(4,7,7,7,0);
    FUN_8025c65c(4,0,0);
    FUN_8025c2a8(4,0,0,0,0,0);
    FUN_8025c368(4,0,0,2,1,0);
    FUN_8025c584(5,0xd);
    FUN_8025be80(5);
    FUN_8025c828(5,4,0,0xff);
    FUN_8025c1a4(5,0xf,8,0xe,0);
    FUN_8025c224(5,7,7,7,0);
    FUN_8025c65c(5,0,0);
    FUN_8025c2a8(5,0,0,0,0,0);
    FUN_8025c368(5,0,0,2,1,0);
    FUN_8025c584(6,0xd);
    FUN_8025be80(6);
    FUN_8025c828(6,5,0,0xff);
    FUN_8025c1a4(6,0xf,8,0xe,0);
    FUN_8025c224(6,7,7,7,0);
    FUN_8025c65c(6,0,0);
    FUN_8025c2a8(6,0,0,3,1,0);
    FUN_8025c368(6,0,0,0,1,0);
  }
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025cce8(1,4,5,5);
  if ((((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 7)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(0,7,0);
    DAT_803ddc98 = '\0';
    DAT_803ddc94 = 7;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  FUN_80259000(0x80,0,4);
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_1_ = 0xff;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x80;
  FUN_8000fb20();
  return;
}

