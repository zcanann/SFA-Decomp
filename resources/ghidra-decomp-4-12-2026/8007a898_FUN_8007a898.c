// Function: FUN_8007a898
// Entry: 8007a898
// Size: 1524 bytes

void FUN_8007a898(uint param_1)

{
  undefined uVar1;
  undefined uVar2;
  ushort uVar3;
  uint uVar4;
  undefined4 local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  int local_5c;
  int local_58;
  float local_54;
  float local_50;
  undefined4 local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  float afStack_3c [3];
  float local_30;
  float local_20;
  
  local_54 = DAT_802c2628;
  local_50 = (float)DAT_802c262c;
  local_4c = DAT_802c2630;
  local_48 = (float)DAT_802c2634;
  local_44 = (float)DAT_802c2638;
  local_40 = DAT_802c263c;
  uVar3 = FUN_8000fa90();
  if ((short)uVar3 < 0) {
    uVar4 = (((int)(uint)uVar3 >> 8) + -0xc0) * 4 & 0xfc;
  }
  else {
    uVar4 = 0xff;
  }
  uVar2 = (undefined)((param_1 & 0xff) * 0xff >> 8);
  uVar1 = (undefined)(uVar4 * (param_1 & 0xff) >> 8);
  FUN_8006c86c(0);
  FUN_8006c754(&local_5c);
  FUN_8004c460(local_5c,1);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8006cc38(&local_60,&local_64);
  local_60 = local_60 * FLOAT_803dfbec;
  local_64 = local_64 * FLOAT_803dfbec;
  FUN_8006c760(&local_58);
  FUN_8004c460(local_58,2);
  FUN_802943c4();
  local_68 = local_68 * FLOAT_803dfb78;
  local_6c = local_6c * FLOAT_803dfb78;
  local_48 = -local_6c;
  local_54 = local_68;
  local_50 = local_6c;
  local_44 = local_68;
  FUN_80247a7c((double)FLOAT_803dfbf4,(double)FLOAT_803dfbf4,(double)FLOAT_803dfb64,afStack_3c);
  local_30 = local_60;
  local_20 = -local_64;
  FUN_8025d8c4(afStack_3c,0x40,0);
  FUN_80258674(1,0,4,0x3c,0,0x40);
  FUN_8025bd1c(0,1,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_54,-6);
  FUN_8025b94c(1,0,0,7,1,0,0,0,0,0);
  local_70 = DAT_803dc304;
  FUN_8025c510(0,(byte *)&local_70);
  FUN_8025c5f0(0,0x1c);
  FUN_8025be80(0);
  FUN_8025c828(0,0,1,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  FUN_8025c224(0,6,7,7,4);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,1,0,2,1,0);
  FUN_8025c828(1,0,0,0xff);
  FUN_8025c1a4(1,8,0xf,0xf,0xf);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,2,1,0);
  FUN_8025be80(2);
  FUN_8025c828(2,0xff,0xff,4);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,0,5,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,2,1,0);
  FUN_80258944(2);
  FUN_8025ca04(3);
  FUN_8025be54(1);
  FUN_8025a5bc(1);
  FUN_80257b5c();
  FUN_8025d888(0x3c);
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025cce8(1,4,5,5);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 1)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,1,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 1;
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
  FUN_8025a608(4,0,0,1,0,0,2);
  FUN_80259000(0x80,0,4);
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = uVar1;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = uVar1;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = uVar2;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = 0;
  DAT_cc008000._0_1_ = uVar2;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x80;
  FUN_8000fb20();
  FUN_8025d888(0);
  return;
}

