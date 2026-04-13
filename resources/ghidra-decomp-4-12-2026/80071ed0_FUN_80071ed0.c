// Function: FUN_80071ed0
// Entry: 80071ed0
// Size: 1372 bytes

void FUN_80071ed0(byte *param_1)

{
  char cVar1;
  char cVar2;
  char cVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_18 = DAT_803dfb54;
  local_c._0_1_ = (char)((uint)DAT_803dfb48 >> 0x18);
  cVar1 = (char)((int)(uint)*param_1 >> 3);
  local_c._1_1_ = (char)((uint)DAT_803dfb48 >> 0x10);
  cVar2 = (char)((int)(uint)param_1[1] >> 3);
  local_c._2_1_ = (char)((uint)DAT_803dfb48 >> 8);
  cVar3 = (char)((int)(uint)param_1[2] >> 3);
  local_c._2_1_ = local_c._2_1_ + cVar3;
  local_c._3_1_ = (undefined)DAT_803dfb48;
  local_c = CONCAT22(CONCAT11(local_c._0_1_ + cVar1,local_c._1_1_ + cVar2),
                     CONCAT11(local_c._2_1_,(undefined)local_c));
  local_10._0_1_ = (char)((uint)DAT_803dfb4c >> 0x18);
  local_10._1_1_ = (char)((uint)DAT_803dfb4c >> 0x10);
  local_10._2_1_ = (char)((uint)DAT_803dfb4c >> 8);
  local_10._2_1_ = local_10._2_1_ + cVar3;
  local_10._3_1_ = (undefined)DAT_803dfb4c;
  local_10 = CONCAT22(CONCAT11(local_10._0_1_ + cVar1,local_10._1_1_ + cVar2),
                      CONCAT11(local_10._2_1_,(undefined)local_10));
  local_14._0_1_ = (char)((uint)DAT_803dfb50 >> 0x18);
  local_14._1_1_ = (char)((uint)DAT_803dfb50 >> 0x10);
  local_14._2_1_ = (char)((uint)DAT_803dfb50 >> 8);
  local_14._2_1_ = local_14._2_1_ + cVar3;
  local_14._3_1_ = (undefined)DAT_803dfb50;
  local_14 = CONCAT22(CONCAT11(local_14._0_1_ + cVar1,local_14._1_1_ + cVar2),
                      CONCAT11(local_14._2_1_,(undefined)local_14));
  FUN_8006c9ac();
  FUN_8006c86c(0);
  FUN_8025c6b4(1,0,0,0,3);
  FUN_8025c6b4(2,1,1,1,3);
  FUN_8025c6b4(3,2,2,2,3);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  local_1c = local_c;
  FUN_8025c510(0,(byte *)&local_1c);
  local_20 = local_10;
  FUN_8025c510(1,(byte *)&local_20);
  local_24 = local_14;
  FUN_8025c510(2,(byte *)&local_24);
  local_28 = local_18;
  FUN_8025c428(1,(byte *)&local_28);
  FUN_80258944(1);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_8025ca04(3);
  FUN_8025c584(0,0xc);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,8,0xe,2);
  FUN_8025c224(0,7,7,7,1);
  FUN_8025c65c(0,0,1);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025c584(1,0xd);
  FUN_8025c5f0(1,0x1d);
  FUN_8025be80(1);
  FUN_8025c828(1,0,0,0xff);
  FUN_8025c1a4(1,0xf,8,0xe,0);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,2);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,3);
  FUN_8025c584(2,0xe);
  FUN_8025be80(2);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025c1a4(2,0xf,8,0xe,0);
  FUN_8025c224(2,7,7,7,0);
  FUN_8025c65c(2,0,3);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025cce8(0,1,0,5);
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
  FUN_8025d888(0x3c);
  FUN_80259000(0x80,0,4);
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x80;
  FUN_8000fb20();
  return;
}

