// Function: FUN_80079be0
// Entry: 80079be0
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x80079fc0) */
/* WARNING: Removing unreachable block (ram,0x80079fb8) */
/* WARNING: Removing unreachable block (ram,0x80079bf8) */
/* WARNING: Removing unreachable block (ram,0x80079bf0) */

void FUN_80079be0(double param_1,double param_2,byte param_3,char param_4)

{
  double dVar1;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  int local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  local_60 = DAT_803dfb20;
  local_64 = DAT_803dfb24;
  local_68 = DAT_803dfb28;
  FUN_8006c6bc(&local_5c);
  FUN_8004c460(local_5c,0);
  dVar1 = (double)FLOAT_803dfb78;
  local_58 = (float)(dVar1 / param_1);
  local_44 = (float)(dVar1 / param_2);
  local_54 = FLOAT_803dfb5c;
  local_50 = FLOAT_803dfb5c;
  local_4c = (float)((double)FLOAT_803dfbcc * (double)local_58 + dVar1);
  local_48 = FLOAT_803dfb5c;
  local_40 = FLOAT_803dfb5c;
  local_3c = (float)((double)FLOAT_803dfbd0 * (double)local_44 + dVar1);
  local_38 = FLOAT_803dfb5c;
  local_34 = FLOAT_803dfb5c;
  local_30 = FLOAT_803dfb5c;
  local_2c = FLOAT_803dfb64;
  FUN_80258674(0,1,0,0x1e,0,0x7d);
  FUN_8025d8c4(&local_58,0x1e,1);
  FUN_8025c584(0,0xc);
  FUN_8025c5f0(0,0x1c);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  if (param_4 == '\0') {
    local_60 = CONCAT31(local_60._0_3_,(char)((int)(uint)param_3 >> 2));
    local_78 = local_60;
    FUN_8025c510(0,(byte *)&local_78);
    FUN_8025c224(0,4,7,7,6);
    FUN_8025c368(0,0,0,2,1,0);
  }
  else {
    local_60 = CONCAT31(local_60._0_3_,param_3);
    local_6c = local_60;
    FUN_8025c510(0,(byte *)&local_6c);
    local_70 = local_64;
    FUN_8025c428(1,(byte *)&local_70);
    local_74 = local_68;
    FUN_8025c428(2,(byte *)&local_74);
    FUN_8025c224(0,4,1,2,6);
    FUN_8025c368(0,0xe,0,0,1,0);
  }
  FUN_80258944(1);
  FUN_8025ca04(1);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80257b5c();
  FUN_8025d888(0x3c);
  FUN_802570dc(9,1);
  FUN_80259288(0);
  FUN_8025cce8(1,5,4,5);
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
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  FUN_8000fb20();
  FUN_8025d888(0);
  return;
}

