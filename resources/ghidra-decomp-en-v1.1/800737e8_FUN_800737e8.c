// Function: FUN_800737e8
// Entry: 800737e8
// Size: 1088 bytes

void FUN_800737e8(undefined param_1)

{
  double dVar1;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 uStack_98;
  float local_94;
  int local_90;
  int local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float afStack_40 [3];
  float local_34;
  
  FUN_8000f56c();
  FUN_8006c86c(0);
  FUN_8025d8c4((float *)&DAT_80397480,0x52,0);
  FUN_80258674(0,0,0,0,0,0x52);
  FUN_8006cc38(&local_94,&uStack_98);
  local_94 = local_94 * FLOAT_803dfba8;
  FUN_8006c760(&local_8c);
  FUN_8004c460(local_8c,1);
  dVar1 = (double)FLOAT_803dfbac;
  FUN_80247a7c(dVar1,dVar1,dVar1,afStack_40);
  local_34 = local_94;
  FUN_8025d8c4(afStack_40,0x21,1);
  FUN_80258674(1,1,0,0x21,0,0x7d);
  local_88 = FLOAT_803dfb78;
  local_84 = FLOAT_803dfb5c;
  local_80 = FLOAT_803dfb5c;
  local_7c = FLOAT_803dfb5c;
  local_78 = FLOAT_803dfb6c;
  local_74 = FLOAT_803dfb5c;
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_88,-3);
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  local_70 = FLOAT_803dfbb0;
  local_6c = FLOAT_803dfb5c;
  local_68 = FLOAT_803dfb5c;
  local_64 = FLOAT_803dfb78;
  local_60 = FLOAT_803dfb5c;
  local_5c = FLOAT_803dfbb0;
  local_58 = FLOAT_803dfb5c;
  local_54 = FLOAT_803dfb78;
  local_50 = FLOAT_803dfb5c;
  local_4c = FLOAT_803dfb5c;
  local_48 = FLOAT_803dfb5c;
  local_44 = FLOAT_803dfb64;
  FUN_8025d8c4(&local_70,0x55,0);
  FUN_80258674(2,1,1,0x1e,1,0x55);
  FUN_8006c748(&local_90);
  FUN_8004c460(local_90,2);
  local_9c = CONCAT31(local_9c._0_3_,param_1);
  local_a0 = local_9c;
  FUN_8025c510(0,(byte *)&local_a0);
  FUN_8025c5f0(1,0x1c);
  FUN_8025be54(1);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(3);
  FUN_8025ca04(2);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,8);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025be80(1);
  FUN_8025c828(1,2,2,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,0);
  FUN_8025c224(1,7,4,6,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  FUN_8025cce8(1,4,5,5);
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(2);
  return;
}

