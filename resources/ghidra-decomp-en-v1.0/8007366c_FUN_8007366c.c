// Function: FUN_8007366c
// Entry: 8007366c
// Size: 1088 bytes

void FUN_8007366c(byte param_1)

{
  double dVar1;
  uint local_a0;
  uint local_9c;
  undefined auStack152 [4];
  float local_94;
  undefined4 local_90;
  undefined4 local_8c;
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
  undefined auStack64 [12];
  float local_34;
  
  FUN_8000f54c();
  FUN_8006c6f0(0);
  FUN_8025d160(&DAT_80396820,0x52,0);
  FUN_80257f10(0,0,0,0,0,0x52);
  FUN_8006cabc(&local_94,auStack152);
  local_94 = local_94 * FLOAT_803def28;
  FUN_8006c5e4(&local_8c);
  FUN_8004c2e4(local_8c,1);
  dVar1 = (double)FLOAT_803def2c;
  FUN_80247318(dVar1,dVar1,dVar1,auStack64);
  local_34 = local_94;
  FUN_8025d160(auStack64,0x21,1);
  FUN_80257f10(1,1,0,0x21,0,0x7d);
  local_88 = FLOAT_803deef8;
  local_84 = FLOAT_803deedc;
  local_80 = FLOAT_803deedc;
  local_7c = FLOAT_803deedc;
  local_78 = FLOAT_803deeec;
  local_74 = FLOAT_803deedc;
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_88,0xfffffffd);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  local_70 = FLOAT_803def30;
  local_6c = FLOAT_803deedc;
  local_68 = FLOAT_803deedc;
  local_64 = FLOAT_803deef8;
  local_60 = FLOAT_803deedc;
  local_5c = FLOAT_803def30;
  local_58 = FLOAT_803deedc;
  local_54 = FLOAT_803deef8;
  local_50 = FLOAT_803deedc;
  local_4c = FLOAT_803deedc;
  local_48 = FLOAT_803deedc;
  local_44 = FLOAT_803deee4;
  FUN_8025d160(&local_70,0x55,0);
  FUN_80257f10(2,1,1,0x1e,1,0x55);
  FUN_8006c5cc(&local_90);
  FUN_8004c2e4(local_90,2);
  local_9c = local_9c & 0xffffff00 | (uint)param_1;
  local_a0 = local_9c;
  FUN_8025bdac(0,&local_a0);
  FUN_8025be8c(1,0x1c);
  FUN_8025b6f0(1);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(3);
  FUN_8025c2a0(2);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,2,2,0xff);
  FUN_8025ba40(1,0xf,0xf,0xf,0);
  FUN_8025bac0(1,7,4,6,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  FUN_8025c584(1,4,5,5);
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(2);
  return;
}

