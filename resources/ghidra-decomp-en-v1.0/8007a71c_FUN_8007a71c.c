// Function: FUN_8007a71c
// Entry: 8007a71c
// Size: 1524 bytes

void FUN_8007a71c(uint param_1)

{
  undefined uVar1;
  undefined uVar2;
  short sVar3;
  uint uVar4;
  undefined4 local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  float local_54;
  float local_50;
  undefined4 local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  undefined auStack60 [12];
  float local_30;
  float local_20;
  
  local_54 = DAT_802c1ea8;
  local_50 = (float)DAT_802c1eac;
  local_4c = DAT_802c1eb0;
  local_48 = (float)DAT_802c1eb4;
  local_44 = (float)DAT_802c1eb8;
  local_40 = DAT_802c1ebc;
  sVar3 = FUN_8000fa70();
  if (sVar3 < 0) {
    uVar4 = (((int)((int)sVar3 & 0xffffU) >> 8) + -0xc0) * 4 & 0xfc;
  }
  else {
    uVar4 = 0xff;
  }
  uVar2 = (undefined)((param_1 & 0xff) * 0xff >> 8);
  uVar1 = (undefined)(uVar4 * (param_1 & 0xff) >> 8);
  FUN_8006c6f0(0);
  FUN_8006c5d8(&local_5c);
  FUN_8004c2e4(local_5c,1);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_8006cabc(&local_60,&local_64);
  local_60 = local_60 * FLOAT_803def6c;
  local_64 = local_64 * FLOAT_803def6c;
  FUN_8006c5e4(&local_58);
  FUN_8004c2e4(local_58,2);
  FUN_80293c64((double)(FLOAT_803def70 * local_60),&local_6c,&local_68);
  local_68 = local_68 * FLOAT_803deef8;
  local_6c = local_6c * FLOAT_803deef8;
  local_48 = -local_6c;
  local_54 = local_68;
  local_50 = local_6c;
  local_44 = local_68;
  FUN_80247318((double)FLOAT_803def74,(double)FLOAT_803def74,(double)FLOAT_803deee4,auStack60);
  local_30 = local_60;
  local_20 = -local_64;
  FUN_8025d160(auStack60,0x40,0);
  FUN_80257f10(1,0,4,0x3c,0,0x40);
  FUN_8025b5b8(0,1,2);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_54,0xfffffffa);
  FUN_8025b1e8(1,0,0,7,1,0,0,0,0,0);
  local_70 = DAT_803db6a4;
  FUN_8025bdac(0,&local_70);
  FUN_8025be8c(0,0x1c);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,1,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  FUN_8025bac0(0,6,7,7,4);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,1,0,2,1,0);
  FUN_8025c0c4(1,0,0,0xff);
  FUN_8025ba40(1,8,0xf,0xf,0xf);
  FUN_8025bac0(1,7,7,7,0);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,2,1,0);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,0xff,0xff,4);
  FUN_8025ba40(2,0xf,0xf,0xf,0);
  FUN_8025bac0(2,7,0,5,7);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,2,1,0);
  FUN_802581e0(2);
  FUN_8025c2a0(3);
  FUN_8025b6f0(1);
  FUN_80259e58(1);
  FUN_802573f8();
  FUN_8025d124(0x3c);
  FUN_80256978(9,1);
  FUN_80256978(0xb,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  FUN_8025c584(1,4,5,5);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 1)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,1,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 1;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  FUN_8025cf48(&DAT_80396880,1);
  FUN_80259ea4(4,0,0,1,0,0,2);
  FUN_8025889c(0x80,0,4);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,uVar1);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,uVar1);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,uVar2);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,0);
  write_volatile_1(DAT_cc008000,uVar2);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x80);
  FUN_8000fb00();
  FUN_8025d124(0);
  return;
}

