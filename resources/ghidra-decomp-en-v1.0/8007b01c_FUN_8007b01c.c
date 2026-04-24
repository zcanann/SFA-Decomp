// Function: FUN_8007b01c
// Entry: 8007b01c
// Size: 3440 bytes

void FUN_8007b01c(double param_1,undefined8 param_2,double param_3,char param_4,char param_5)

{
  bool bVar1;
  byte extraout_var;
  undefined4 local_128;
  uint local_124;
  undefined auStack288 [4];
  undefined auStack284 [4];
  undefined auStack280 [4];
  float local_114;
  undefined4 local_110;
  uint local_10c;
  undefined auStack264 [12];
  float local_fc;
  undefined auStack216 [12];
  float local_cc;
  undefined auStack168 [28];
  float local_8c;
  undefined auStack120 [28];
  float local_5c;
  undefined auStack72 [60];
  
  FUN_8000ef48((double)(float)(param_1 - (double)FLOAT_803dcdd8),param_2,
               (double)(float)(param_3 - (double)FLOAT_803dcddc),auStack280,auStack284,&local_114,
               auStack288);
  local_114 = local_114 + FLOAT_803deee4;
  FUN_80285fb4((double)(FLOAT_803def08 * local_114));
  local_10c = local_10c & 0xffffff00 | (uint)extraout_var;
  FUN_8006c6f0(0);
  FUN_8006c5d8(&local_110);
  FUN_8004c2e4(local_110,1);
  FUN_8025bf50(1,0,0,0,1);
  FUN_80246e54(auStack120);
  local_5c = FLOAT_803def78;
  FUN_8025d160(auStack120,0x24,1);
  FUN_80257f10(0,1,4,0x24,0,0x7d);
  FUN_80246e54(auStack168);
  local_8c = FLOAT_803def78;
  FUN_8025d160(auStack168,0x2a,1);
  FUN_80257f10(2,1,4,0x2a,0,0x7d);
  FUN_80246e54(auStack216);
  local_cc = FLOAT_803def7c;
  FUN_8025d160(auStack216,0x2d,1);
  FUN_80257f10(3,1,4,0x2d,0,0x7d);
  FUN_80246e54(auStack264);
  local_fc = FLOAT_803def80;
  FUN_8025d160(auStack264,0x30,1);
  FUN_80257f10(4,1,4,0x30,0,0x7d);
  FUN_80257f10(5,1,4,0x3c,0,0x7d);
  FUN_80246e54(auStack72);
  FUN_8025d160(auStack72,0x27,1);
  FUN_80257f10(1,1,4,0x27,0,0x7d);
  local_124 = local_10c;
  FUN_8025bdac(0,&local_124);
  FUN_8025be8c(0,0x1c);
  local_128 = DAT_803db69c;
  FUN_8025bdac(1,&local_128);
  FUN_802581e0(6);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  if (param_5 == '\0') {
    if (param_4 != '\0') {
      FUN_8025c2a0(6);
    }
    else {
      FUN_8025be8c(1,0x1c);
      FUN_8025c2a0(7);
      FUN_8025b71c(0);
      FUN_8025c0c4(0,1,1,0xff);
      FUN_8025ba40(0,0xf,0xf,0xf,0xf);
      FUN_8025bac0(0,4,7,7,6);
      FUN_8025bef8(0,0,0);
      FUN_8025bb44(0,0,0,0,1,3);
      FUN_8025bc04(0,1,0,3,1,3);
    }
    bVar1 = param_4 == '\0';
    FUN_8025b71c(bVar1);
    FUN_8025c0c4(bVar1,1,1,0xff);
    FUN_8025ba40(bVar1,0xf,0xf,0xf,0xf);
    FUN_8025bac0(bVar1,6,7,7,4);
    FUN_8025bef8(bVar1,0,0);
    FUN_8025bb44(bVar1,0,0,0,1,0);
    FUN_8025bc04(bVar1,1,0,3,1,0);
    FUN_8025be20(bVar1 + '\x01',0xd);
    FUN_8025b71c(bVar1 + '\x01');
    FUN_8025c0c4(bVar1 + '\x01',0,0,0xff);
    FUN_8025ba40(bVar1 + '\x01',0xf,8,0xe,0xf);
    if (param_4 == '\0') {
      FUN_8025bac0(bVar1 + '\x01',0,7,7,3);
    }
    else {
      FUN_8025bac0(bVar1 + '\x01',7,7,7,0);
    }
    FUN_8025bef8(bVar1 + '\x01',0,0);
    FUN_8025bb44(bVar1 + '\x01',0,0,0,0,0);
    FUN_8025bc04(bVar1 + '\x01',0,0,3,1,0);
    FUN_8025be20(bVar1 + '\x02',0xd);
    FUN_8025b71c(bVar1 + '\x02');
    FUN_8025c0c4(bVar1 + '\x02',2,0,0xff);
    FUN_8025ba40(bVar1 + '\x02',0xf,8,0xe,0);
    FUN_8025bac0(bVar1 + '\x02',7,7,7,0);
    FUN_8025bef8(bVar1 + '\x02',0,0);
    FUN_8025bb44(bVar1 + '\x02',0,0,0,0,0);
    FUN_8025bc04(bVar1 + '\x02',0,0,2,1,0);
    FUN_8025be20(bVar1 + '\x03',0xd);
    FUN_8025b71c(bVar1 + '\x03');
    FUN_8025c0c4(bVar1 + '\x03',3,0,0xff);
    FUN_8025ba40(bVar1 + '\x03',0xf,8,0xe,0);
    FUN_8025bac0(bVar1 + '\x03',7,7,7,0);
    FUN_8025bef8(bVar1 + '\x03',0,0);
    FUN_8025bb44(bVar1 + '\x03',0,0,0,0,0);
    FUN_8025bc04(bVar1 + '\x03',0,0,2,1,0);
    FUN_8025be20(bVar1 + '\x04',0xd);
    FUN_8025b71c(bVar1 + '\x04');
    FUN_8025c0c4(bVar1 + '\x04',4,0,0xff);
    FUN_8025ba40(bVar1 + '\x04',0xf,8,0xe,0);
    FUN_8025bac0(bVar1 + '\x04',7,7,7,0);
    FUN_8025bef8(bVar1 + '\x04',0,0);
    FUN_8025bb44(bVar1 + '\x04',0,0,0,0,0);
    FUN_8025bc04(bVar1 + '\x04',0,0,2,1,0);
    FUN_8025be20(bVar1 + '\x05',0xd);
    FUN_8025b71c(bVar1 + '\x05');
    FUN_8025c0c4(bVar1 + '\x05',5,0,0xff);
    FUN_8025ba40(bVar1 + '\x05',0xf,8,0xe,0);
    FUN_8025bac0(bVar1 + '\x05',7,7,7,0);
    FUN_8025bef8(bVar1 + '\x05',0,0);
    FUN_8025bb44(bVar1 + '\x05',0,0,3,1,0);
    FUN_8025bc04(bVar1 + '\x05',0,0,2,1,0);
  }
  else {
    FUN_8025be8c(1,0x1c);
    FUN_8025c2a0(7);
    FUN_8025b71c(0);
    FUN_8025c0c4(0,1,1,0xff);
    FUN_8025ba40(0,0xf,0xf,0xf,0xf);
    FUN_8025bac0(0,4,7,7,6);
    FUN_8025bef8(0,0,0);
    FUN_8025bb44(0,0,0,0,1,3);
    FUN_8025bc04(0,1,0,0,1,3);
    FUN_8025b71c(1);
    FUN_8025c0c4(1,1,1,0xff);
    FUN_8025ba40(1,0xf,0xf,0xf,0xf);
    FUN_8025bac0(1,6,7,7,4);
    FUN_8025bef8(1,0,0);
    FUN_8025bb44(1,0,0,0,1,0);
    FUN_8025bc04(1,1,0,0,1,0);
    FUN_8025be20(2,0xd);
    FUN_8025b71c(2);
    FUN_8025c0c4(2,0,0,0xff);
    FUN_8025ba40(2,0xf,8,0xe,0xf);
    FUN_8025bac0(2,0,7,7,3);
    FUN_8025bef8(2,0,0);
    FUN_8025bb44(2,0,0,0,0,0);
    FUN_8025bc04(2,0,0,2,1,0);
    FUN_8025be20(3,0xd);
    FUN_8025b71c(3);
    FUN_8025c0c4(3,2,0,0xff);
    FUN_8025ba40(3,0xf,8,0xe,0);
    FUN_8025bac0(3,7,7,7,0);
    FUN_8025bef8(3,0,0);
    FUN_8025bb44(3,0,0,0,0,0);
    FUN_8025bc04(3,0,0,2,1,0);
    FUN_8025be20(4,0xd);
    FUN_8025b71c(4);
    FUN_8025c0c4(4,3,0,0xff);
    FUN_8025ba40(4,0xf,8,0xe,0);
    FUN_8025bac0(4,7,7,7,0);
    FUN_8025bef8(4,0,0);
    FUN_8025bb44(4,0,0,0,0,0);
    FUN_8025bc04(4,0,0,2,1,0);
    FUN_8025be20(5,0xd);
    FUN_8025b71c(5);
    FUN_8025c0c4(5,4,0,0xff);
    FUN_8025ba40(5,0xf,8,0xe,0);
    FUN_8025bac0(5,7,7,7,0);
    FUN_8025bef8(5,0,0);
    FUN_8025bb44(5,0,0,0,0,0);
    FUN_8025bc04(5,0,0,2,1,0);
    FUN_8025be20(6,0xd);
    FUN_8025b71c(6);
    FUN_8025c0c4(6,5,0,0xff);
    FUN_8025ba40(6,0xf,8,0xe,0);
    FUN_8025bac0(6,7,7,7,0);
    FUN_8025bef8(6,0,0);
    FUN_8025bb44(6,0,0,3,1,0);
    FUN_8025bc04(6,0,0,0,1,0);
  }
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xb,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  FUN_8025c584(1,4,5,5);
  if ((((DAT_803dd018 != '\0') || (DAT_803dd014 != 7)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(0,7,0);
    DAT_803dd018 = '\0';
    DAT_803dd014 = 7;
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
  FUN_8025889c(0x80,0,4);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_1(DAT_cc008000,0xff);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x80);
  FUN_8000fb00();
  return;
}

