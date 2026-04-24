// Function: FUN_8007ad10
// Entry: 8007ad10
// Size: 780 bytes

void FUN_8007ad10(double param_1)

{
  uint local_48;
  undefined auStack68 [52];
  longlong local_10;
  
  local_10 = (longlong)(int)((double)FLOAT_803def20 * param_1);
  DAT_803db6a0 = DAT_803db6a0 & 0xffffff00 | (int)((double)FLOAT_803def20 * param_1) & 0xffU;
  FUN_8006c6f0(0);
  local_48 = DAT_803db6a0;
  FUN_8025bdac(0,&local_48);
  FUN_8025be8c(0,0x1c);
  FUN_80246e54(auStack68);
  FUN_8025d160(auStack68,0x24,1);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
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
  FUN_802581e0(1);
  FUN_8025c2a0(1);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,6);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,7,7,6);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025889c(0x80,0,4);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x80);
  FUN_8000fb00();
  return;
}

