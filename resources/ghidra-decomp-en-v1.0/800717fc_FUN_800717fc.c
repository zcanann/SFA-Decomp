// Function: FUN_800717fc
// Entry: 800717fc
// Size: 1368 bytes

void FUN_800717fc(void)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c [3];
  
  FUN_8006c830();
  FUN_8006c6f0(0);
  FUN_8025bf50(0,1,2,0,3);
  FUN_8025bf50(1,0,0,0,3);
  FUN_8025bf50(2,1,1,1,3);
  FUN_8025bf50(3,2,2,2,3);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  local_c[0] = DAT_803db6d0;
  FUN_8025bdac(0,local_c);
  local_10 = DAT_803db6d4;
  FUN_8025bdac(1,&local_10);
  local_14 = DAT_803db6d8;
  FUN_8025bdac(2,&local_14);
  local_18 = DAT_803db6dc;
  FUN_8025bcc4(1,&local_18);
  FUN_802581e0(1);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_8025c2a0(4);
  FUN_8025be20(0,0xc);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,8,0xe,2);
  FUN_8025bac0(0,7,7,7,1);
  FUN_8025bef8(0,0,1);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025be20(1,0xd);
  FUN_8025be8c(1,0x1d);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,0,0,0xff);
  FUN_8025ba40(1,0xf,8,0xe,0);
  FUN_8025bac0(1,7,7,7,0);
  FUN_8025bef8(1,0,2);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,3);
  FUN_8025be20(2,0xe);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,0,0,0xff);
  FUN_8025ba40(2,0xf,8,0xe,0);
  FUN_8025bac0(2,7,7,7,0);
  FUN_8025bef8(2,0,3);
  FUN_8025bb44(2,0,0,3,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  FUN_8025b71c(3);
  FUN_8025c0c4(3,0,0,0xff);
  FUN_8025ba40(3,0,0xf,0xf,8);
  FUN_8025bac0(3,7,7,7,0);
  FUN_8025bef8(3,0,0);
  FUN_8025bb44(3,1,0,2,1,0);
  FUN_8025bc04(3,0,0,0,1,0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  FUN_8025c584(0,1,0,5);
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
  FUN_8025d124(0x3c);
  FUN_8025889c(0x80,0,4);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0x80);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x80);
  FUN_8000fb00();
  FUN_8025bf50(0,0,1,2,3);
  return;
}

