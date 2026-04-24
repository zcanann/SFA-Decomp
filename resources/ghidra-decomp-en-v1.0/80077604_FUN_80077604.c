// Function: FUN_80077604
// Entry: 80077604
// Size: 648 bytes

void FUN_80077604(int param_1,undefined4 *param_2,undefined4 param_3)

{
  undefined4 local_48;
  undefined4 local_44;
  undefined auStack64 [52];
  
  FUN_8025bf50(1,3,0,3,0);
  FUN_80246eb4(param_1,param_3,auStack64);
  FUN_8025d160(auStack64,0x1e,1);
  FUN_80257f10(0,1,0,0x1e,0,0x7d);
  FUN_8004c2e4(*(undefined4 *)(param_1 + 0x60),0);
  local_44 = *param_2;
  FUN_8025bdac(0,&local_44);
  FUN_8025be8c(0,0x1c);
  FUN_8025be20(0,0xc);
  local_48 = DAT_803db6a8;
  FUN_8025bcc4(2,&local_48);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  FUN_8025bac0(0,2,4,6,7);
  FUN_8025bef8(0,0,1);
  FUN_8025bb44(0,0,0,0,0,1);
  FUN_8025bc04(0,0xe,0,0,1,0);
  FUN_8025c584(1,4,5,5);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(1);
  FUN_8025c2a0(1);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  return;
}

