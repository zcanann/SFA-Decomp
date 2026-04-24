// Function: FUN_8011de20
// Entry: 8011de20
// Size: 696 bytes

void FUN_8011de20(int param_1,byte param_2,undefined4 param_3,char param_4)

{
  undefined4 local_18;
  uint local_14;
  undefined4 local_10;
  uint local_c;
  
  local_10 = DAT_803e1e38;
  local_c = DAT_803e1e34 & 0xffffff00 | (uint)param_2;
  local_14 = local_c;
  FUN_8025bcc4(1,&local_14);
  FUN_8025d0a8(&DAT_803a8830,0);
  FUN_8025d0e4(&DAT_803a8830,0);
  FUN_8025d124(0);
  FUN_802581e0(1);
  FUN_8025b6f0(0);
  FUN_80259e58(0);
  FUN_8004c264(param_1,0);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_8025be20(0,0xc);
  local_18 = local_10;
  FUN_8025bdac(0,&local_18);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,2,8,0xe,0xf);
  FUN_8025bac0(0,7,1,4,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  if (*(int *)(param_1 + 0x50) == 0) {
    FUN_8025c2a0(1);
  }
  else {
    FUN_8025b71c(1);
    FUN_8025c0c4(1,0,1,0xff);
    FUN_8025ba40(1,0xf,0xf,0xf,0);
    FUN_8025bac0(1,7,1,4,7);
    FUN_8025bef8(1,0,0);
    FUN_8025bb44(1,0,0,0,1,0);
    FUN_8025bc04(1,0,0,0,1,0);
    FUN_8025c2a0(2);
  }
  FUN_80258b24(0);
  if (param_4 == '\0') {
    FUN_8025c584(1,4,5,5);
  }
  else {
    FUN_8025c584(1,4,1,5);
  }
  FUN_80070310(0,7,0);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  return;
}

