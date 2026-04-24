// Function: FUN_80079a64
// Entry: 80079a64
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x80079e3c) */
/* WARNING: Removing unreachable block (ram,0x80079e44) */

void FUN_80079a64(double param_1,double param_2,byte param_3,char param_4)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f30;
  undefined8 in_f31;
  uint local_78;
  undefined4 local_74;
  undefined4 local_70;
  uint local_6c;
  undefined4 local_68;
  undefined4 local_64;
  uint local_60;
  undefined4 local_5c;
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
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_60 = DAT_803deea0;
  local_64 = DAT_803deea4;
  local_68 = DAT_803deea8;
  FUN_8006c540(&local_5c);
  FUN_8004c2e4(local_5c,0);
  dVar2 = (double)FLOAT_803deef8;
  local_58 = (float)(dVar2 / param_1);
  local_44 = (float)(dVar2 / param_2);
  local_54 = FLOAT_803deedc;
  local_50 = FLOAT_803deedc;
  local_4c = (float)((double)FLOAT_803def4c * (double)local_58 + dVar2);
  local_48 = FLOAT_803deedc;
  local_40 = FLOAT_803deedc;
  local_3c = (float)((double)FLOAT_803def50 * (double)local_44 + dVar2);
  local_38 = FLOAT_803deedc;
  local_34 = FLOAT_803deedc;
  local_30 = FLOAT_803deedc;
  local_2c = FLOAT_803deee4;
  FUN_80257f10(0,1,0,0x1e,0,0x7d);
  FUN_8025d160(&local_58,0x1e,1);
  FUN_8025be20(0,0xc);
  FUN_8025be8c(0,0x1c);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  if (param_4 == '\0') {
    local_60 = local_60 & 0xffffff00 | (int)(uint)param_3 >> 2;
    local_78 = local_60;
    FUN_8025bdac(0,&local_78);
    FUN_8025bac0(0,4,7,7,6);
    FUN_8025bc04(0,0,0,2,1,0);
  }
  else {
    local_60 = local_60 & 0xffffff00 | (uint)param_3;
    local_6c = local_60;
    FUN_8025bdac(0,&local_6c);
    local_70 = local_64;
    FUN_8025bcc4(1,&local_70);
    local_74 = local_68;
    FUN_8025bcc4(2,&local_74);
    FUN_8025bac0(0,4,1,2,6);
    FUN_8025bc04(0,0xe,0,0,1,0);
  }
  FUN_802581e0(1);
  FUN_8025c2a0(1);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802573f8();
  FUN_8025d124(0x3c);
  FUN_80256978(9,1);
  FUN_80258b24(0);
  FUN_8025c584(1,5,4,5);
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
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0x280);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_2(0xcc008000,0);
  write_volatile_2(0xcc008000,0x1e0);
  write_volatile_2(0xcc008000,0xfff8);
  FUN_8000fb00();
  FUN_8025d124(0);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  return;
}

