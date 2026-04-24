// Function: FUN_80071d54
// Entry: 80071d54
// Size: 1372 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80071d54(byte *param_1)

{
  char cVar1;
  char cVar2;
  char cVar3;
  undefined4 local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_18 = DAT_803deed4;
  local_c._0_1_ = (char)(DAT_803deec8 >> 0x18);
  cVar1 = (char)((int)(uint)*param_1 >> 3);
  local_c._1_1_ = (char)((DAT_803deec8 & 0xffffff) >> 0x10);
  cVar2 = (char)((int)(uint)param_1[1] >> 3);
  local_c._2_2_ = (ushort)(DAT_803deec8 & 0xffffff);
  local_c._1_3_ = CONCAT12(local_c._1_1_ + cVar2,local_c._2_2_);
  local_c._2_1_ = (char)((uint)local_c._1_3_ >> 8);
  cVar3 = (char)((int)(uint)param_1[2] >> 3);
  local_c._2_2_ = local_c._2_2_ & 0xff | (ushort)(byte)(local_c._2_1_ + cVar3) << 8;
  local_c = (uint)(byte)(local_c._0_1_ + cVar1) << 0x18 | local_c._1_3_ & 0xffff0000 |
            (uint)local_c._2_2_;
  local_10._0_1_ = (char)(DAT_803deecc >> 0x18);
  local_10._1_1_ = (char)((DAT_803deecc & 0xffffff) >> 0x10);
  local_10._2_2_ = (ushort)(DAT_803deecc & 0xffffff);
  local_10._1_3_ = CONCAT12(local_10._1_1_ + cVar2,local_10._2_2_);
  local_10._2_1_ = (char)((uint)local_10._1_3_ >> 8);
  local_10._2_2_ = local_10._2_2_ & 0xff | (ushort)(byte)(local_10._2_1_ + cVar3) << 8;
  local_10 = (uint)(byte)(local_10._0_1_ + cVar1) << 0x18 | local_10._1_3_ & 0xffff0000 |
             (uint)local_10._2_2_;
  local_14._0_1_ = (char)(DAT_803deed0 >> 0x18);
  local_14._1_1_ = (char)((DAT_803deed0 & 0xffffff) >> 0x10);
  local_14._2_2_ = (ushort)(DAT_803deed0 & 0xffffff);
  local_14._1_3_ = CONCAT12(local_14._1_1_ + cVar2,local_14._2_2_);
  local_14._2_1_ = (char)((uint)local_14._1_3_ >> 8);
  local_14._2_2_ = local_14._2_2_ & 0xff | (ushort)(byte)(local_14._2_1_ + cVar3) << 8;
  local_14 = (uint)(byte)(local_14._0_1_ + cVar1) << 0x18 | local_14._1_3_ & 0xffff0000 |
             (uint)local_14._2_2_;
  FUN_8006c830();
  FUN_8006c6f0(0);
  FUN_8025bf50(1,0,0,0,3);
  FUN_8025bf50(2,1,1,1,3);
  FUN_8025bf50(3,2,2,2,3);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  local_1c = local_c;
  FUN_8025bdac(0,&local_1c);
  local_20 = local_10;
  FUN_8025bdac(1,&local_20);
  local_24 = local_14;
  FUN_8025bdac(2,&local_24);
  local_28 = local_18;
  FUN_8025bcc4(1,&local_28);
  FUN_802581e0(1);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_8025c2a0(3);
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
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
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
  return;
}

