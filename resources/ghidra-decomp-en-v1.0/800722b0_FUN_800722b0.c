// Function: FUN_800722b0
// Entry: 800722b0
// Size: 2892 bytes

/* WARNING: Removing unreachable block (ram,0x80072ddc) */
/* WARNING: Removing unreachable block (ram,0x80072de4) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_800722b0(double param_1,undefined8 param_2,float *param_3,byte *param_4)

{
  char cVar1;
  char cVar2;
  char cVar3;
  float fVar4;
  byte extraout_var;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f30;
  undefined8 in_f31;
  uint local_11c;
  uint local_118;
  uint local_114;
  uint local_110;
  undefined4 local_10c;
  undefined4 local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  undefined auStack248 [4];
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  undefined auStack192 [48];
  undefined auStack144 [48];
  undefined auStack96 [48];
  longlong local_30;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_fc._0_1_ = (char)(DAT_803deeb8 >> 0x18);
  cVar1 = (char)((int)(uint)*param_4 >> 2);
  local_fc._1_1_ = (char)((DAT_803deeb8 & 0xffffff) >> 0x10);
  cVar2 = (char)((int)(uint)param_4[1] >> 2);
  local_fc._2_2_ = (ushort)(DAT_803deeb8 & 0xffffff);
  local_fc._1_3_ = CONCAT12(local_fc._1_1_ + cVar2,local_fc._2_2_);
  local_fc._2_1_ = (char)((uint)local_fc._1_3_ >> 8);
  cVar3 = (char)((int)(uint)param_4[2] >> 2);
  local_fc._2_2_ = local_fc._2_2_ & 0xff | (ushort)(byte)(local_fc._2_1_ + cVar3) << 8;
  local_fc = (uint)(byte)(local_fc._0_1_ + cVar1) << 0x18 | local_fc._1_3_ & 0xffff0000 |
             (uint)local_fc._2_2_;
  local_100._0_1_ = (char)(DAT_803deebc >> 0x18);
  local_100._1_1_ = (char)((DAT_803deebc & 0xffffff) >> 0x10);
  local_100._2_2_ = (ushort)(DAT_803deebc & 0xffffff);
  local_100._1_3_ = CONCAT12(local_100._1_1_ + cVar2,local_100._2_2_);
  local_100._2_1_ = (char)((uint)local_100._1_3_ >> 8);
  local_100._2_2_ = local_100._2_2_ & 0xff | (ushort)(byte)(local_100._2_1_ + cVar3) << 8;
  local_100 = (uint)(byte)(local_100._0_1_ + cVar1) << 0x18 | local_100._1_3_ & 0xffff0000 |
              (uint)local_100._2_2_;
  local_104._0_1_ = (char)(DAT_803deec0 >> 0x18);
  local_104._1_1_ = (char)((DAT_803deec0 & 0xffffff) >> 0x10);
  local_104._2_2_ = (ushort)(DAT_803deec0 & 0xffffff);
  local_104._1_3_ = CONCAT12(local_104._1_1_ + cVar2,local_104._2_2_);
  local_104._2_1_ = (char)((uint)local_104._1_3_ >> 8);
  local_104._2_2_ = local_104._2_2_ & 0xff | (ushort)(byte)(local_104._2_1_ + cVar3) << 8;
  local_104 = (uint)(byte)(local_104._0_1_ + cVar1) << 0x18 | local_104._1_3_ & 0xffff0000 |
              (uint)local_104._2_2_;
  local_108._0_1_ = (char)(DAT_803deec4 >> 0x18);
  local_108._1_1_ = (char)((DAT_803deec4 & 0xffffff) >> 0x10);
  local_108._2_2_ = (ushort)(DAT_803deec4 & 0xffffff);
  local_108._1_3_ = CONCAT12(local_108._1_1_ + (char)((int)(uint)param_4[1] >> 3),local_108._2_2_);
  local_108._2_1_ = (char)((uint)local_108._1_3_ >> 8);
  local_108._2_2_ =
       local_108._2_2_ & 0xff |
       (ushort)(byte)(local_108._2_1_ + (char)((int)(uint)param_4[2] >> 3)) << 8;
  local_108 = (uint)(byte)(local_108._0_1_ + (char)((int)(uint)*param_4 >> 3)) << 0x18 |
              local_108._1_3_ & 0xffff0000 | (uint)local_108._2_2_;
  FUN_8000eb88((double)(*param_3 - FLOAT_803dcdd8),(double)param_3[1],
               (double)(param_3[2] - FLOAT_803dcddc),param_1,&local_e4,&local_e8,&local_ec,&local_f0
               ,&local_f4,auStack248);
  local_ec = local_ec + FLOAT_803deee4;
  FUN_80285fb4((double)(FLOAT_803def08 * local_ec));
  local_fc = local_fc & 0xffffff00 | (uint)extraout_var;
  FUN_8006c6f0(0);
  FUN_8006c5d8(&local_dc);
  FUN_8004c2e4(local_dc,1);
  FUN_8006c540(&local_e0);
  FUN_8004c2e4(local_e0,2);
  FUN_8025bf50(1,0,0,0,3);
  FUN_8025bf50(2,1,1,1,3);
  FUN_8025bf50(3,2,2,2,3);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_80257f10(1,1,4,0x3c,0,0x7d);
  FUN_802472e4((double)(FLOAT_803deef8 * -local_e4 - FLOAT_803deef8),
               (double)(FLOAT_803deef8 * local_e8 - FLOAT_803deef8),(double)FLOAT_803deedc,
               auStack144);
  FUN_80247318((double)(FLOAT_803db6c4 / local_f0),(double)(FLOAT_803db6c4 / local_f4),
               (double)FLOAT_803deedc,auStack192);
  FUN_80246eb4(auStack192,auStack144,auStack96);
  FUN_802472e4((double)FLOAT_803deef8,(double)FLOAT_803deef8,(double)FLOAT_803deedc,auStack144);
  FUN_80246eb4(auStack144,auStack96,auStack96);
  FUN_8025d160(auStack96,0x1e,1);
  FUN_80257f10(2,1,4,0x1e,0,0x7d);
  dVar7 = (double)(float)((double)FLOAT_803db6c8 / param_1);
  if ((double)FLOAT_803deedc < dVar7) {
    dVar6 = 1.0 / SQRT(dVar7);
    dVar6 = DOUBLE_803def10 * dVar6 * -(dVar7 * dVar6 * dVar6 - DOUBLE_803def18);
    dVar6 = DOUBLE_803def10 * dVar6 * -(dVar7 * dVar6 * dVar6 - DOUBLE_803def18);
    dVar7 = (double)(float)(dVar7 * DOUBLE_803def10 * dVar6 *
                                    -(dVar7 * dVar6 * dVar6 - DOUBLE_803def18));
  }
  if (dVar7 <= (double)FLOAT_803deee4) {
    local_100 = local_100 & 0xffffff00 | (int)((double)FLOAT_803def20 * dVar7) & 0xffU;
  }
  else {
    local_100 = CONCAT31(local_100._0_3_,0xff);
  }
  fVar4 = (float)(dVar7 * (double)FLOAT_803deee0);
  if (FLOAT_803deee4 < (float)(dVar7 * (double)FLOAT_803deee0)) {
    fVar4 = FLOAT_803deee4;
  }
  local_30 = (longlong)(int)(FLOAT_803def20 * fVar4);
  local_108 = local_108 & 0xffffff00 | (int)(FLOAT_803def20 * fVar4) & 0xffU;
  local_110 = local_fc;
  FUN_8025bdac(0,&local_110);
  local_114 = local_100;
  FUN_8025bdac(1,&local_114);
  local_118 = local_104;
  FUN_8025bdac(2,&local_118);
  local_11c = local_108;
  FUN_8025bcc4(1,&local_11c);
  FUN_8006c534(&local_10c);
  FUN_8004c2e4(local_10c,3);
  local_d8 = (float)((double)FLOAT_803db6cc / param_1);
  if (FLOAT_803deef8 < (float)((double)FLOAT_803db6cc / param_1)) {
    local_d8 = FLOAT_803deef8;
  }
  local_d4 = FLOAT_803deedc;
  local_d0 = FLOAT_803deedc;
  local_cc = FLOAT_803deedc;
  local_c4 = FLOAT_803deedc;
  local_c8 = local_d8;
  FUN_802472e4((double)(FLOAT_803deef8 * -local_e4 - FLOAT_803deef8),
               (double)(FLOAT_803deef8 * local_e8 - FLOAT_803deef8),auStack144);
  FUN_80247318((double)FLOAT_803def24,(double)FLOAT_803def24,(double)FLOAT_803deedc,auStack192);
  FUN_802470c8(param_2,auStack96,0x7a);
  FUN_80246eb4(auStack192,auStack144,auStack192);
  FUN_80246eb4(auStack96,auStack192,auStack96);
  FUN_802472e4((double)FLOAT_803deef8,(double)FLOAT_803deef8,(double)FLOAT_803deedc,auStack144);
  FUN_80246eb4(auStack144,auStack96,auStack96);
  FUN_8025d160(auStack96,0x21,1);
  FUN_80257f10(3,1,4,0x21,0,0x7d);
  FUN_8025b5b8(0,3,3);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_d8,1);
  FUN_8025b1e8(2,0,0,7,1,0,0,0,0,0);
  FUN_8025b1e8(3,0,0,7,1,0,0,0,0,0);
  FUN_8025b1e8(4,0,0,7,1,0,0,0,0,0);
  FUN_802581e0(4);
  FUN_8025b6f0(1);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_8025c2a0(6);
  FUN_8025be8c(0,0x1c);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,1,1,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  FUN_8025bac0(0,4,7,7,6);
  FUN_8025bef8(0,0,1);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,1,0,2,1,3);
  FUN_8025be8c(1,0x1c);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,1,1,0xff);
  FUN_8025ba40(1,0xf,0xf,0xf,0xf);
  FUN_8025bac0(1,6,7,7,4);
  FUN_8025bef8(1,0,1);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,1,0,2,1,0);
  FUN_8025be20(2,0xc);
  FUN_8025c0c4(2,0,0,0xff);
  FUN_8025ba40(2,0xf,8,0xe,2);
  FUN_8025bac0(2,7,0,1,7);
  FUN_8025bef8(2,0,1);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,2,1,0);
  FUN_8025be20(3,0xd);
  FUN_8025be8c(3,0x1d);
  FUN_8025c0c4(3,0,0,0xff);
  FUN_8025ba40(3,0xf,8,0xe,0);
  FUN_8025bac0(3,7,3,6,7);
  FUN_8025bef8(3,0,2);
  FUN_8025bb44(3,0,0,0,1,0);
  FUN_8025bc04(3,0,0,2,1,3);
  FUN_8025be20(4,0xe);
  FUN_8025c0c4(4,0,0,0xff);
  FUN_8025ba40(4,0xf,8,0xe,0);
  FUN_8025bac0(4,3,7,7,0);
  FUN_8025bef8(4,0,3);
  FUN_8025bb44(4,0,0,0,1,0);
  FUN_8025bc04(4,0,0,2,1,0);
  FUN_8025b71c(5);
  FUN_8025c0c4(5,2,2,0xff);
  FUN_8025ba40(5,0xf,0xf,0xf,0);
  FUN_8025bac0(5,4,7,0,7);
  FUN_8025bef8(5,0,0);
  FUN_8025bb44(5,0,0,0,1,0);
  FUN_8025bc04(5,0,0,0,1,0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
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
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return;
}

