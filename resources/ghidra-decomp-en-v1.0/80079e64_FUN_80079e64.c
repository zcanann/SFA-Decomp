// Function: FUN_80079e64
// Entry: 80079e64
// Size: 2232 bytes

/* WARNING: Removing unreachable block (ram,0x8007a6f4) */
/* WARNING: Removing unreachable block (ram,0x8007a6e4) */
/* WARNING: Removing unreachable block (ram,0x8007a6d4) */
/* WARNING: Removing unreachable block (ram,0x8007a6dc) */
/* WARNING: Removing unreachable block (ram,0x8007a6ec) */
/* WARNING: Removing unreachable block (ram,0x8007a6fc) */

void FUN_80079e64(double param_1,double param_2,double param_3,byte param_4,float *param_5,
                 byte param_6,byte param_7)

{
  int iVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f26;
  double dVar4;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar5;
  uint local_f8;
  uint local_f4;
  uint local_f0;
  uint local_ec;
  uint local_e8;
  uint local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined auStack216 [48];
  undefined auStack168 [48];
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  local_e8 = local_e8 & 0xffffff00 | (uint)param_6;
  local_ec = local_ec & 0xffffff00 | (uint)param_7;
  uStack116 = FUN_8000fa90();
  uStack116 = uStack116 & 0xffff;
  local_78 = 0x43300000;
  dVar3 = (double)((float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803def00) -
                  FLOAT_803def54);
  dVar5 = (double)(float)(dVar3 / (double)FLOAT_803def58);
  uStack108 = FUN_8000fa70(dVar3);
  uStack108 = uStack108 & 0xffff;
  local_70 = 0x43300000;
  dVar3 = (double)((float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803def00) -
                  FLOAT_803def54);
  dVar4 = (double)(float)(dVar3 / (double)FLOAT_803def58);
  iVar1 = FUN_8002073c(dVar3);
  if (iVar1 == 0) {
    dVar3 = (double)FUN_80292194((double)(*param_5 / param_5[1]));
    dVar3 = (double)FUN_80021370((double)(float)(dVar3 - (double)FLOAT_803dd00c),
                                 (double)FLOAT_803def5c,(double)FLOAT_803db414);
    FLOAT_803dd00c = (float)((double)FLOAT_803dd00c + dVar3);
  }
  dVar3 = (double)FLOAT_803dd00c;
  local_e4 = local_e4 & 0xffffff00 | (uint)param_4;
  FUN_8006c5d8(&local_dc);
  FUN_8004c2e4(local_dc,0);
  FUN_8006c4f8(&local_e0);
  FUN_8004c2e4(local_e0,1);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_80247318((double)(float)((double)FLOAT_803def60 * param_2),
               (double)(float)((double)FLOAT_803def60 * param_2),(double)FLOAT_803deedc,auStack168);
  FUN_802472e4((double)(float)(dVar5 * param_3),(double)(float)(dVar4 * param_3 + param_1),
               (double)FLOAT_803deedc,auStack216);
  FUN_80246eb4(auStack216,auStack168,auStack168);
  FUN_802470c8(dVar3,auStack216,0x7a);
  FUN_80246eb4(auStack168,auStack216,auStack168);
  FUN_802472e4((double)FLOAT_803deef4,(double)FLOAT_803deef4,(double)FLOAT_803deedc,auStack216);
  FUN_80246eb4(auStack168,auStack216,auStack168);
  FUN_8025d160(auStack168,0x1e,1);
  FUN_80257f10(1,1,4,0x1e,0,0x7d);
  FUN_80247318((double)(float)((double)FLOAT_803def64 * param_2),
               (double)(float)((double)FLOAT_803def64 * param_2),(double)FLOAT_803deedc,auStack168);
  FUN_802472e4((double)(float)((double)(float)((double)FLOAT_803deee0 * dVar5) * param_3),
               (double)(float)((double)FLOAT_803def68 * param_1 +
                              (double)(float)((double)(float)((double)FLOAT_803deee0 * dVar4) *
                                             param_3)),(double)FLOAT_803deedc,auStack216);
  FUN_80246eb4(auStack216,auStack168,auStack168);
  FUN_802470c8((double)(float)((double)FLOAT_803deef8 * dVar3),auStack216,0x7a);
  FUN_80246eb4(auStack168,auStack216,auStack168);
  FUN_802472e4((double)FLOAT_803deef4,(double)FLOAT_803deef4,(double)FLOAT_803deedc,auStack216);
  FUN_80246eb4(auStack168,auStack216,auStack168);
  FUN_8025d160(auStack168,0x21,1);
  FUN_80257f10(2,1,4,0x21,0,0x7d);
  local_f0 = local_e8;
  FUN_8025bdac(0,&local_f0);
  FUN_8025be8c(0,0x1c);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  FUN_8025bac0(0,6,7,7,4);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,1,0,2,1,0);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,1,1,0xff);
  FUN_8025ba40(1,8,0xf,0xf,0xf);
  FUN_8025bac0(1,7,0,4,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,1,1,0);
  local_f4 = local_ec;
  FUN_8025bdac(1,&local_f4);
  FUN_8025be8c(2,0x1d);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,0,0,0xff);
  FUN_8025ba40(2,0xf,0xf,0xf,0xf);
  FUN_8025bac0(2,6,7,7,4);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,1);
  FUN_8025bc04(2,1,0,2,1,1);
  FUN_8025b71c(3);
  FUN_8025c0c4(3,2,1,0xff);
  FUN_8025ba40(3,8,0xf,0xf,0xf);
  FUN_8025bac0(3,7,1,4,7);
  FUN_8025bef8(3,0,0);
  FUN_8025bb44(3,0,0,0,1,1);
  FUN_8025bc04(3,0,0,2,1,1);
  FUN_8025be8c(4,0);
  FUN_8025b71c(4);
  FUN_8025c0c4(4,0xff,0xff,0xff);
  FUN_8025ba40(4,0,2,3,0xf);
  FUN_8025bac0(4,0,6,1,7);
  FUN_8025bef8(4,0,0);
  FUN_8025bb44(4,0,0,0,1,0);
  FUN_8025bc04(4,0,0,0,1,0);
  local_f8 = local_e4;
  FUN_8025bdac(2,&local_f8);
  FUN_8025be8c(5,0x1e);
  FUN_8025b71c(5);
  FUN_8025c0c4(5,0xff,0xff,0xff);
  FUN_8025ba40(5,0xf,0xf,0xf,0);
  FUN_8025bac0(5,7,0,6,7);
  FUN_8025bef8(5,0,0);
  FUN_8025bb44(5,0,0,0,1,0);
  FUN_8025bc04(5,0,0,0,1,0);
  FUN_802581e0(3);
  FUN_8025c2a0(6);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802573f8();
  FUN_8025d124(0x3c);
  FUN_80256978(9,1);
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
  FUN_8025d124(0);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  __psq_l0(auStack56,uVar2);
  __psq_l1(auStack56,uVar2);
  __psq_l0(auStack72,uVar2);
  __psq_l1(auStack72,uVar2);
  __psq_l0(auStack88,uVar2);
  __psq_l1(auStack88,uVar2);
  return;
}

