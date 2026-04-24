// Function: FUN_80074d04
// Entry: 80074d04
// Size: 1716 bytes

/* WARNING: Removing unreachable block (ram,0x80075394) */

undefined4 FUN_80074d04(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  uint local_12c;
  uint local_128;
  float local_124;
  float local_120;
  undefined4 local_11c;
  undefined4 local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  undefined auStack228 [48];
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  undefined auStack132 [12];
  float local_78;
  float local_68;
  undefined auStack84 [12];
  float local_48;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar1 = FUN_8000f54c();
  if (param_2 == 0) {
    dVar4 = (double)FLOAT_803deee4;
  }
  else {
    uVar2 = FUN_8002856c(param_2,0);
    FUN_80246eb4(uVar1,uVar2,&local_b4);
    dVar5 = (double)(local_88 * local_88 + local_a8 * local_a8 + local_98 * local_98);
    if ((double)FLOAT_803deedc < dVar5) {
      dVar4 = 1.0 / SQRT(dVar5);
      dVar4 = DOUBLE_803def10 * dVar4 * -(dVar5 * dVar4 * dVar4 - DOUBLE_803def18);
      dVar4 = DOUBLE_803def10 * dVar4 * -(dVar5 * dVar4 * dVar4 - DOUBLE_803def18);
      dVar5 = (double)(float)(dVar5 * DOUBLE_803def10 * dVar4 *
                                      -(dVar5 * dVar4 * dVar4 - DOUBLE_803def18));
    }
    dVar4 = (double)(float)((double)FLOAT_803def3c / dVar5);
    if ((double)FLOAT_803deee4 < (double)(float)((double)FLOAT_803def3c / dVar5)) {
      dVar4 = (double)FLOAT_803deee4;
    }
  }
  FUN_8006c6f0(0);
  FUN_8025d160(&DAT_80396820,0x52,0);
  FUN_80257f10(0,0,0,0,0,0x52);
  FUN_8006cabc(&local_120,&local_124);
  local_120 = local_120 * FLOAT_803def2c;
  local_124 = local_124 * FLOAT_803def2c;
  FUN_8006c5e4(&local_118);
  FUN_8004c2e4(local_118,1);
  dVar5 = (double)FLOAT_803def2c;
  FUN_80247318(dVar5,dVar5,dVar5,auStack84);
  local_48 = local_120;
  FUN_8025d160(auStack84,0x21,1);
  FUN_80257f10(1,1,4,0x21,0,0x7d);
  local_fc = (float)((double)FLOAT_803deef8 * dVar4);
  local_f8 = FLOAT_803deedc;
  local_f4 = FLOAT_803deedc;
  local_f0 = FLOAT_803deedc;
  local_e8 = FLOAT_803deedc;
  local_ec = local_fc;
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_fc,0xfffffffc);
  FUN_8025b1e8(0,0,0,7,1,6,6,0,0,0);
  dVar5 = (double)FLOAT_803def40;
  FUN_80247318(dVar5,dVar5,dVar5,auStack132);
  FUN_802470c8((double)FLOAT_803deef0,auStack228,0x7a);
  FUN_80246eb4(auStack228,auStack132,auStack132);
  local_78 = local_124;
  local_68 = local_124;
  FUN_8025d160(auStack132,0x24,1);
  FUN_80257f10(2,1,4,0x24,0,0x7d);
  local_114 = (float)((double)FLOAT_803def44 * dVar4);
  local_10c = FLOAT_803deedc;
  local_108 = (float)((double)FLOAT_803def48 * dVar4);
  local_100 = FLOAT_803deedc;
  local_110 = local_114;
  local_104 = local_114;
  FUN_8025b5b8(1,2,1);
  FUN_8025b3e4(1,0,0);
  FUN_8025b284(2,&local_114,0xfffffffc);
  FUN_8025b1e8(1,1,0,7,2,0,0,1,0,0);
  local_b4 = FLOAT_803db6ac;
  local_b0 = FLOAT_803deedc;
  local_ac = FLOAT_803deedc;
  local_a8 = FLOAT_803deef8;
  local_a4 = FLOAT_803deedc;
  local_a0 = FLOAT_803db6ac;
  local_9c = FLOAT_803deedc;
  local_98 = FLOAT_803deef8;
  local_94 = FLOAT_803deedc;
  local_90 = FLOAT_803deedc;
  local_8c = FLOAT_803deedc;
  local_88 = FLOAT_803deee4;
  FUN_8025d160(&local_b4,0x55,0);
  FUN_80257f10(3,0,1,0x1e,0,0x55);
  FUN_8006c5cc(&local_11c);
  FUN_8004c2e4(local_11c,2);
  FUN_8025b6f0(2);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(4);
  FUN_8025c2a0(3);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025c0c4(1,0,0,0xff);
  FUN_8025ba40(1,0xf,0xf,0xf,8);
  FUN_8025bac0(1,7,7,7,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  local_128 = local_128 & 0xffffff00 | (uint)*(byte *)(param_1 + 0x37);
  local_12c = local_128;
  FUN_8025bdac(0,&local_12c);
  FUN_8025be8c(2,0x1c);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,3,2,0xff);
  FUN_8025ba40(2,0xf,0xf,0xf,0);
  FUN_8025bac0(2,7,4,6,7);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  FUN_8025c584(1,4,5,5);
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(2);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return 1;
}

