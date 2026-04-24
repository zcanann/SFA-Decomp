// Function: FUN_8011e0d8
// Entry: 8011e0d8
// Size: 1464 bytes

/* WARNING: Removing unreachable block (ram,0x8011e670) */

undefined4 FUN_8011e0d8(int param_1,undefined4 *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  double dVar4;
  undefined4 local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined auStack216 [48];
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  undefined auStack120 [8];
  float local_70;
  float local_60;
  undefined auStack72 [12];
  float local_3c;
  float local_2c;
  float local_1c;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_f8 = DAT_803e1e30;
  local_f0 = DAT_802c21ac;
  local_ec = DAT_802c21b0;
  local_e8 = DAT_802c21b4;
  local_e4 = DAT_802c21b8;
  local_e0 = DAT_802c21bc;
  local_dc = DAT_802c21c0;
  uVar1 = FUN_80028424(*param_2,param_3);
  puVar2 = (undefined4 *)FUN_8004c250(uVar1,0);
  uVar1 = FUN_800536c0(*puVar2);
  FUN_80246e80(&DAT_803a8950,auStack72);
  local_3c = FLOAT_803e1e3c;
  local_2c = FLOAT_803e1e3c;
  local_1c = FLOAT_803e1e3c;
  FUN_80247318((double)(FLOAT_803e1e64 / FLOAT_803dd80c),(double)(FLOAT_803e1e64 / FLOAT_803dd80c),
               (double)(FLOAT_803e1e68 / FLOAT_803dd80c),auStack120);
  local_70 = FLOAT_803e1e6c / FLOAT_803dd80c;
  local_60 = local_70;
  FUN_80246eb4(auStack120,auStack72,auStack72);
  FUN_8025d160(auStack72,0x1e,1);
  FUN_802581e0(3);
  FUN_8025c2a0(3);
  FUN_8025b6f0(2);
  FUN_80259e58(1);
  FUN_8025b5b8(0,0,2);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_f0,0);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  FUN_8004c2e4(uVar1,0);
  FUN_80257f10(0,1,1,0x1e,0,0x7d);
  FUN_8025c0c4(0,0,0,4);
  FUN_8025ba40(0,0xf,0xf,0xf,10);
  FUN_8025bac0(0,7,7,7,5);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  local_fc = local_f8;
  FUN_80259cf0(4,&local_fc);
  FUN_8025b5b8(1,0,2);
  FUN_8025b3e4(1,0,0);
  FUN_8025b1e8(1,1,0,7,1,0,0,1,0,0);
  FUN_80246eb4(&DAT_80396820,&DAT_803a8950,auStack72);
  dVar4 = (double)(FLOAT_803e1e70 * FLOAT_803dd850 * FLOAT_803dd850);
  FUN_80247318(dVar4,dVar4,(double)FLOAT_803e1e68,auStack216);
  FUN_80246eb4(auStack216,auStack72,auStack72);
  dVar4 = (double)(FLOAT_803e1e70 * (float)((double)FLOAT_803e1e68 - dVar4));
  FUN_802472e4(dVar4,dVar4,(double)FLOAT_803e1e3c,auStack216);
  FUN_80246eb4(auStack216,auStack72,auStack72);
  FUN_8025d160(auStack72,0x21,0);
  FUN_80257f10(1,0,0,0x21,0,0x7d);
  FUN_8025c0c4(1,1,0,0xff);
  FUN_8025ba40(1,0xf,0xf,0xf,8);
  FUN_8025bac0(1,7,7,7,0);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  local_a8 = FLOAT_803dbb14;
  local_a4 = FLOAT_803e1e3c;
  local_a0 = FLOAT_803e1e3c;
  local_9c = FLOAT_803e1e70;
  local_98 = FLOAT_803e1e3c;
  local_94 = FLOAT_803dbb14;
  local_90 = FLOAT_803e1e3c;
  local_8c = FLOAT_803e1e70;
  local_88 = FLOAT_803e1e3c;
  local_84 = FLOAT_803e1e3c;
  local_80 = FLOAT_803e1e3c;
  local_7c = FLOAT_803e1e68;
  FUN_8025d160(&local_a8,0x24,1);
  FUN_80257f10(2,1,1,0x24,0,0x7d);
  FUN_8006c5cc(&local_f4);
  FUN_8004c2e4(local_f4,1);
  FUN_8025be8c(2,0x1c);
  local_100 = DAT_803dbb10;
  FUN_8025bdac(0,&local_100);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,2,1,0xff);
  FUN_8025ba40(2,0xf,0xf,0xf,0);
  FUN_8025bac0(2,7,4,6,0);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,1,0,0,1,0);
  if (*(short *)(param_1 + 0x46) == 0x755) {
    FUN_80258b24(1);
  }
  else {
    FUN_80258b24(2);
  }
  FUN_8025c584(1,4,5,5);
  FUN_80070310(0,7,0);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(10,1);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return 1;
}

