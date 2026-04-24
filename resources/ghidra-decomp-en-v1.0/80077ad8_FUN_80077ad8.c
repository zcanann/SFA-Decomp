// Function: FUN_80077ad8
// Entry: 80077ad8
// Size: 1056 bytes

/* WARNING: Removing unreachable block (ram,0x80077ecc) */
/* WARNING: Removing unreachable block (ram,0x80077ed4) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_80077ad8(double param_1,int param_2,int param_3,int param_4)

{
  byte bVar1;
  uint3 uVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar5;
  undefined4 local_b8;
  uint local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  float local_9c;
  undefined auStack152 [48];
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_b0 = DAT_803e8454;
  FUN_80246eb4(param_2,param_4,&local_68);
  FUN_8025d160(&local_68,0x1e,1);
  FUN_80257f10(0,1,0,0x1e,0,0x7d);
  FUN_8004c2e4(*(undefined4 *)(param_2 + 0x60),0);
  *(char *)(param_3 + 3) =
       (char)((int)(uint)*(byte *)(param_3 + 3) >> 1) +
       (char)((int)(uint)*(byte *)(param_3 + 3) >> 2);
  bVar1 = *(byte *)(param_3 + 3);
  uVar2 = CONCAT12(bVar1,local_a8._2_2_);
  local_a8._2_2_ = local_a8._2_2_ & 0xff | (ushort)bVar1 << 8;
  local_a8 = (uint)bVar1 << 0x18 | uVar2 & 0xffff0000 | (uint)local_a8._2_2_;
  local_b4 = local_a8;
  FUN_8025bdac(0,&local_b4);
  FUN_8025be20(0,0xc);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,8,0xe,0xf);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  local_a4 = *(undefined4 *)(param_4 + 0xc);
  local_a0 = *(undefined4 *)(param_4 + 0x1c);
  local_9c = *(float *)(param_4 + 0x2c);
  FUN_80247494(param_2 + 0x30,&local_a4,&local_a4);
  dVar5 = -(double)local_9c;
  FUN_8006c5b8(&local_ac);
  FUN_8004c2e4(local_ac,1);
  local_68 = FLOAT_803deedc;
  local_64 = FLOAT_803deedc;
  dVar4 = (double)(float)(dVar5 - (double)(float)(dVar5 - param_1));
  local_60 = (float)((double)FLOAT_803deee4 / dVar4);
  local_5c = (float)(dVar5 / dVar4);
  local_58 = FLOAT_803deedc;
  local_54 = FLOAT_803deedc;
  local_50 = FLOAT_803deedc;
  local_4c = FLOAT_803deedc;
  FUN_80246eb4(param_2 + 0x30,param_4,auStack152);
  FUN_80246eb4(&local_68,auStack152,auStack152);
  FUN_8025d160(auStack152,0x21,1);
  FUN_80257f10(1,1,0,0x21,0,0x7d);
  FUN_8025b71c(1);
  FUN_8025bef8(1,0,0);
  FUN_8025c0c4(1,1,1,0xff);
  FUN_8025ba40(1,0,0xf,8,0xf);
  FUN_8025bac0(1,7,7,7,7);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(2);
  FUN_8025c2a0(2);
  local_b8 = local_b0;
  FUN_8025c2d4((double)FLOAT_803dd024,(double)FLOAT_803dd020,(double)FLOAT_803dd038,
               (double)FLOAT_803dd034,4,&local_b8);
  FUN_8025c584(1,0,3,5);
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
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  return;
}

