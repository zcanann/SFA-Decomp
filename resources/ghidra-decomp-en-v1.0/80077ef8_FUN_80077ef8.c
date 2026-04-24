// Function: FUN_80077ef8
// Entry: 80077ef8
// Size: 2120 bytes

/* WARNING: Removing unreachable block (ram,0x80078718) */
/* WARNING: Removing unreachable block (ram,0x80078720) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_80077ef8(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  uint3 uVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  int unaff_r31;
  undefined4 uVar6;
  double extraout_f1;
  double dVar7;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar8;
  undefined8 uVar9;
  undefined4 local_178;
  uint local_174;
  uint local_170;
  undefined4 local_16c;
  undefined4 local_168;
  undefined4 local_164;
  undefined4 local_160;
  undefined4 local_15c;
  undefined2 local_158;
  undefined local_156;
  undefined4 local_154;
  undefined4 local_150;
  float local_14c;
  undefined4 local_148 [4];
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  undefined4 local_12c [4];
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110 [4];
  undefined4 local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4 [4];
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8 [4];
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc [4];
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined auStack160 [48];
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar9 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  local_bc[0] = DAT_802c1ec0;
  local_bc[1] = DAT_802c1ec4;
  local_bc[2] = DAT_802c1ec8;
  local_bc[3] = DAT_802c1ecc;
  local_ac = DAT_802c1ed0;
  local_a8 = DAT_802c1ed4;
  local_a4 = DAT_802c1ed8;
  local_d8[0] = DAT_802c1edc;
  local_d8[1] = DAT_802c1ee0;
  local_d8[2] = DAT_802c1ee4;
  local_d8[3] = DAT_802c1ee8;
  local_c8 = DAT_802c1eec;
  local_c4 = DAT_802c1ef0;
  local_c0 = DAT_802c1ef4;
  local_f4[0] = DAT_802c1ef8;
  local_f4[1] = DAT_802c1efc;
  local_f4[2] = DAT_802c1f00;
  local_f4[3] = DAT_802c1f04;
  local_e4 = DAT_802c1f08;
  local_e0 = DAT_802c1f0c;
  local_dc = DAT_802c1f10;
  local_110[0] = DAT_802c1f14;
  local_110[1] = DAT_802c1f18;
  local_110[2] = DAT_802c1f1c;
  local_110[3] = DAT_802c1f20;
  local_100 = DAT_802c1f24;
  local_fc = DAT_802c1f28;
  local_f8 = DAT_802c1f2c;
  local_12c[0] = DAT_802c1f30;
  local_12c[1] = DAT_802c1f34;
  local_12c[2] = DAT_802c1f38;
  local_12c[3] = DAT_802c1f3c;
  local_11c = DAT_802c1f40;
  local_118 = DAT_802c1f44;
  local_114 = DAT_802c1f48;
  local_148[0] = DAT_802c1f4c;
  local_148[1] = DAT_802c1f50;
  local_148[2] = DAT_802c1f54;
  local_148[3] = DAT_802c1f58;
  local_138 = DAT_802c1f5c;
  local_134 = DAT_802c1f60;
  local_130 = DAT_802c1f64;
  local_15c = DAT_803deeac;
  local_158 = DAT_803deeb0;
  local_156 = DAT_803deeb2;
  local_16c = DAT_803e8450;
  dVar7 = extraout_f1;
  FUN_80246eb4(iVar3,param_3,&local_70);
  FUN_8025d160(&local_70,0x1e,1);
  FUN_80257f10(0,1,0,0x1e,0,0x7d);
  FUN_8004c2e4(*(undefined4 *)(iVar3 + 0x60),0);
  if (*(byte *)(iVar3 + 0x65) < 8) {
    FUN_8025bf50(1,0,0,0,0);
    unaff_r31 = *(byte *)(iVar3 + 0x65) - 1;
  }
  else if (*(byte *)(iVar3 + 0x65) < 0x10) {
    FUN_8025bf50(1,3,3,3,3);
    unaff_r31 = *(byte *)(iVar3 + 0x65) - 9;
  }
  if (unaff_r31 < 0) {
    unaff_r31 = 0;
  }
  local_164 = CONCAT13(0x7f,CONCAT12(0x7f,local_164._2_2_));
  local_164._2_2_ = CONCAT11(0x7f,(undefined)local_164);
  local_164 = local_164 & 0xffff0000 | (uint)local_164._2_2_;
  local_170 = local_164;
  FUN_8025bcc4(1,&local_170);
  *(char *)(iVar4 + 3) =
       (char)((int)(uint)*(byte *)(iVar4 + 3) >> 1) + (char)((int)(uint)*(byte *)(iVar4 + 3) >> 2);
  bVar1 = *(byte *)(iVar4 + 3);
  uVar2 = CONCAT12(bVar1,local_160._2_2_);
  local_160._2_2_ = local_160._2_2_ & 0xff | (ushort)bVar1 << 8;
  local_160 = (uint)bVar1 << 0x18 | uVar2 & 0xffff0000 | (uint)local_160._2_2_;
  local_174 = local_160;
  FUN_8025bdac(0,&local_174);
  bVar1 = *(byte *)((int)&local_15c + unaff_r31);
  cVar5 = bVar1 != 0;
  if ((bool)cVar5) {
    FUN_8025b71c(0);
    FUN_8025bef8(0,0,1);
    FUN_8025c0c4(0,0,0,0xff);
    FUN_8025ba40(0,0xf,8,0xc,local_bc[unaff_r31]);
    FUN_8025bac0(0,7,7,7,7);
    FUN_8025bb44(0,0,0,local_d8[unaff_r31],0,0);
    FUN_8025bc04(0,0,0,0,0,0);
  }
  if (1 < bVar1) {
    FUN_8025b71c(cVar5);
    FUN_8025bef8(cVar5,0,0);
    FUN_8025c0c4(cVar5,0xff,0xff,0xff);
    FUN_8025ba40(cVar5,0xf,0,0xc,local_f4[unaff_r31]);
    FUN_8025bac0(cVar5,7,7,7,7);
    FUN_8025bb44(cVar5,0,0,local_110[unaff_r31],0,0);
    FUN_8025bc04(cVar5,0,0,0,0,0);
    cVar5 = cVar5 + '\x01';
  }
  if (2 < bVar1) {
    FUN_8025b71c(cVar5);
    FUN_8025bef8(cVar5,0,0);
    FUN_8025c0c4(cVar5,0xff,0xff,0xff);
    FUN_8025ba40(cVar5,0xf,0,0xc,local_12c[unaff_r31]);
    FUN_8025bac0(cVar5,7,7,7,7);
    FUN_8025bb44(cVar5,0,0,local_148[unaff_r31],0,0);
    FUN_8025bc04(cVar5,0,0,0,0,0);
    cVar5 = cVar5 + '\x01';
  }
  FUN_8025b71c(cVar5);
  FUN_8025bef8(cVar5,0,0);
  FUN_8025be20(cVar5,0xc);
  FUN_8025c0c4(cVar5,0xff,0xff,0xff);
  if (bVar1 == 0) {
    FUN_8025ba40(cVar5,8,2,0xe,0xf);
  }
  else {
    FUN_8025ba40(cVar5,0,2,0xe,0xf);
  }
  FUN_8025bac0(cVar5,7,7,7,7);
  FUN_8025bb44(cVar5,8,0,0,1,0);
  FUN_8025bc04(cVar5,0,0,0,1,0);
  local_154 = *(undefined4 *)(param_3 + 0xc);
  local_150 = *(undefined4 *)(param_3 + 0x1c);
  local_14c = *(float *)(param_3 + 0x2c);
  FUN_80247494(iVar3 + 0x30,&local_154,&local_154);
  dVar8 = -(double)local_14c;
  FUN_8006c5b8(&local_168);
  FUN_8004c2e4(local_168,1);
  local_70 = FLOAT_803deedc;
  local_6c = FLOAT_803deedc;
  dVar7 = (double)(float)(dVar8 - (double)(float)(dVar8 - dVar7));
  local_68 = (float)((double)FLOAT_803deee4 / dVar7);
  local_64 = (float)(dVar8 / dVar7);
  local_60 = FLOAT_803deedc;
  local_5c = FLOAT_803deedc;
  local_58 = FLOAT_803deedc;
  local_54 = FLOAT_803deedc;
  FUN_80246eb4(iVar3 + 0x30,param_3,auStack160);
  FUN_80246eb4(&local_70,auStack160,auStack160);
  FUN_8025d160(auStack160,0x21,1);
  FUN_80257f10(1,1,0,0x21,0,0x7d);
  FUN_8025b71c(cVar5 + '\x01');
  FUN_8025bef8(cVar5 + '\x01',0,0);
  FUN_8025c0c4(cVar5 + '\x01',1,1,0xff);
  FUN_8025ba40(cVar5 + '\x01',0,0xf,8,0xf);
  FUN_8025bac0(cVar5 + '\x01',7,7,7,7);
  FUN_8025bb44(cVar5 + '\x01',0,0,0,1,0);
  FUN_8025bc04(cVar5 + '\x01',0,0,0,1,0);
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(2);
  FUN_8025c2a0(bVar1 + 2);
  local_178 = local_16c;
  FUN_8025c2d4((double)FLOAT_803dd024,(double)FLOAT_803dd020,(double)FLOAT_803dd038,
               (double)FLOAT_803dd034,4,&local_178);
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
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  FUN_80286124();
  return;
}

