// Function: FUN_80097734
// Entry: 80097734
// Size: 1020 bytes

/* WARNING: Removing unreachable block (ram,0x80097b08) */
/* WARNING: Removing unreachable block (ram,0x80097af8) */
/* WARNING: Removing unreachable block (ram,0x80097af0) */
/* WARNING: Removing unreachable block (ram,0x80097b00) */
/* WARNING: Removing unreachable block (ram,0x80097b10) */

void FUN_80097734(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,int param_10,
                 uint param_11)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  double extraout_f1;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined8 uVar9;
  undefined2 local_f8;
  undefined2 local_f6;
  undefined2 local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined2 local_b0;
  undefined2 local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
  undefined2 local_a6;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  undefined4 local_90;
  uint uStack140;
  double local_88;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
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
  uVar9 = FUN_802860c4();
  local_c0 = DAT_802c2064;
  local_bc = DAT_802c2068;
  local_b8 = DAT_802c206c;
  local_b4 = DAT_802c2070;
  local_b0 = DAT_802c2074;
  local_d0 = DAT_802c2078;
  local_cc = DAT_802c207c;
  local_c8 = DAT_802c2080;
  local_c4 = DAT_802c2084;
  local_e0 = DAT_802c2088;
  local_dc = DAT_802c208c;
  local_d8 = DAT_802c2090;
  local_d4 = DAT_802c2094;
  local_f0 = DAT_802c2098;
  local_ec = DAT_802c209c;
  local_e8 = DAT_802c20a0;
  local_e4 = DAT_802c20a4;
  local_a4 = (float)extraout_f1;
  local_a6 = *(undefined2 *)((int)&local_c0 + (param_7 & 0xff) * 2);
  local_aa = 0x3c;
  iVar4 = 0;
  dVar8 = (double)(float)(param_2 - param_3);
  iVar1 = ((uint)uVar9 & 0xff) * 2;
  do {
    iVar2 = FUN_800221a0(0,99);
    if (iVar2 < (int)(param_9 & 0xff)) {
      local_f8 = FUN_800221a0(0,0xffff);
      local_f6 = 0;
      local_f4 = 0;
      uStack140 = FUN_800221a0(1,1000);
      uStack140 = uStack140 ^ 0x80000000;
      local_90 = 0x43300000;
      dVar7 = (double)((float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803df360) /
                      FLOAT_803df368);
      uVar3 = FUN_800221a0(0,1000);
      local_88 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      dVar6 = (double)((float)(local_88 - DOUBLE_803df360) / FLOAT_803df368);
      local_9c = FLOAT_803df35c;
      local_98 = FLOAT_803df35c;
      switch(param_8 & 0xff) {
      case 1:
        local_a0 = -(float)(dVar7 * dVar7 - (double)FLOAT_803df354);
        break;
      case 2:
        dVar6 = (double)(float)(dVar6 * (double)(float)(dVar6 * dVar6));
        local_a0 = -(float)(dVar7 * dVar7 - (double)FLOAT_803df354);
        break;
      case 3:
        dVar6 = -(double)(float)(dVar6 * (double)(float)(dVar6 * dVar6) - (double)FLOAT_803df354);
        local_a0 = -(float)(dVar7 * dVar7 - (double)FLOAT_803df354);
        break;
      case 4:
        local_88 = (double)(longlong)(int)((double)FLOAT_803df350 * dVar6);
        uStack140 = (int)((double)FLOAT_803df350 * dVar6) & 0xffff;
        local_90 = 0x43300000;
        dVar6 = (double)FUN_80294204((double)((FLOAT_803df36c *
                                              (float)((double)CONCAT44(0x43300000,uStack140) -
                                                     DOUBLE_803df378)) / FLOAT_803df370));
        dVar6 = (double)(FLOAT_803df358 * (float)((double)FLOAT_803df354 + dVar6));
        local_a0 = -(float)(dVar7 * dVar7 - (double)FLOAT_803df354);
        break;
      case 5:
        local_88 = (double)(longlong)(int)((double)FLOAT_803df350 * dVar6);
        uStack140 = (int)((double)FLOAT_803df350 * dVar6) & 0xffff;
        local_90 = 0x43300000;
        dVar6 = (double)FUN_80293e80((double)((FLOAT_803df36c *
                                              (float)((double)CONCAT44(0x43300000,uStack140) -
                                                     DOUBLE_803df378)) / FLOAT_803df370));
        dVar6 = (double)(FLOAT_803df358 * (float)((double)FLOAT_803df354 + dVar6));
        local_a0 = -(float)(dVar7 * dVar7 - (double)FLOAT_803df354);
        break;
      case 6:
        local_a0 = (float)(dVar7 * dVar7);
        break;
      case 7:
        local_a0 = -(float)(dVar7 * (double)(float)(dVar7 * (double)(float)(dVar7 * (double)(float)(
                                                  dVar7 * dVar7))) - (double)FLOAT_803df354);
      }
      local_a0 = local_a0 * (float)(dVar6 * dVar8 + param_3);
      FUN_80021ac8(&local_f8,&local_a0);
      local_9c = (float)((double)(float)(dVar6 - (double)FLOAT_803df358) * param_4);
      if (param_10 != 0) {
        local_a0 = local_a0 + *(float *)(param_10 + 0xc);
        local_9c = local_9c + *(float *)(param_10 + 0x10);
        local_98 = local_98 + *(float *)(param_10 + 0x14);
      }
      local_a8 = *(undefined2 *)((int)&local_e0 + iVar1);
      local_ac = *(undefined2 *)((int)&local_f0 + iVar1);
      (**(code **)(*DAT_803dca88 + 8))
                ((int)((ulonglong)uVar9 >> 0x20),*(undefined2 *)((int)&local_d0 + iVar1),&local_ac,
                 param_11 | 2,0xffffffff,0);
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 < 4);
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  __psq_l0(auStack72,uVar5);
  __psq_l1(auStack72,uVar5);
  FUN_80286110();
  return;
}

