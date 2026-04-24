// Function: FUN_80096c94
// Entry: 80096c94
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x80096f74) */
/* WARNING: Removing unreachable block (ram,0x80096f64) */
/* WARNING: Removing unreachable block (ram,0x80096f54) */
/* WARNING: Removing unreachable block (ram,0x80096f5c) */
/* WARNING: Removing unreachable block (ram,0x80096f6c) */
/* WARNING: Removing unreachable block (ram,0x80096f7c) */

void FUN_80096c94(undefined4 param_1,undefined4 param_2,uint param_3,int param_4,ushort param_5)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  double extraout_f1;
  undefined8 in_f26;
  double dVar7;
  undefined8 in_f27;
  double dVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined2 local_f8;
  undefined2 local_f6;
  undefined2 local_f4;
  undefined auStack240 [2];
  undefined2 local_ee;
  ushort local_ec;
  undefined2 local_ea;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
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
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a0;
  uint uStack156;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
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
  uVar13 = FUN_802860c4();
  uVar4 = (undefined4)((ulonglong)uVar13 >> 0x20);
  local_d8 = DAT_802c212c;
  local_d4 = DAT_802c2130;
  local_d0 = DAT_802c2134;
  local_cc = DAT_802c2138;
  local_c8 = DAT_802c213c;
  local_c4 = DAT_802c2140;
  local_c0 = DAT_802c2144;
  local_bc = DAT_802c2148;
  local_b8 = DAT_802c214c;
  local_b4 = DAT_802c2150;
  local_b0 = DAT_802c2154;
  local_ac = DAT_802c2158;
  local_a8 = DAT_802c215c;
  uVar3 = (uint)DAT_803db410;
  if (3 < uVar3) {
    uVar3 = 3;
  }
  uVar1 = (uint)uVar13 & 0xff;
  param_5 = param_5 & 0xff;
  dVar8 = (double)FLOAT_803df368;
  dVar9 = (double)FLOAT_803df354;
  dVar10 = (double)FLOAT_803df35c;
  dVar11 = extraout_f1;
  dVar12 = DOUBLE_803df360;
  for (iVar5 = 0; iVar5 < (int)(uVar3 * (param_3 & 0xff)); iVar5 = iVar5 + 1) {
    uStack156 = FUN_800221a0(0,1000);
    uStack156 = uStack156 ^ 0x80000000;
    local_a0 = 0x43300000;
    dVar7 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack156) - dVar12) / dVar8
                           );
    local_f8 = FUN_800221a0(0,0xffff);
    local_f6 = FUN_800221a0(0,0xffff);
    local_f4 = FUN_800221a0(0,0xffff);
    local_e4 = (float)(dVar11 * -(double)(float)(dVar7 * (double)(float)(dVar7 * dVar7) - dVar9));
    local_e0 = (float)dVar10;
    local_dc = (float)dVar10;
    FUN_80021ac8(&local_f8,&local_e4);
    if (param_4 != 0) {
      local_e4 = local_e4 + *(float *)(param_4 + 0xc);
      local_e0 = local_e0 + *(float *)(param_4 + 0x10);
      local_dc = local_dc + *(float *)(param_4 + 0x14);
    }
    local_ea = *(undefined2 *)(&local_d8 + uVar1);
    local_ee = *(undefined2 *)((int)&local_d8 + uVar1 * 4 + 2);
    local_e8 = (float)dVar9;
    local_ec = param_5;
    if ((uVar1 < 9) || (0xb < uVar1)) {
      (**(code **)(*DAT_803dca88 + 8))(uVar4,0x7e2,auStack240,2,0xffffffff,0);
    }
    else {
      if ((uVar1 == 0xb) || (uVar1 == 10)) {
        (**(code **)(*DAT_803dca88 + 8))(uVar4,0x7e3,auStack240,2,0xffffffff,0);
      }
      uVar2 = (uint)uVar13 & 0xff;
      if ((uVar2 == 0xb) || (uVar2 == 9)) {
        (**(code **)(*DAT_803dca88 + 8))(uVar4,0x7e4,auStack240,2,0xffffffff,0);
      }
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  __psq_l0(auStack72,uVar6);
  __psq_l1(auStack72,uVar6);
  __psq_l0(auStack88,uVar6);
  __psq_l1(auStack88,uVar6);
  FUN_80286110();
  return;
}

