// Function: FUN_80097b30
// Entry: 80097b30
// Size: 1140 bytes

/* WARNING: Removing unreachable block (ram,0x80097f7c) */
/* WARNING: Removing unreachable block (ram,0x80097f74) */
/* WARNING: Removing unreachable block (ram,0x80097f84) */

void FUN_80097b30(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,int param_10,
                 uint param_11)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double extraout_f1;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar9;
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
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined2 local_98;
  undefined2 local_94;
  undefined2 local_92;
  undefined2 local_90;
  undefined2 local_8e;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  double local_68;
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
  uVar9 = FUN_802860c8();
  local_a8 = DAT_802c2020;
  local_a4 = DAT_802c2024;
  local_a0 = DAT_802c2028;
  local_9c = DAT_802c202c;
  local_98 = DAT_802c2030;
  local_b8 = DAT_802c2034;
  local_b4 = DAT_802c2038;
  local_b0 = DAT_802c203c;
  local_ac = DAT_802c2040;
  local_c8 = DAT_802c2044;
  local_c4 = DAT_802c2048;
  local_c0 = DAT_802c204c;
  local_bc = DAT_802c2050;
  local_d8 = DAT_802c2054;
  local_d4 = DAT_802c2058;
  local_d0 = DAT_802c205c;
  local_cc = DAT_802c2060;
  local_8c = (float)extraout_f1;
  local_8e = *(undefined2 *)((int)&local_a8 + (param_7 & 0xff) * 2);
  local_92 = 0x3c;
  iVar4 = 0;
  iVar1 = ((uint)uVar9 & 0xff) * 2;
  do {
    iVar2 = FUN_800221a0(0,99);
    if (iVar2 < (int)(param_9 & 0xff)) {
      uStack116 = FUN_800221a0(0,1000);
      uStack116 = uStack116 ^ 0x80000000;
      local_78 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803df360) / FLOAT_803df368;
      uStack108 = FUN_800221a0(0,1000);
      uStack108 = uStack108 ^ 0x80000000;
      local_70 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803df360) / FLOAT_803df368;
      uVar3 = FUN_800221a0(0,1000);
      local_68 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_80 = (float)(local_68 - DOUBLE_803df360) / FLOAT_803df368;
      switch(param_8 & 0xff) {
      case 1:
        local_88 = local_88 - FLOAT_803df358;
        local_84 = local_84 - FLOAT_803df358;
        local_80 = local_80 - FLOAT_803df358;
        break;
      case 2:
        local_88 = local_88 - FLOAT_803df358;
        local_84 = local_84 * local_84 * local_84 - FLOAT_803df358;
        local_80 = local_80 - FLOAT_803df358;
        break;
      case 3:
        local_88 = local_88 - FLOAT_803df358;
        local_84 = (FLOAT_803df354 - local_84 * local_84 * local_84) - FLOAT_803df358;
        local_80 = local_80 - FLOAT_803df358;
        break;
      case 4:
        local_88 = local_88 - FLOAT_803df358;
        local_68 = (double)(longlong)(int)(FLOAT_803df350 * local_84);
        uStack108 = (int)(FLOAT_803df350 * local_84) & 0xffff;
        local_70 = 0x43300000;
        dVar6 = (double)FUN_80294204((double)((FLOAT_803df36c *
                                              (float)((double)CONCAT44(0x43300000,uStack108) -
                                                     DOUBLE_803df378)) / FLOAT_803df370));
        local_84 = (float)((double)FLOAT_803df358 * dVar6);
        local_80 = (float)((double)local_80 - (double)FLOAT_803df358);
        break;
      case 5:
        local_88 = local_88 - FLOAT_803df358;
        local_68 = (double)(longlong)(int)(FLOAT_803df350 * local_84);
        uStack108 = (int)(FLOAT_803df350 * local_84) & 0xffff;
        local_70 = 0x43300000;
        dVar6 = (double)FUN_80293e80((double)((FLOAT_803df36c *
                                              (float)((double)CONCAT44(0x43300000,uStack108) -
                                                     DOUBLE_803df378)) / FLOAT_803df370));
        local_84 = (float)((double)FLOAT_803df358 * dVar6);
        local_80 = (float)((double)local_80 - (double)FLOAT_803df358);
        break;
      case 6:
        local_88 = local_88 - FLOAT_803df358;
        local_84 = local_84 - FLOAT_803df358;
        local_80 = local_80 - FLOAT_803df358;
        break;
      case 7:
        local_88 = local_88 - FLOAT_803df358;
        local_84 = local_84 - FLOAT_803df358;
        local_80 = local_80 - FLOAT_803df358;
      }
      dVar6 = (double)local_88;
      local_88 = (float)(dVar6 * param_2);
      dVar7 = (double)local_84;
      local_84 = (float)(dVar7 * param_3);
      dVar8 = (double)local_80;
      local_80 = (float)(dVar8 * param_4);
      if (param_10 != 0) {
        local_88 = (float)(dVar6 * param_2) + *(float *)(param_10 + 0xc);
        local_84 = (float)(dVar7 * param_3) + *(float *)(param_10 + 0x10);
        local_80 = (float)(dVar8 * param_4) + *(float *)(param_10 + 0x14);
      }
      local_90 = *(undefined2 *)((int)&local_c8 + iVar1);
      local_94 = *(undefined2 *)((int)&local_d8 + iVar1);
      (**(code **)(*DAT_803dca88 + 8))
                ((int)((ulonglong)uVar9 >> 0x20),*(undefined2 *)((int)&local_b8 + iVar1),&local_94,
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
  FUN_80286114();
  return;
}

