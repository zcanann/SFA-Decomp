// Function: FUN_8008f0a4
// Entry: 8008f0a4
// Size: 1200 bytes

/* WARNING: Removing unreachable block (ram,0x8008f534) */
/* WARNING: Removing unreachable block (ram,0x8008f52c) */
/* WARNING: Removing unreachable block (ram,0x8008f524) */
/* WARNING: Removing unreachable block (ram,0x8008f51c) */
/* WARNING: Removing unreachable block (ram,0x8008f514) */
/* WARNING: Removing unreachable block (ram,0x8008f0d4) */
/* WARNING: Removing unreachable block (ram,0x8008f0cc) */
/* WARNING: Removing unreachable block (ram,0x8008f0c4) */
/* WARNING: Removing unreachable block (ram,0x8008f0bc) */
/* WARNING: Removing unreachable block (ram,0x8008f0b4) */

void FUN_8008f0a4(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 *param_4)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  float *pfVar7;
  undefined4 unaff_r30;
  uint uVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  double in_f27;
  double dVar11;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  float local_118;
  float local_114;
  float local_110;
  float afStack_10c [3];
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float afStack_e8 [3];
  float afStack_dc [13];
  undefined8 local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar12 = FUN_8028683c();
  pfVar3 = (float *)((ulonglong)uVar12 >> 0x20);
  pfVar7 = (float *)uVar12;
  dVar11 = extraout_f1;
  iVar4 = FUN_80020800();
  if (iVar4 == 0) {
    unaff_r30 = FUN_80293520();
    FUN_80293544(*param_4);
  }
  FUN_80247eb8(pfVar7,pfVar3,afStack_e8);
  dVar9 = FUN_80247f54(afStack_e8);
  FUN_80247edc((double)(float)((double)FLOAT_803dfe24 / dVar9),afStack_e8,&local_f4);
  if (FLOAT_803dfe38 <= ABS(local_f4)) {
    local_100 = FLOAT_803dfe20;
    local_f8 = FLOAT_803dfe24;
  }
  else {
    local_100 = FLOAT_803dfe24;
    local_f8 = FLOAT_803dfe20;
  }
  local_fc = FLOAT_803dfe20;
  FUN_80247fb0(&local_f4,&local_100,afStack_10c);
  FUN_80247fb0(afStack_10c,&local_f4,&local_100);
  FUN_80247ef8(&local_100,&local_100);
  iVar4 = (int)(dVar9 * dVar11);
  local_a8 = (double)(longlong)iVar4;
  if (10 < iVar4) {
    iVar4 = 10;
  }
  if (iVar4 == 0) {
    iVar4 = 1;
  }
  iVar5 = 0;
  fVar1 = FLOAT_803dfe20;
  if (0 < iVar4) {
    if ((8 < iVar4) && (uVar8 = iVar4 - 1U >> 3, 0 < iVar4 + -8)) {
      do {
        local_a8 = (double)CONCAT44(0x43300000,iVar5 + 1U ^ 0x80000000);
        uStack_9c = iVar5 + 2U ^ 0x80000000;
        local_a0 = 0x43300000;
        uStack_94 = iVar5 + 3U ^ 0x80000000;
        local_98 = 0x43300000;
        uStack_8c = iVar5 + 4U ^ 0x80000000;
        local_90 = 0x43300000;
        uStack_84 = iVar5 + 5U ^ 0x80000000;
        local_88 = 0x43300000;
        uStack_7c = iVar5 + 6U ^ 0x80000000;
        local_80 = 0x43300000;
        uStack_74 = iVar5 + 7U ^ 0x80000000;
        local_78 = 0x43300000;
        uStack_6c = iVar5 + 8U ^ 0x80000000;
        local_70 = 0x43300000;
        fVar1 = fVar1 + (float)(local_a8 - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803dfe28) +
                (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803dfe28);
        iVar5 = iVar5 + 8;
        uVar8 = uVar8 - 1;
      } while (uVar8 != 0);
    }
    iVar2 = iVar4 - iVar5;
    if (iVar5 < iVar4) {
      do {
        uStack_6c = iVar5 + 1U ^ 0x80000000;
        local_70 = 0x43300000;
        fVar1 = fVar1 + (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803dfe28);
        iVar5 = iVar5 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  dVar11 = (double)(FLOAT_803dfe24 / fVar1);
  FUN_80259178(param_3,5);
  FUN_80259000(0xb0,2,iVar4 + 1U & 0xffff);
  for (iVar5 = 0; iVar5 <= iVar4; iVar5 = iVar5 + 1) {
    if (iVar5 == 0) {
      DAT_cc008000 = *pfVar3;
      DAT_cc008000 = pfVar3[1];
      DAT_cc008000 = pfVar3[2];
      DAT_cc008000 = FLOAT_803dfe20;
      DAT_cc008000 = FLOAT_803dfe20;
      in_f30 = (double)*pfVar3;
      in_f29 = (double)pfVar3[1];
      in_f28 = (double)pfVar3[2];
    }
    else if (iVar5 < iVar4) {
      uStack_6c = FUN_80022264(1,100);
      uStack_6c = uStack_6c ^ 0x80000000;
      local_70 = 0x43300000;
      FUN_80247edc((double)(FLOAT_803dfe3c *
                           FLOAT_803dfe40 *
                           (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                                          DOUBLE_803dfe28))),&local_100,&local_118);
      uStack_74 = FUN_80022264(0,1000);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      FUN_80247944((double)(FLOAT_803dfe44 *
                           FLOAT_803dfe48 *
                           FLOAT_803dfe4c *
                           (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803dfe28)),
                   afStack_dc,&local_f4);
      FUN_80247cd8(afStack_dc,&local_118,&local_118);
      uStack_7c = iVar4 - iVar5 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar10 = (double)(float)(dVar11 * (double)(float)(dVar9 * (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack_7c) - DOUBLE_803dfe28)));
      in_f30 = (double)(float)((double)local_f4 * dVar10 + in_f30);
      in_f29 = (double)(float)((double)local_f0 * dVar10 + in_f29);
      in_f28 = (double)(float)((double)local_ec * dVar10 + in_f28);
      DAT_cc008000 = (float)(in_f30 + (double)local_118);
      DAT_cc008000 = (float)(in_f29 + (double)local_114);
      DAT_cc008000 = (float)(in_f28 + (double)local_110);
      DAT_cc008000 = FLOAT_803dfe20;
      DAT_cc008000 = FLOAT_803dfe20;
    }
    else {
      DAT_cc008000 = *pfVar7;
      DAT_cc008000 = pfVar7[1];
      DAT_cc008000 = pfVar7[2];
      DAT_cc008000 = FLOAT_803dfe20;
      DAT_cc008000 = FLOAT_803dfe20;
    }
  }
  iVar4 = FUN_80020800();
  if (iVar4 == 0) {
    uVar6 = FUN_80293520();
    *param_4 = uVar6;
    FUN_80293544(unaff_r30);
  }
  FUN_80286888();
  return;
}

