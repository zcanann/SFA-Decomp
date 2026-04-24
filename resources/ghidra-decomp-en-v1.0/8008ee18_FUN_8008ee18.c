// Function: FUN_8008ee18
// Entry: 8008ee18
// Size: 1200 bytes

/* WARNING: Removing unreachable block (ram,0x8008f2a0) */
/* WARNING: Removing unreachable block (ram,0x8008f290) */
/* WARNING: Removing unreachable block (ram,0x8008f288) */
/* WARNING: Removing unreachable block (ram,0x8008f298) */
/* WARNING: Removing unreachable block (ram,0x8008f2a8) */

void FUN_8008ee18(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 *param_4)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  undefined4 unaff_r30;
  uint uVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  double dVar11;
  undefined8 in_f27;
  double dVar12;
  double in_f28;
  double in_f29;
  double in_f30;
  undefined8 in_f31;
  undefined8 uVar13;
  float local_118;
  float local_114;
  float local_110;
  undefined auStack268 [12];
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined auStack232 [12];
  undefined auStack220 [52];
  double local_a8;
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,SUB84(in_f28,0),0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar13 = FUN_802860d8();
  pfVar3 = (float *)((ulonglong)uVar13 >> 0x20);
  puVar7 = (undefined4 *)uVar13;
  dVar12 = extraout_f1;
  iVar4 = FUN_8002073c();
  if (iVar4 == 0) {
    unaff_r30 = FUN_80292dc0();
    FUN_80292de4(*param_4);
  }
  FUN_80247754(puVar7,pfVar3,auStack232);
  dVar10 = (double)FUN_802477f0(auStack232);
  FUN_80247778((double)(float)((double)FLOAT_803df1a4 / dVar10),auStack232,&local_f4);
  if (FLOAT_803df1b8 <= ABS(local_f4)) {
    local_100 = FLOAT_803df1a0;
    local_f8 = FLOAT_803df1a4;
  }
  else {
    local_100 = FLOAT_803df1a4;
    local_f8 = FLOAT_803df1a0;
  }
  local_fc = FLOAT_803df1a0;
  FUN_8024784c(&local_f4,&local_100,auStack268);
  FUN_8024784c(auStack268,&local_f4,&local_100);
  FUN_80247794(&local_100,&local_100);
  iVar4 = (int)(dVar10 * dVar12);
  local_a8 = (double)(longlong)iVar4;
  if (10 < iVar4) {
    iVar4 = 10;
  }
  if (iVar4 == 0) {
    iVar4 = 1;
  }
  iVar5 = 0;
  fVar1 = FLOAT_803df1a0;
  if (0 < iVar4) {
    if ((8 < iVar4) && (uVar8 = iVar4 - 1U >> 3, 0 < iVar4 + -8)) {
      do {
        local_a8 = (double)CONCAT44(0x43300000,iVar5 + 1U ^ 0x80000000);
        uStack156 = iVar5 + 2U ^ 0x80000000;
        local_a0 = 0x43300000;
        uStack148 = iVar5 + 3U ^ 0x80000000;
        local_98 = 0x43300000;
        uStack140 = iVar5 + 4U ^ 0x80000000;
        local_90 = 0x43300000;
        uStack132 = iVar5 + 5U ^ 0x80000000;
        local_88 = 0x43300000;
        uStack124 = iVar5 + 6U ^ 0x80000000;
        local_80 = 0x43300000;
        uStack116 = iVar5 + 7U ^ 0x80000000;
        local_78 = 0x43300000;
        uStack108 = iVar5 + 8U ^ 0x80000000;
        local_70 = 0x43300000;
        fVar1 = fVar1 + (float)(local_a8 - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803df1a8) +
                (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803df1a8);
        iVar5 = iVar5 + 8;
        uVar8 = uVar8 - 1;
      } while (uVar8 != 0);
    }
    iVar2 = iVar4 - iVar5;
    if (iVar5 < iVar4) {
      do {
        uStack108 = iVar5 + 1U ^ 0x80000000;
        local_70 = 0x43300000;
        fVar1 = fVar1 + (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803df1a8);
        iVar5 = iVar5 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  dVar12 = (double)(FLOAT_803df1a4 / fVar1);
  FUN_80258a14(param_3,5);
  FUN_8025889c(0xb0,2,iVar4 + 1U & 0xffff);
  for (iVar5 = 0; iVar5 <= iVar4; iVar5 = iVar5 + 1) {
    if (iVar5 == 0) {
      write_volatile_4(0xcc008000,*pfVar3);
      write_volatile_4(0xcc008000,pfVar3[1]);
      write_volatile_4(0xcc008000,pfVar3[2]);
      write_volatile_4(0xcc008000,FLOAT_803df1a0);
      write_volatile_4(0xcc008000,FLOAT_803df1a0);
      in_f30 = (double)*pfVar3;
      in_f29 = (double)pfVar3[1];
      in_f28 = (double)pfVar3[2];
    }
    else if (iVar5 < iVar4) {
      uStack108 = FUN_800221a0(1,100);
      uStack108 = uStack108 ^ 0x80000000;
      local_70 = 0x43300000;
      FUN_80247778((double)(FLOAT_803df1bc *
                           FLOAT_803df1c0 *
                           (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack108) -
                                                           DOUBLE_803df1a8))),&local_100,&local_118)
      ;
      uStack116 = FUN_800221a0(0,1000);
      uStack116 = uStack116 ^ 0x80000000;
      local_78 = 0x43300000;
      FUN_802471e0((double)(FLOAT_803df1c4 *
                           FLOAT_803df1c8 *
                           FLOAT_803df1cc *
                           (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803df1a8)),
                   auStack220,&local_f4);
      FUN_80247574(auStack220,&local_118,&local_118);
      uStack124 = iVar4 - iVar5 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar11 = (double)(float)(dVar12 * (double)(float)(dVar10 * (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack124) - DOUBLE_803df1a8)));
      in_f30 = (double)(float)((double)local_f4 * dVar11 + in_f30);
      in_f29 = (double)(float)((double)local_f0 * dVar11 + in_f29);
      in_f28 = (double)(float)((double)local_ec * dVar11 + in_f28);
      write_volatile_4(0xcc008000,(float)(in_f30 + (double)local_118));
      write_volatile_4(0xcc008000,(float)(in_f29 + (double)local_114));
      write_volatile_4(0xcc008000,(float)(in_f28 + (double)local_110));
      write_volatile_4(0xcc008000,FLOAT_803df1a0);
      write_volatile_4(0xcc008000,FLOAT_803df1a0);
    }
    else {
      write_volatile_4(0xcc008000,*puVar7);
      write_volatile_4(0xcc008000,puVar7[1]);
      write_volatile_4(0xcc008000,puVar7[2]);
      write_volatile_4(0xcc008000,FLOAT_803df1a0);
      write_volatile_4(0xcc008000,FLOAT_803df1a0);
    }
  }
  iVar4 = FUN_8002073c();
  if (iVar4 == 0) {
    uVar6 = FUN_80292dc0();
    *param_4 = uVar6;
    FUN_80292de4(unaff_r30);
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  __psq_l0(auStack72,uVar9);
  __psq_l1(auStack72,uVar9);
  FUN_80286124();
  return;
}

