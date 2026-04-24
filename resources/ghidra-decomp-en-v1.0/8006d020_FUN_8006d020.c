// Function: FUN_8006d020
// Entry: 8006d020
// Size: 1480 bytes

/* WARNING: Removing unreachable block (ram,0x8006d5c0) */
/* WARNING: Removing unreachable block (ram,0x8006d5b0) */
/* WARNING: Removing unreachable block (ram,0x8006d5a0) */
/* WARNING: Removing unreachable block (ram,0x8006d590) */
/* WARNING: Removing unreachable block (ram,0x8006d598) */
/* WARNING: Removing unreachable block (ram,0x8006d5a8) */
/* WARNING: Removing unreachable block (ram,0x8006d5b8) */
/* WARNING: Removing unreachable block (ram,0x8006d5c8) */

void FUN_8006d020(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  undefined uVar7;
  float *pfVar5;
  int iVar6;
  uint uVar8;
  float *pfVar9;
  uint uVar10;
  int iVar11;
  float *pfVar12;
  int *piVar13;
  float *pfVar14;
  uint uVar15;
  undefined4 uVar16;
  double dVar17;
  undefined8 in_f24;
  double dVar18;
  undefined8 in_f25;
  double dVar19;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar20;
  undefined8 in_f28;
  double dVar21;
  undefined8 in_f29;
  double dVar22;
  undefined8 in_f30;
  double dVar23;
  undefined8 in_f31;
  double dVar24;
  float local_ec;
  float local_e8 [2];
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  double local_d0;
  longlong local_c8;
  double local_c0;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
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
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  FUN_802860bc();
  uVar7 = FUN_80022d3c(1);
  uVar15 = 0;
  iVar11 = 0;
  dVar23 = (double)FLOAT_803ded2c;
  dVar24 = (double)FLOAT_803ded28;
  dVar22 = (double)FLOAT_803deddc;
  dVar20 = (double)FLOAT_803dedd8;
  pfVar14 = (float *)&DAT_80391978;
  dVar21 = DOUBLE_803dedc8;
  while ((iVar11 < 0x32 && (uVar15 < 10000))) {
    uStack220 = FUN_800221a0(8,0x10);
    uStack220 = uStack220 ^ 0x80000000;
    local_e0 = 0x43300000;
    *pfVar14 = (float)((double)CONCAT44(0x43300000,uStack220) - dVar21);
    uStack212 = FUN_800221a0(5,10);
    uStack212 = uStack212 ^ 0x80000000;
    local_d8 = 0x43300000;
    pfVar14[3] = (float)(dVar20 * (double)(float)((double)CONCAT44(0x43300000,uStack212) - dVar21));
    uVar15 = FUN_800221a0(0x14,0x32);
    local_d0 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
    pfVar14[4] = pfVar14[3] * (float)(dVar20 * (double)(float)(local_d0 - dVar21));
    uVar15 = 0;
    pfVar9 = pfVar14 + 1;
    pfVar12 = pfVar14 + 2;
    do {
      uVar10 = FUN_800221a0(0,999);
      local_d0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
      *pfVar9 = (float)(dVar22 * (double)(float)(local_d0 - dVar21));
      uStack212 = FUN_800221a0(0,999);
      uStack212 = uStack212 ^ 0x80000000;
      local_d8 = 0x43300000;
      *pfVar12 = (float)(dVar22 * (double)(float)((double)CONCAT44(0x43300000,uStack212) - dVar21));
      bVar4 = false;
      iVar6 = 0;
      pfVar5 = (float *)&DAT_80391978;
      while ((iVar6 < iVar11 && (!bVar4))) {
        fVar1 = ABS((float)((double)*pfVar9 - (double)pfVar5[1]));
        fVar2 = ABS((float)((double)(float)(dVar23 + (double)*pfVar9) - (double)pfVar5[1]));
        if (fVar2 < fVar1) {
          fVar1 = fVar2;
        }
        fVar2 = ABS((float)((double)*pfVar9 - dVar23) - pfVar5[1]);
        if (fVar2 < fVar1) {
          fVar1 = fVar2;
        }
        fVar2 = ABS((float)((double)*pfVar12 - (double)pfVar5[2]));
        fVar3 = ABS((float)((double)(float)(dVar23 + (double)*pfVar12) - (double)pfVar5[2]));
        if (fVar3 < fVar2) {
          fVar2 = fVar3;
        }
        fVar3 = ABS((float)((double)*pfVar12 - dVar23) - pfVar5[2]);
        if (fVar3 < fVar2) {
          fVar2 = fVar3;
        }
        dVar19 = (double)(fVar1 * fVar1 + fVar2 * fVar2);
        if (dVar24 < dVar19) {
          dVar17 = 1.0 / SQRT(dVar19);
          dVar17 = DOUBLE_803ded58 * dVar17 * -(dVar19 * dVar17 * dVar17 - DOUBLE_803ded60);
          dVar17 = DOUBLE_803ded58 * dVar17 * -(dVar19 * dVar17 * dVar17 - DOUBLE_803ded60);
          dVar19 = (double)(float)(dVar19 * DOUBLE_803ded58 * dVar17 *
                                            -(dVar19 * dVar17 * dVar17 - DOUBLE_803ded60));
        }
        if (dVar19 < (double)(pfVar14[4] + pfVar5[3])) {
          bVar4 = true;
        }
        pfVar5 = pfVar5 + 5;
        iVar6 = iVar6 + 1;
      }
      uVar15 = uVar15 + 1;
    } while ((bVar4) && (uVar15 < 10000));
    pfVar14 = pfVar14 + 5;
    iVar11 = iVar11 + 1;
  }
  uVar15 = 0;
  piVar13 = &DAT_8038e268;
  dVar22 = (double)FLOAT_803dede0;
  dVar20 = (double)FLOAT_803ded08;
  dVar21 = DOUBLE_803dedc8;
  do {
    iVar6 = FUN_80054c98(0x40,0x40,3,0,0,1,1,1,1);
    *piVar13 = iVar6;
    uVar10 = 0;
    do {
      uVar8 = 0;
      do {
        iVar6 = *piVar13;
        local_d0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
        uStack212 = uVar8 ^ 0x80000000;
        local_d8 = 0x43300000;
        local_e0 = 0x43300000;
        uStack220 = uVar15 ^ 0x80000000;
        FUN_8006cd20((double)(float)((double)(float)(local_d0 - dVar21) * dVar22),
                     (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack212) - dVar21
                                                    ) * dVar22),
                     (double)(float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - dVar21),
                     &DAT_80391978,iVar11,local_e8,&local_ec);
        local_c8 = (longlong)(int)(dVar20 * (double)local_ec);
        local_c0 = (double)(longlong)(int)(dVar20 * (double)local_e8[0]);
        *(ushort *)
         (iVar6 + (uVar10 & 3) * 2 + ((int)uVar10 >> 2) * 0x20 + (uVar8 & 3) * 8 +
          ((int)uVar8 >> 2) * 0x200 + 0x60) =
             (ushort)(((int)(dVar20 * (double)local_ec) & 0xffffU) << 8) |
             (ushort)(int)(dVar20 * (double)local_e8[0]);
        uVar8 = uVar8 + 1;
      } while ((int)uVar8 < 0x40);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x40);
    FUN_802419e8(*piVar13 + 0x60,*(undefined4 *)(*piVar13 + 0x44));
    piVar13 = piVar13 + 1;
    uVar15 = uVar15 + 1;
  } while ((int)uVar15 < 0x10);
  DAT_803dcfe0 = FUN_80054c98(0x40,0x40,3,0,0,1,1,1,1);
  uVar15 = 0;
  dVar24 = (double)FLOAT_803dede8;
  dVar23 = (double)FLOAT_803ded38;
  dVar22 = (double)FLOAT_803dedc0;
  dVar20 = (double)FLOAT_803dede4;
  dVar21 = DOUBLE_803dedc8;
  do {
    uVar10 = 0;
    local_c0 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
    dVar19 = (double)(float)(dVar20 * (double)(float)(local_c0 - dVar21));
    do {
      iVar6 = DAT_803dcfe0 + (uVar15 & 3) * 2;
      local_c0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
      dVar18 = (double)(float)(dVar24 * (double)(float)(local_c0 - dVar21));
      dVar17 = (double)FUN_80294098(dVar18);
      dVar17 = (double)FUN_802943f4((double)(float)(dVar23 * dVar17 + dVar19));
      dVar18 = (double)FUN_802943f4(dVar18);
      iVar11 = (int)(dVar22 * dVar17 + dVar22);
      local_c8 = (longlong)iVar11;
      uVar8 = (uint)(dVar22 * (double)(float)(dVar17 * dVar18) + dVar22);
      local_d0 = (double)(longlong)(int)uVar8;
      *(ushort *)
       (iVar6 + ((int)uVar15 >> 2) * 0x20 + (uVar10 & 3) * 8 + ((int)uVar10 >> 2) * 0x200 + 0x60) =
           (ushort)iVar11 | (ushort)((uVar8 & 0xffff) << 8);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x40);
    uVar15 = uVar15 + 1;
  } while ((int)uVar15 < 0x40);
  FUN_802419e8(DAT_803dcfe0 + 0x60,*(undefined4 *)(DAT_803dcfe0 + 0x44));
  FLOAT_803dcfac = FLOAT_803ded28;
  FLOAT_803dcfa8 = FLOAT_803ded28;
  FUN_80022d3c(uVar7);
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  __psq_l0(auStack40,uVar16);
  __psq_l1(auStack40,uVar16);
  __psq_l0(auStack56,uVar16);
  __psq_l1(auStack56,uVar16);
  __psq_l0(auStack72,uVar16);
  __psq_l1(auStack72,uVar16);
  __psq_l0(auStack88,uVar16);
  __psq_l1(auStack88,uVar16);
  __psq_l0(auStack104,uVar16);
  __psq_l1(auStack104,uVar16);
  __psq_l0(auStack120,uVar16);
  __psq_l1(auStack120,uVar16);
  FUN_80286108();
  return;
}

