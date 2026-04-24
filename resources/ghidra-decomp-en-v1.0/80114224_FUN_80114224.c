// Function: FUN_80114224
// Entry: 80114224
// Size: 484 bytes

/* WARNING: Removing unreachable block (ram,0x801143e0) */
/* WARNING: Removing unreachable block (ram,0x801143d0) */
/* WARNING: Removing unreachable block (ram,0x801143c0) */
/* WARNING: Removing unreachable block (ram,0x801143b0) */
/* WARNING: Removing unreachable block (ram,0x801143b8) */
/* WARNING: Removing unreachable block (ram,0x801143c8) */
/* WARNING: Removing unreachable block (ram,0x801143d8) */
/* WARNING: Removing unreachable block (ram,0x801143e8) */

void FUN_80114224(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 uint param_5)

{
  float fVar1;
  float *pfVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f24;
  undefined8 in_f25;
  double dVar10;
  double dVar11;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar12;
  undefined8 in_f28;
  double dVar13;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  float local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  uVar16 = FUN_802860d0();
  pfVar2 = (float *)((ulonglong)uVar16 >> 0x20);
  puVar3 = (undefined4 *)uVar16;
  dVar10 = (double)*pfVar2;
  dVar9 = (double)pfVar2[2];
  dVar8 = (double)pfVar2[1];
  dVar15 = DOUBLE_803e1c98;
  fVar1 = FLOAT_803e1c90;
  for (uVar4 = 1; dVar13 = (double)fVar1, (int)uVar4 < (int)(param_5 + 1); uVar4 = uVar4 + 1) {
    uStack180 = uVar4 ^ 0x80000000;
    local_b8 = 0x43300000;
    local_b0 = 0x43300000;
    dVar12 = (double)((float)((double)CONCAT44(0x43300000,uStack180) - dVar15) /
                     (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - dVar15));
    local_c8 = *pfVar2;
    local_c4 = *param_3;
    local_c0 = *puVar3;
    local_bc = *param_4;
    uStack172 = param_5 ^ 0x80000000;
    dVar6 = (double)FUN_80010dc0(dVar12,&local_c8,0);
    dVar11 = (double)(float)(dVar6 - dVar10);
    local_c8 = pfVar2[1];
    local_c4 = param_3[1];
    local_c0 = puVar3[1];
    local_bc = param_4[1];
    dVar7 = (double)FUN_80010dc0(dVar12,&local_c8,0);
    dVar14 = (double)(float)(dVar7 - dVar8);
    local_c8 = pfVar2[2];
    local_c4 = param_3[2];
    local_c0 = puVar3[2];
    local_bc = param_4[2];
    dVar8 = (double)FUN_80010dc0(dVar12,&local_c8,0);
    dVar10 = dVar6;
    dVar9 = (double)FUN_802931a0((double)((float)(dVar8 - dVar9) * (float)(dVar8 - dVar9) +
                                         (float)(dVar11 * dVar11 + (double)(float)(dVar14 * dVar14))
                                         ));
    fVar1 = (float)(dVar13 + dVar9);
    dVar9 = dVar8;
    dVar8 = dVar7;
  }
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
  __psq_l0(auStack88,uVar5);
  __psq_l1(auStack88,uVar5);
  __psq_l0(auStack104,uVar5);
  __psq_l1(auStack104,uVar5);
  __psq_l0(auStack120,uVar5);
  __psq_l1(auStack120,uVar5);
  FUN_8028611c(dVar13);
  return;
}

