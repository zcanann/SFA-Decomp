// Function: FUN_8013afe0
// Entry: 8013afe0
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x8013b1b8) */
/* WARNING: Removing unreachable block (ram,0x8013b1a8) */
/* WARNING: Removing unreachable block (ram,0x8013b198) */
/* WARNING: Removing unreachable block (ram,0x8013b1a0) */
/* WARNING: Removing unreachable block (ram,0x8013b1b0) */
/* WARNING: Removing unreachable block (ram,0x8013b1c0) */

void FUN_8013afe0(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,float *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  float *pfVar5;
  undefined4 uVar6;
  double extraout_f1;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  undefined8 uVar14;
  float local_88 [2];
  float local_80;
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
  uVar14 = FUN_802860dc();
  pfVar4 = (float *)((ulonglong)uVar14 >> 0x20);
  pfVar5 = (float *)uVar14;
  dVar11 = extraout_f1;
  dVar7 = (double)FUN_8002166c(param_6,pfVar4);
  dVar8 = (double)FUN_8002166c(param_6,pfVar5);
  dVar12 = (double)(float)(dVar11 * dVar11);
  dVar11 = (double)(float)(param_2 * param_2);
  if ((dVar8 <= dVar7) && (dVar9 = (double)FUN_8002166c(param_5,param_6), dVar12 <= dVar9)) {
    dVar9 = (double)FUN_8002166c(pfVar4,param_5);
    dVar10 = (double)FUN_8002166c(pfVar4,param_6);
    if (dVar10 <= dVar9) {
      dVar9 = dVar11;
      if (dVar7 < dVar11) {
        dVar9 = dVar7;
      }
      if (dVar8 < dVar9) {
        fVar3 = pfVar5[2] - pfVar4[2];
        fVar1 = *pfVar4;
        fVar2 = fVar3 / (*pfVar5 - fVar1);
        local_80 = -(fVar2 * fVar1 - pfVar4[2]);
        fVar3 = (fVar1 - *pfVar5) / fVar3;
        local_88[0] = (-(fVar3 * *param_6 - param_6[2]) - local_80) / (fVar2 - fVar3);
        local_80 = fVar2 * local_88[0] + local_80;
        dVar10 = (double)FUN_8002166c(param_6,local_88);
        if (dVar10 < dVar12) {
          dVar10 = (double)(*pfVar5 - *param_6);
          dVar13 = (double)(pfVar5[2] - param_6[2]);
          dVar12 = (double)FUN_802931a0((double)(float)(dVar10 * dVar10 +
                                                       (double)(float)(dVar13 * dVar13)));
          if ((double)FLOAT_803e23dc != dVar12) {
            dVar10 = (double)(float)(dVar10 / dVar12);
            dVar13 = (double)(float)(dVar13 / dVar12);
          }
          if (dVar7 < dVar11) {
            dVar11 = (double)FUN_802931a0(dVar9);
            dVar7 = (double)FUN_802931a0(dVar8);
            param_2 = -(double)(float)((double)(float)(dVar11 - dVar7) * (double)FLOAT_803e2480 -
                                      dVar11);
          }
          *pfVar5 = (float)(dVar10 * param_2 + (double)*param_6);
          pfVar5[2] = (float)(dVar13 * param_2 + (double)param_6[2]);
        }
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
  FUN_80286128();
  return;
}

