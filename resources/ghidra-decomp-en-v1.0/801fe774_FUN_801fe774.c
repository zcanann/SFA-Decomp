// Function: FUN_801fe774
// Entry: 801fe774
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x801fe9b0) */
/* WARNING: Removing unreachable block (ram,0x801fe9a0) */
/* WARNING: Removing unreachable block (ram,0x801fe9a8) */
/* WARNING: Removing unreachable block (ram,0x801fe9b8) */

void FUN_801fe774(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short **ppsVar4;
  float *pfVar5;
  int iVar6;
  short *psVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  uint local_78 [2];
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar14 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar14 >> 0x20);
  pfVar5 = (float *)uVar14;
  dVar12 = (double)FLOAT_803e61c8;
  dVar10 = dVar12;
  ppsVar4 = (short **)FUN_80036f50(0x14,local_78);
  dVar13 = (double)FLOAT_803e61e8;
  for (iVar6 = 0; fVar1 = FLOAT_803e6200, iVar6 < (int)local_78[0]; iVar6 = iVar6 + 1) {
    psVar7 = *ppsVar4;
    dVar9 = (double)(*(float *)(psVar7 + 8) - *(float *)(iVar3 + 0x10));
    if ((dVar9 <= dVar13) && ((double)FLOAT_803e61ec <= dVar9)) {
      fVar1 = *(float *)(psVar7 + 6) - *(float *)(iVar3 + 0xc);
      fVar2 = *(float *)(psVar7 + 10) - *(float *)(iVar3 + 0x14);
      dVar9 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
      uStack108 = (uint)*(byte *)(*(int *)(psVar7 + 0x26) + 0x19);
      local_70 = 0x43300000;
      dVar11 = (double)(FLOAT_803e61f0 *
                       (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e61d8));
      if (dVar9 < dVar11) {
        dVar11 = (double)((float)((double)(float)(dVar11 - dVar9) / dVar11) *
                         FLOAT_803e61f4 * *(float *)(psVar7 + 4));
        uStack108 = (int)*psVar7 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar9 = (double)FUN_80293e80((double)((FLOAT_803e61f8 *
                                              (float)((double)CONCAT44(0x43300000,uStack108) -
                                                     DOUBLE_803e6210)) / FLOAT_803e61fc));
        dVar10 = (double)(float)(dVar11 * dVar9 + dVar10);
        uStack100 = (int)*psVar7 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar9 = (double)FUN_80294204((double)((FLOAT_803e61f8 *
                                              (float)((double)CONCAT44(0x43300000,uStack100) -
                                                     DOUBLE_803e6210)) / FLOAT_803e61fc));
        dVar12 = (double)(float)(dVar11 * dVar9 + dVar12);
      }
    }
    ppsVar4 = ppsVar4 + 1;
  }
  if (local_78[0] != 0) {
    uStack108 = local_78[0] ^ 0x80000000;
    local_68 = 0x43300000;
    local_70 = 0x43300000;
    dVar13 = (double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e6210;
    *pfVar5 = -(FLOAT_803e6200 *
                (float)(dVar10 / (double)(float)((double)CONCAT44(0x43300000,uStack108) -
                                                DOUBLE_803e6210)) - *pfVar5);
    pfVar5[2] = -(fVar1 * (float)(dVar12 / (double)(float)dVar13) - pfVar5[2]);
    fVar1 = FLOAT_803e6204;
    *pfVar5 = *pfVar5 * FLOAT_803e6204;
    pfVar5[2] = pfVar5[2] * fVar1;
    uStack100 = uStack108;
    dVar10 = (double)FUN_802931a0((double)(*pfVar5 * *pfVar5 + pfVar5[2] * pfVar5[2]));
    if ((double)FLOAT_803e6208 < dVar10) {
      fVar1 = (float)((double)FLOAT_803e6208 / dVar10);
      *pfVar5 = *pfVar5 * fVar1;
      pfVar5[2] = pfVar5[2] * fVar1;
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  FUN_80286128();
  return;
}

