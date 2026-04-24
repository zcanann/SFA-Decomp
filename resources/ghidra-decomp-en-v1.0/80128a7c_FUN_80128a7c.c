// Function: FUN_80128a7c
// Entry: 80128a7c
// Size: 1012 bytes

/* WARNING: Removing unreachable block (ram,0x80128e48) */
/* WARNING: Removing unreachable block (ram,0x80128e38) */
/* WARNING: Removing unreachable block (ram,0x80128e28) */
/* WARNING: Removing unreachable block (ram,0x80128e20) */
/* WARNING: Removing unreachable block (ram,0x80128e30) */
/* WARNING: Removing unreachable block (ram,0x80128e40) */
/* WARNING: Removing unreachable block (ram,0x80128e50) */

void FUN_80128a7c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  short sVar6;
  ushort uVar7;
  int iVar5;
  short *psVar8;
  uint uVar9;
  char cVar10;
  undefined4 uVar11;
  undefined8 in_f25;
  double dVar12;
  undefined8 in_f26;
  double dVar13;
  undefined8 in_f27;
  double dVar14;
  undefined8 in_f28;
  double dVar15;
  undefined8 in_f29;
  double dVar16;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  double dVar19;
  undefined8 uVar20;
  double local_a8;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
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
  uVar20 = FUN_802860c0();
  uVar1 = (uint)(((double)CONCAT44(0x43300000,(int)(short)uVar20 ^ 0x80000000) - DOUBLE_803e1e78) *
                 (DOUBLE_803e2080 -
                 ((double)CONCAT44(0x43300000,(int)DAT_803dd75c ^ 0x80000000) - DOUBLE_803e1e78)) *
                DOUBLE_803e2088);
  uVar2 = (uint)((ulonglong)uVar20 >> 0x20) & 0xff;
  iVar3 = uVar2 * 0x20;
  if (-1 < *(short *)(DAT_803dd824 + iVar3)) {
    iVar4 = (int)(short)uVar1;
    iVar4 = iVar4 / 0xf + (iVar4 >> 0x1f);
    dVar18 = (double)FLOAT_803e20b8;
    dVar12 = DOUBLE_803e2108;
    dVar13 = DOUBLE_803e2128;
    dVar19 = DOUBLE_803e1e88;
    for (cVar10 = DAT_803dd824[iVar3 + 10]; -1 < cVar10; cVar10 = cVar10 + -4) {
      psVar8 = (short *)(DAT_803dd824 + iVar3);
      dVar16 = (double)(float)(dVar18 * (double)*(float *)(psVar8 + 8));
      local_a8 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar8[1]);
      dVar15 = (double)(float)(local_a8 - dVar19);
      dVar14 = (double)(float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar8[2]) - dVar19);
      sVar6 = psVar8[3] - (short)cVar10;
      if ((uVar2 == DAT_803dd7d8) && (DAT_803dd824 != &DAT_8031b818)) {
        local_a8 = (double)CONCAT44(0x43300000,(int)DAT_803dd75c ^ 0x80000000);
        dVar17 = (double)(float)(dVar16 * (DOUBLE_803e1f60 +
                                          (local_a8 - DOUBLE_803e1e78) / DOUBLE_803e2118));
        dVar16 = (double)FUN_80293e80((double)((FLOAT_803e1ec8 * FLOAT_803e2104 * FLOAT_803dd748) /
                                              FLOAT_803e1e94));
        dVar16 = (double)(float)(dVar17 + (double)(float)((double)FLOAT_803e20bc * dVar16 +
                                                         (double)FLOAT_803e2090));
        dVar15 = (double)(float)((double)((float)((double)FLOAT_803e1f34 - dVar15) *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (int)DAT_803dd75c ^ 0x80000000U) -
                                                DOUBLE_803e1e78)) * DOUBLE_803e2088 + dVar15);
        dVar14 = (double)(float)((double)((float)((double)FLOAT_803e2120 - dVar14) *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (int)DAT_803dd75c ^ 0x80000000U) -
                                                DOUBLE_803e1e78)) * DOUBLE_803e2088 + dVar14);
        uVar9 = (uint)uVar20;
      }
      else {
        if ((*psVar8 == 0x4a) || (uVar9 = uVar1, *psVar8 == 0x4c)) {
          uVar7 = (ushort)(int)FLOAT_803dd748 & 0x1f;
          if (((int)FLOAT_803dd748 & 0x10U) != 0) {
            uVar7 = uVar7 ^ 0x1f;
          }
          uVar9 = (int)(short)(uVar7 * ((short)iVar4 - (short)(iVar4 >> 0x1f)));
        }
        sVar6 = sVar6 - DAT_803dd75c;
      }
      psVar8 = (short *)(DAT_803dd824 + iVar3);
      local_a8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar8 + 4));
      dVar15 = (double)(float)-(dVar12 * (double)(float)(dVar16 * (double)(float)(local_a8 - dVar19)
                                                        ) * dVar13 - dVar15);
      dVar14 = (double)(float)-(dVar12 * (double)(float)(dVar16 * (double)(float)((double)CONCAT44(
                                                  0x43300000,(uint)*(byte *)((int)psVar8 + 9)) -
                                                  dVar19)) * dVar13 - dVar14);
      if (DAT_803dd824 == &DAT_8031bd90) {
        if ((&DAT_803a8b48)[*psVar8] == 0xbf0) {
          sVar6 = sVar6 + -0x14;
        }
        if ((&DAT_803a8b98)[*psVar8] != 0) {
          FUN_8011eda4(dVar15,dVar14,(&DAT_803a8b98)[*psVar8],(int)sVar6,uVar9 & 0xff,(int)dVar16,
                       param_3);
        }
      }
      else {
        iVar5 = (int)*psVar8;
        if (iVar5 != 0) {
          if (iVar5 == 0x25) {
            sVar6 = sVar6 + -0x14;
          }
          FUN_8011eda4(dVar15,dVar14,(&DAT_803a89b0)[iVar5],(int)sVar6,uVar9 & 0xff,(int)dVar16,
                       param_3);
        }
      }
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  __psq_l0(auStack88,uVar11);
  __psq_l1(auStack88,uVar11);
  __psq_l0(auStack104,uVar11);
  __psq_l1(auStack104,uVar11);
  FUN_8028610c();
  return;
}

