// Function: FUN_8008fc9c
// Entry: 8008fc9c
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x80090050) */
/* WARNING: Removing unreachable block (ram,0x80090040) */
/* WARNING: Removing unreachable block (ram,0x80090030) */
/* WARNING: Removing unreachable block (ram,0x80090038) */
/* WARNING: Removing unreachable block (ram,0x80090048) */
/* WARNING: Removing unreachable block (ram,0x80090058) */

void FUN_8008fc9c(undefined8 param_1,double param_2)

{
  int iVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  undefined4 uVar6;
  double extraout_f1;
  double dVar7;
  undefined8 in_f26;
  double dVar8;
  undefined8 in_f27;
  double dVar9;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  undefined8 uVar13;
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
  uVar13 = FUN_802860d8();
  iVar4 = (int)uVar13;
  dVar11 = (double)((float)(extraout_f1 * param_2) * FLOAT_803df1e0);
  iVar3 = 0;
  if (((((((DAT_8039a828 == 0) || (iVar4 != *(int *)(DAT_8039a828 + 0x13f0))) &&
         ((iVar3 = 1, DAT_8039a82c == 0 || (iVar4 != *(int *)(DAT_8039a82c + 0x13f0))))) &&
        ((iVar3 = 2, DAT_8039a830 == 0 || (iVar4 != *(int *)(DAT_8039a830 + 0x13f0))))) &&
       ((iVar3 = 3, DAT_8039a834 == 0 || (iVar4 != *(int *)(DAT_8039a834 + 0x13f0))))) &&
      ((((iVar3 = 4, DAT_8039a838 == 0 || (iVar4 != *(int *)(DAT_8039a838 + 0x13f0))) &&
        ((iVar3 = 5, DAT_8039a83c == 0 || (iVar4 != *(int *)(DAT_8039a83c + 0x13f0))))) &&
       ((iVar3 = 6, DAT_8039a840 == 0 || (iVar4 != *(int *)(DAT_8039a840 + 0x13f0))))))) &&
     ((iVar3 = 7, DAT_8039a844 == 0 || (iVar4 != *(int *)(DAT_8039a844 + 0x13f0))))) {
    iVar3 = 8;
  }
  iVar1 = (&DAT_8039a828)[iVar3];
  if ((iVar1 != 0) && (dVar7 = (double)FLOAT_803df1e4, dVar7 != (double)FLOAT_803dd1ac)) {
    if (iVar4 == *(int *)(iVar1 + 0x13f0)) {
      if (*(int *)(iVar1 + 0x13f4) != 4) {
        dVar7 = (double)FLOAT_803df1e8;
      }
      iVar4 = 0;
      pfVar5 = (float *)(iVar1 + 0x1008);
      dVar10 = -dVar7;
      dVar9 = (double)(float)((double)FLOAT_803df1ec * dVar10);
      dVar8 = (double)FLOAT_803df1a0;
      do {
        *pfVar5 = (float)dVar10;
        pfVar5[6] = (float)dVar8;
        pfVar5[1] = (float)dVar7;
        pfVar5[7] = (float)dVar8;
        pfVar5[2] = (float)dVar8;
        pfVar5[8] = (float)dVar8;
        if (*(int *)((&DAT_8039a828)[iVar3] + 0x13f4) == 0) {
          pfVar5[3] = (float)dVar10;
          pfVar5[4] = (float)dVar10;
          pfVar5[5] = (float)dVar7;
        }
        else {
          pfVar5[3] = (float)dVar10;
          pfVar5[4] = (float)dVar10;
          pfVar5[5] = (float)dVar9;
        }
        uVar2 = FUN_800221a0(0,0xffff);
        *(undefined2 *)(pfVar5 + 10) = uVar2;
        uVar2 = FUN_800221a0(0,0xffff);
        *(undefined2 *)((int)pfVar5 + 0x2a) = uVar2;
        uVar2 = FUN_800221a0(0x96,500);
        *(undefined2 *)(pfVar5 + 9) = uVar2;
        uVar2 = FUN_800221a0(0x96,500);
        *(undefined2 *)((int)pfVar5 + 0x26) = uVar2;
        pfVar5 = pfVar5 + 0xb;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x14);
      iVar4 = *(int *)((&DAT_8039a828)[iVar3] + 0x1408);
      pfVar5 = (float *)((int)((ulonglong)uVar13 >> 0x20) + iVar4 * 4);
      dVar12 = (double)FLOAT_803df1f0;
      dVar8 = (double)FLOAT_803df1f4;
      dVar9 = (double)FLOAT_803df1f8;
      dVar10 = (double)FLOAT_803df1a4;
      dVar7 = DOUBLE_803df1a8;
      while( true ) {
        iVar1 = *(int *)((&DAT_8039a828)[iVar3] + 0x1408) + 4000;
        if (iVar1 <= iVar4) break;
        if (iVar4 == 0x400) {
          *(undefined4 *)((&DAT_8039a828)[iVar3] + 0x1400) = 0;
          *(undefined4 *)((&DAT_8039a828)[iVar3] + 0x1408) = 0;
          goto LAB_80090030;
        }
        if (iVar4 == 0) {
          DAT_803dd1a8 = 0;
          FLOAT_803dd1ac = FLOAT_803df1a0;
          FLOAT_803dd1b0 = FLOAT_803df1a0;
        }
        FUN_80293e80((double)(float)((double)(float)(dVar12 * (double)(float)((double)CONCAT44(
                                                  0x43300000,(int)DAT_803dd1a8 ^ 0x80000000) - dVar7
                                                  )) / dVar8));
        FUN_80294204((double)(float)((double)(float)(dVar12 * (double)(float)((double)CONCAT44(
                                                  0x43300000,(int)DAT_803dd1a8 ^ 0x80000000) - dVar7
                                                  )) / dVar8));
        *pfVar5 = (float)((double)FLOAT_803dd1ac * dVar11);
        DAT_803dd1a8 = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                                     (int)DAT_803dd1a8 ^ 0x80000000)
                                                   - dVar7) + dVar9);
        FLOAT_803dd1ac = (float)((double)FLOAT_803dd1ac + dVar10);
        pfVar5 = pfVar5 + 1;
        iVar4 = iVar4 + 1;
      }
      *(int *)((&DAT_8039a828)[iVar3] + 0x1408) = iVar1;
    }
    else {
      FUN_801378a8(s_____Error_non_existant_cloud_id___8030f5f0);
    }
  }
LAB_80090030:
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
  FUN_80286124();
  return;
}

