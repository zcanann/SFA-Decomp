// Function: FUN_800e1b24
// Entry: 800e1b24
// Size: 1040 bytes

/* WARNING: Removing unreachable block (ram,0x800e1f10) */
/* WARNING: Removing unreachable block (ram,0x800e1f00) */
/* WARNING: Removing unreachable block (ram,0x800e1ef0) */
/* WARNING: Removing unreachable block (ram,0x800e1ee0) */
/* WARNING: Removing unreachable block (ram,0x800e1ed0) */
/* WARNING: Removing unreachable block (ram,0x800e1ed8) */
/* WARNING: Removing unreachable block (ram,0x800e1ee8) */
/* WARNING: Removing unreachable block (ram,0x800e1ef8) */
/* WARNING: Removing unreachable block (ram,0x800e1f08) */
/* WARNING: Removing unreachable block (ram,0x800e1f18) */

undefined4
FUN_800e1b24(double param_1,double param_2,double param_3,uint *param_4,float *param_5,
            float *param_6,float *param_7)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f22;
  double dVar14;
  undefined8 in_f23;
  undefined8 in_f24;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar15;
  double dVar16;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  int local_c8 [7];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
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
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  piVar7 = local_c8;
  iVar9 = 2;
  do {
    uVar6 = *param_4;
    if ((int)uVar6 < 0) {
      iVar8 = 0;
    }
    else {
      iVar4 = 0;
      iVar5 = DAT_803dd478 + -1;
      while (iVar4 <= iVar5) {
        iVar3 = iVar5 + iVar4 >> 1;
        iVar8 = (&DAT_803a17e8)[iVar3];
        if (*(uint *)(iVar8 + 0x14) < uVar6) {
          iVar4 = iVar3 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar6) goto LAB_800e1c24;
          iVar5 = iVar3 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e1c24:
    *piVar7 = iVar8;
    uVar6 = param_4[1];
    if ((int)uVar6 < 0) {
      iVar8 = 0;
    }
    else {
      iVar4 = 0;
      iVar5 = DAT_803dd478 + -1;
      while (iVar4 <= iVar5) {
        iVar3 = iVar5 + iVar4 >> 1;
        iVar8 = (&DAT_803a17e8)[iVar3];
        if (*(uint *)(iVar8 + 0x14) < uVar6) {
          iVar4 = iVar3 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar6) goto LAB_800e1c90;
          iVar5 = iVar3 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e1c90:
    piVar7[1] = iVar8;
    param_4 = param_4 + 2;
    piVar7 = piVar7 + 2;
    iVar9 = iVar9 + -1;
    if (iVar9 == 0) {
      dVar12 = (double)(*(float *)(local_c8[2] + 8) - *(float *)(local_c8[1] + 8));
      dVar13 = (double)(*(float *)(local_c8[2] + 0x10) - *(float *)(local_c8[1] + 0x10));
      dVar11 = dVar13;
      dVar14 = dVar12;
      if (local_c8[0] != 0) {
        dVar11 = (double)(*(float *)(local_c8[1] + 0x10) - *(float *)(local_c8[0] + 0x10));
        dVar14 = (double)(*(float *)(local_c8[1] + 8) - *(float *)(local_c8[0] + 8));
      }
      dVar15 = (double)(FLOAT_803e0658 * (float)(dVar14 + dVar12));
      dVar14 = (double)(FLOAT_803e0658 * (float)(dVar11 + dVar13));
      dVar11 = (double)FUN_802931a0((double)(float)(dVar15 * dVar15 +
                                                   (double)(float)(dVar14 * dVar14)));
      if ((double)FLOAT_803e0638 != dVar11) {
        dVar15 = (double)(float)(dVar15 / dVar11);
        dVar14 = (double)(float)(dVar14 / dVar11);
      }
      dVar11 = (double)(float)(dVar15 * dVar12 + (double)(float)(dVar14 * dVar13));
      if ((double)FLOAT_803e0638 != dVar11) {
        dVar11 = (double)(float)(-(double)(-(float)(dVar15 * (double)*(float *)(local_c8[1] + 8) +
                                                   (double)(float)(dVar14 * (double)*(float *)(
                                                  local_c8[1] + 0x10))) +
                                          (float)(dVar15 * param_1 +
                                                 (double)(float)(dVar14 * param_3))) / dVar11);
      }
      dVar18 = (double)(float)((double)*(float *)(local_c8[2] + 8) -
                              (double)*(float *)(local_c8[1] + 8));
      dVar17 = (double)(float)((double)*(float *)(local_c8[2] + 0x10) -
                              (double)*(float *)(local_c8[1] + 0x10));
      dVar14 = dVar17;
      dVar15 = dVar18;
      if (local_c8[3] != 0) {
        dVar14 = (double)(float)((double)*(float *)(local_c8[3] + 0x10) -
                                (double)*(float *)(local_c8[2] + 0x10));
        dVar15 = (double)(float)((double)*(float *)(local_c8[3] + 8) -
                                (double)*(float *)(local_c8[2] + 8));
      }
      dVar16 = (double)(FLOAT_803e0658 * (float)(dVar15 + dVar18));
      dVar15 = (double)(FLOAT_803e0658 * (float)(dVar14 + dVar17));
      dVar14 = (double)FUN_802931a0((double)(float)(dVar16 * dVar16 +
                                                   (double)(float)(dVar15 * dVar15)));
      if ((double)FLOAT_803e0638 != dVar14) {
        dVar16 = (double)(float)(dVar16 / dVar14);
        dVar15 = (double)(float)(dVar15 / dVar14);
      }
      dVar14 = (double)(float)(dVar16 * dVar12 + (double)(float)(dVar15 * dVar13));
      if ((double)FLOAT_803e0638 != dVar14) {
        dVar14 = (double)(float)(-(double)(-(float)(dVar16 * (double)*(float *)(local_c8[2] + 8) +
                                                   (double)(float)(dVar15 * (double)*(float *)(
                                                  local_c8[2] + 0x10))) +
                                          (float)(dVar16 * param_1 +
                                                 (double)(float)(dVar15 * param_3))) / dVar14);
      }
      dVar11 = (double)(float)(-dVar11 / (double)(float)(dVar14 - dVar11));
      if ((dVar11 < (double)FLOAT_803e0638) || ((double)FLOAT_803e0634 <= dVar11)) {
        uVar2 = 0;
      }
      else {
        dVar15 = (double)(*(float *)(local_c8[2] + 0xc) - *(float *)(local_c8[1] + 0xc));
        dVar14 = (double)FUN_802931a0((double)(float)(dVar17 * dVar17 +
                                                     (double)(float)(dVar18 * dVar18 +
                                                                    (double)(float)(dVar15 * dVar15)
                                                                    )));
        if ((double)FLOAT_803e0638 < dVar14) {
          dVar12 = (double)(float)(-dVar18 * (double)(float)((double)FLOAT_803e0634 / dVar14));
          dVar13 = (double)(float)(-dVar17 * (double)(float)((double)FLOAT_803e0634 / dVar14));
        }
        fVar1 = *(float *)(local_c8[1] + 0xc);
        *param_5 = -(float)((double)(float)(dVar18 * dVar11 + (double)*(float *)(local_c8[1] + 8)) *
                            dVar13 - (double)(float)((double)(float)(dVar17 * dVar11 +
                                                                    (double)*(float *)(local_c8[1] +
                                                                                      0x10)) *
                                                    dVar12)) +
                   (float)(param_1 * dVar13 - (double)(float)(param_3 * dVar12));
        *param_6 = (float)(param_2 - (double)(float)(dVar15 * dVar11 + (double)fVar1));
        *param_7 = (float)dVar11;
        uVar2 = 1;
      }
      __psq_l0(auStack8,uVar10);
      __psq_l1(auStack8,uVar10);
      __psq_l0(auStack24,uVar10);
      __psq_l1(auStack24,uVar10);
      __psq_l0(auStack40,uVar10);
      __psq_l1(auStack40,uVar10);
      __psq_l0(auStack56,uVar10);
      __psq_l1(auStack56,uVar10);
      __psq_l0(auStack72,uVar10);
      __psq_l1(auStack72,uVar10);
      __psq_l0(auStack88,uVar10);
      __psq_l1(auStack88,uVar10);
      __psq_l0(auStack104,uVar10);
      __psq_l1(auStack104,uVar10);
      __psq_l0(auStack120,uVar10);
      __psq_l1(auStack120,uVar10);
      __psq_l0(auStack136,uVar10);
      __psq_l1(auStack136,uVar10);
      __psq_l0(auStack152,uVar10);
      __psq_l1(auStack152,uVar10);
      return uVar2;
    }
  } while( true );
}

