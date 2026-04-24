// Function: FUN_800e1da8
// Entry: 800e1da8
// Size: 1040 bytes

/* WARNING: Removing unreachable block (ram,0x800e219c) */
/* WARNING: Removing unreachable block (ram,0x800e2194) */
/* WARNING: Removing unreachable block (ram,0x800e218c) */
/* WARNING: Removing unreachable block (ram,0x800e2184) */
/* WARNING: Removing unreachable block (ram,0x800e217c) */
/* WARNING: Removing unreachable block (ram,0x800e2174) */
/* WARNING: Removing unreachable block (ram,0x800e216c) */
/* WARNING: Removing unreachable block (ram,0x800e2164) */
/* WARNING: Removing unreachable block (ram,0x800e215c) */
/* WARNING: Removing unreachable block (ram,0x800e2154) */
/* WARNING: Removing unreachable block (ram,0x800e1e00) */
/* WARNING: Removing unreachable block (ram,0x800e1df8) */
/* WARNING: Removing unreachable block (ram,0x800e1df0) */
/* WARNING: Removing unreachable block (ram,0x800e1de8) */
/* WARNING: Removing unreachable block (ram,0x800e1de0) */
/* WARNING: Removing unreachable block (ram,0x800e1dd8) */
/* WARNING: Removing unreachable block (ram,0x800e1dd0) */
/* WARNING: Removing unreachable block (ram,0x800e1dc8) */
/* WARNING: Removing unreachable block (ram,0x800e1dc0) */
/* WARNING: Removing unreachable block (ram,0x800e1db8) */

undefined4
FUN_800e1da8(double param_1,double param_2,double param_3,uint *param_4,float *param_5,
            float *param_6,float *param_7)

{
  float fVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  int local_c8 [7];
  
  iVar9 = 2;
  piVar2 = (int *)&stack0xffffff30;
  do {
    uVar7 = *param_4;
    if ((int)uVar7 < 0) {
      iVar8 = 0;
    }
    else {
      iVar5 = 0;
      iVar6 = DAT_803de0f0 + -1;
      while (iVar5 <= iVar6) {
        iVar4 = iVar6 + iVar5 >> 1;
        iVar8 = (&DAT_803a2448)[iVar4];
        if (*(uint *)(iVar8 + 0x14) < uVar7) {
          iVar5 = iVar4 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar7) goto LAB_800e1ea8;
          iVar6 = iVar4 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e1ea8:
    piVar2[2] = iVar8;
    uVar7 = param_4[1];
    if ((int)uVar7 < 0) {
      iVar8 = 0;
    }
    else {
      iVar5 = 0;
      iVar6 = DAT_803de0f0 + -1;
      while (iVar5 <= iVar6) {
        iVar4 = iVar6 + iVar5 >> 1;
        iVar8 = (&DAT_803a2448)[iVar4];
        if (*(uint *)(iVar8 + 0x14) < uVar7) {
          iVar5 = iVar4 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar7) goto LAB_800e1f14;
          iVar6 = iVar4 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e1f14:
    piVar2[3] = iVar8;
    param_4 = param_4 + 2;
    iVar9 = iVar9 + -1;
    piVar2 = piVar2 + 2;
    if (iVar9 == 0) {
      dVar11 = (double)(*(float *)(local_c8[2] + 8) - *(float *)(local_c8[1] + 8));
      dVar12 = (double)(*(float *)(local_c8[2] + 0x10) - *(float *)(local_c8[1] + 0x10));
      dVar10 = dVar12;
      dVar13 = dVar11;
      if (local_c8[0] != 0) {
        dVar10 = (double)(*(float *)(local_c8[1] + 0x10) - *(float *)(local_c8[0] + 0x10));
        dVar13 = (double)(*(float *)(local_c8[1] + 8) - *(float *)(local_c8[0] + 8));
      }
      dVar14 = (double)(FLOAT_803e12d8 * (float)(dVar13 + dVar11));
      dVar13 = (double)(FLOAT_803e12d8 * (float)(dVar10 + dVar12));
      dVar10 = FUN_80293900((double)(float)(dVar14 * dVar14 + (double)(float)(dVar13 * dVar13)));
      if ((double)FLOAT_803e12b8 != dVar10) {
        dVar14 = (double)(float)(dVar14 / dVar10);
        dVar13 = (double)(float)(dVar13 / dVar10);
      }
      dVar10 = (double)(float)(dVar14 * dVar11 + (double)(float)(dVar13 * dVar12));
      if ((double)FLOAT_803e12b8 != dVar10) {
        dVar10 = (double)(float)(-(double)(-(float)(dVar14 * (double)*(float *)(local_c8[1] + 8) +
                                                   (double)(float)(dVar13 * (double)*(float *)(
                                                  local_c8[1] + 0x10))) +
                                          (float)(dVar14 * param_1 +
                                                 (double)(float)(dVar13 * param_3))) / dVar10);
      }
      dVar17 = (double)(float)((double)*(float *)(local_c8[2] + 8) -
                              (double)*(float *)(local_c8[1] + 8));
      dVar16 = (double)(float)((double)*(float *)(local_c8[2] + 0x10) -
                              (double)*(float *)(local_c8[1] + 0x10));
      dVar13 = dVar16;
      dVar14 = dVar17;
      if (local_c8[3] != 0) {
        dVar13 = (double)(float)((double)*(float *)(local_c8[3] + 0x10) -
                                (double)*(float *)(local_c8[2] + 0x10));
        dVar14 = (double)(float)((double)*(float *)(local_c8[3] + 8) -
                                (double)*(float *)(local_c8[2] + 8));
      }
      dVar15 = (double)(FLOAT_803e12d8 * (float)(dVar14 + dVar17));
      dVar14 = (double)(FLOAT_803e12d8 * (float)(dVar13 + dVar16));
      dVar13 = FUN_80293900((double)(float)(dVar15 * dVar15 + (double)(float)(dVar14 * dVar14)));
      if ((double)FLOAT_803e12b8 != dVar13) {
        dVar15 = (double)(float)(dVar15 / dVar13);
        dVar14 = (double)(float)(dVar14 / dVar13);
      }
      dVar13 = (double)(float)(dVar15 * dVar11 + (double)(float)(dVar14 * dVar12));
      if ((double)FLOAT_803e12b8 != dVar13) {
        dVar13 = (double)(float)(-(double)(-(float)(dVar15 * (double)*(float *)(local_c8[2] + 8) +
                                                   (double)(float)(dVar14 * (double)*(float *)(
                                                  local_c8[2] + 0x10))) +
                                          (float)(dVar15 * param_1 +
                                                 (double)(float)(dVar14 * param_3))) / dVar13);
      }
      dVar10 = (double)(float)(-dVar10 / (double)(float)(dVar13 - dVar10));
      if ((dVar10 < (double)FLOAT_803e12b8) || ((double)FLOAT_803e12b4 <= dVar10)) {
        uVar3 = 0;
      }
      else {
        dVar14 = (double)(*(float *)(local_c8[2] + 0xc) - *(float *)(local_c8[1] + 0xc));
        dVar13 = FUN_80293900((double)(float)(dVar16 * dVar16 +
                                             (double)(float)(dVar17 * dVar17 +
                                                            (double)(float)(dVar14 * dVar14))));
        if ((double)FLOAT_803e12b8 < dVar13) {
          dVar11 = (double)(float)(-dVar17 * (double)(float)((double)FLOAT_803e12b4 / dVar13));
          dVar12 = (double)(float)(-dVar16 * (double)(float)((double)FLOAT_803e12b4 / dVar13));
        }
        fVar1 = *(float *)(local_c8[1] + 0xc);
        *param_5 = -(float)((double)(float)(dVar17 * dVar10 + (double)*(float *)(local_c8[1] + 8)) *
                            dVar12 - (double)(float)((double)(float)(dVar16 * dVar10 +
                                                                    (double)*(float *)(local_c8[1] +
                                                                                      0x10)) *
                                                    dVar11)) +
                   (float)(param_1 * dVar12 - (double)(float)(param_3 * dVar11));
        *param_6 = (float)(param_2 - (double)(float)(dVar14 * dVar10 + (double)fVar1));
        *param_7 = (float)dVar10;
        uVar3 = 1;
      }
      return uVar3;
    }
  } while( true );
}

