// Function: FUN_800916c0
// Entry: 800916c0
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x800919a8) */

void FUN_800916c0(double param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  uint *puVar7;
  float *pfVar8;
  float *pfVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f31;
  float local_40 [5];
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  sVar6 = FUN_80008b4c(0xffffffff);
  if (sVar6 != 1) {
    dVar12 = (double)FLOAT_803df1a0;
    puVar7 = &DAT_8039a848;
    pfVar9 = local_40;
    iVar10 = 6;
    pfVar8 = pfVar9;
    do {
      uStack36 = *puVar7 ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,*puVar7 ^ 0x80000000) - DOUBLE_803df1a8) -
              *param_3;
      uStack28 = puVar7[1] ^ 0x80000000;
      local_20 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,puVar7[1] ^ 0x80000000) - DOUBLE_803df1a8) -
              param_3[2];
      dVar14 = (double)(fVar1 * fVar1 + fVar2 * fVar2);
      if (dVar14 == dVar12) {
        *pfVar8 = FLOAT_803df1a0;
      }
      else {
        if (dVar12 < dVar14) {
          dVar13 = 1.0 / SQRT(dVar14);
          dVar13 = DOUBLE_803df218 * dVar13 * -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220);
          dVar13 = DOUBLE_803df218 * dVar13 * -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220);
          dVar14 = (double)(float)(dVar14 * DOUBLE_803df218 * dVar13 *
                                            -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220));
        }
        *pfVar8 = (float)dVar14;
      }
      if (*pfVar8 < FLOAT_803df1dc) {
        *pfVar8 = FLOAT_803df1dc;
      }
      puVar7 = puVar7 + 7;
      pfVar8 = pfVar8 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    iVar10 = 3;
    do {
      dVar14 = (double)*pfVar9;
      if ((double)FLOAT_803df1a0 < dVar14) {
        dVar13 = 1.0 / SQRT(dVar14);
        dVar13 = DOUBLE_803df218 * dVar13 * -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220);
        dVar13 = DOUBLE_803df218 * dVar13 * -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220);
        dVar14 = (double)(float)(dVar14 * DOUBLE_803df218 * dVar13 *
                                          -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220));
      }
      *pfVar9 = (float)((double)FLOAT_803df1a4 / dVar14);
      dVar14 = (double)pfVar9[1];
      if ((double)FLOAT_803df1a0 < dVar14) {
        dVar13 = 1.0 / SQRT(dVar14);
        dVar13 = DOUBLE_803df218 * dVar13 * -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220);
        dVar13 = DOUBLE_803df218 * dVar13 * -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220);
        dVar14 = (double)(float)(dVar14 * DOUBLE_803df218 * dVar13 *
                                          -(dVar14 * dVar13 * dVar13 - DOUBLE_803df220));
      }
      pfVar9[1] = (float)((double)FLOAT_803df1a4 / dVar14);
      pfVar9 = pfVar9 + 2;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    dVar14 = (double)DAT_8039a858;
    fVar1 = DAT_8039a874 * local_40[1];
    fVar2 = DAT_8039a890 * local_40[2];
    fVar3 = DAT_8039a8ac * local_40[3];
    fVar4 = DAT_8039a8c8 * local_40[4];
    fVar5 = DAT_8039a8e4 * local_2c;
    *param_2 = -(DAT_8039a8dc * local_2c +
                DAT_8039a8c0 * local_40[4] +
                DAT_8039a8a4 * local_40[3] +
                DAT_8039a888 * local_40[2] +
                DAT_8039a86c * local_40[1] +
                (float)((double)DAT_8039a850 * (double)local_40[0] + dVar12));
    param_2[2] = -(fVar5 + fVar4 + fVar3 + fVar2 + fVar1 + (float)(dVar14 * (double)local_40[0] +
                                                                  dVar12));
    param_2[1] = FLOAT_803df1a0;
    FUN_800701a4(param_2,param_2 + 1,param_2 + 2);
    *param_2 = (float)((double)*param_2 * param_1);
    param_2[1] = FLOAT_803df1a0;
    param_2[2] = (float)((double)param_2[2] * param_1);
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

