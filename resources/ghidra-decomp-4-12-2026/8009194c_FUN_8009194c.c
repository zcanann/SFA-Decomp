// Function: FUN_8009194c
// Entry: 8009194c
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x80091c34) */
/* WARNING: Removing unreachable block (ram,0x8009195c) */

void FUN_8009194c(double param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  uint *puVar7;
  float *pfVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  float local_40 [5];
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar6 = FUN_80008b4c(-1);
  if ((short)iVar6 != 1) {
    dVar10 = (double)FLOAT_803dfe20;
    puVar7 = &DAT_8039b4a8;
    pfVar9 = local_40;
    iVar6 = 6;
    pfVar8 = pfVar9;
    do {
      uStack_24 = *puVar7 ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,*puVar7 ^ 0x80000000) - DOUBLE_803dfe28) -
              *param_3;
      uStack_1c = puVar7[1] ^ 0x80000000;
      local_20 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,puVar7[1] ^ 0x80000000) - DOUBLE_803dfe28) -
              param_3[2];
      dVar12 = (double)(fVar1 * fVar1 + fVar2 * fVar2);
      if (dVar12 == dVar10) {
        *pfVar8 = FLOAT_803dfe20;
      }
      else {
        if (dVar10 < dVar12) {
          dVar11 = 1.0 / SQRT(dVar12);
          dVar11 = DOUBLE_803dfe98 * dVar11 * -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0);
          dVar11 = DOUBLE_803dfe98 * dVar11 * -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0);
          dVar12 = (double)(float)(dVar12 * DOUBLE_803dfe98 * dVar11 *
                                            -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0));
        }
        *pfVar8 = (float)dVar12;
      }
      if (*pfVar8 < FLOAT_803dfe5c) {
        *pfVar8 = FLOAT_803dfe5c;
      }
      puVar7 = puVar7 + 7;
      pfVar8 = pfVar8 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 3;
    do {
      dVar12 = (double)*pfVar9;
      if ((double)FLOAT_803dfe20 < dVar12) {
        dVar11 = 1.0 / SQRT(dVar12);
        dVar11 = DOUBLE_803dfe98 * dVar11 * -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0);
        dVar11 = DOUBLE_803dfe98 * dVar11 * -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0);
        dVar12 = (double)(float)(dVar12 * DOUBLE_803dfe98 * dVar11 *
                                          -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0));
      }
      *pfVar9 = (float)((double)FLOAT_803dfe24 / dVar12);
      dVar12 = (double)pfVar9[1];
      if ((double)FLOAT_803dfe20 < dVar12) {
        dVar11 = 1.0 / SQRT(dVar12);
        dVar11 = DOUBLE_803dfe98 * dVar11 * -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0);
        dVar11 = DOUBLE_803dfe98 * dVar11 * -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0);
        dVar12 = (double)(float)(dVar12 * DOUBLE_803dfe98 * dVar11 *
                                          -(dVar12 * dVar11 * dVar11 - DOUBLE_803dfea0));
      }
      pfVar9[1] = (float)((double)FLOAT_803dfe24 / dVar12);
      pfVar9 = pfVar9 + 2;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    dVar12 = (double)DAT_8039b4b8;
    fVar1 = DAT_8039b4d4 * local_40[1];
    fVar2 = DAT_8039b4f0 * local_40[2];
    fVar3 = DAT_8039b50c * local_40[3];
    fVar4 = DAT_8039b528 * local_40[4];
    fVar5 = DAT_8039b544 * local_2c;
    *param_2 = -(DAT_8039b53c * local_2c +
                DAT_8039b520 * local_40[4] +
                DAT_8039b504 * local_40[3] +
                DAT_8039b4e8 * local_40[2] +
                DAT_8039b4cc * local_40[1] +
                (float)((double)DAT_8039b4b0 * (double)local_40[0] + dVar10));
    param_2[2] = -(fVar5 + fVar4 + fVar3 + fVar2 + fVar1 + (float)(dVar12 * (double)local_40[0] +
                                                                  dVar10));
    param_2[1] = FLOAT_803dfe20;
    FUN_80070320(param_2,param_2 + 1,param_2 + 2);
    *param_2 = (float)((double)*param_2 * param_1);
    param_2[1] = FLOAT_803dfe20;
    param_2[2] = (float)((double)param_2[2] * param_1);
  }
  return;
}

