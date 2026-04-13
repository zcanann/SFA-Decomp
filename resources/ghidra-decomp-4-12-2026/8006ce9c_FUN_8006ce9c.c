// Function: FUN_8006ce9c
// Entry: 8006ce9c
// Size: 768 bytes

void FUN_8006ce9c(double param_1,double param_2,double param_3,float *param_4,int param_5,
                 float *param_6,float *param_7)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  
  dVar5 = (double)FLOAT_803df9a8;
  dVar6 = dVar5;
  if (0 < param_5) {
    do {
      dVar8 = (double)*param_4;
      if (param_3 < dVar8) {
        dVar8 = (double)(FLOAT_803df9bc + (float)((double)(float)(dVar8 - param_3) / dVar8));
        if ((double)FLOAT_803df9ac < dVar8) {
          dVar8 = (double)FLOAT_803df9ac;
        }
        if ((double)FLOAT_803df9a8 < dVar8) {
          dVar7 = 1.0 / SQRT(dVar8);
          dVar7 = DOUBLE_803df9d8 * dVar7 * -(dVar8 * dVar7 * dVar7 - DOUBLE_803df9e0);
          dVar7 = DOUBLE_803df9d8 * dVar7 * -(dVar8 * dVar7 * dVar7 - DOUBLE_803df9e0);
          dVar8 = (double)(float)(dVar8 * DOUBLE_803df9d8 * dVar7 *
                                          -(dVar8 * dVar7 * dVar7 - DOUBLE_803df9e0));
        }
        fVar2 = ABS((float)((double)param_4[1] - param_1));
        fVar1 = ABS((float)((double)(float)((double)FLOAT_803df9ac + (double)param_4[1]) - param_1))
        ;
        if (fVar1 < fVar2) {
          fVar2 = fVar1;
        }
        fVar1 = ABS((float)((double)(param_4[1] - FLOAT_803df9ac) - param_1));
        if (fVar1 < fVar2) {
          fVar2 = fVar1;
        }
        dVar7 = (double)param_4[2];
        fVar1 = FLOAT_803df9a8;
        if (dVar7 < param_2) {
          fVar1 = (float)(param_2 - dVar7);
        }
        fVar4 = ABS((float)((double)(float)((double)FLOAT_803df9ac + dVar7) - param_2));
        fVar3 = ABS((float)(dVar7 - param_2));
        if (fVar4 < ABS((float)(dVar7 - param_2))) {
          fVar3 = fVar4;
          fVar1 = FLOAT_803df9a8;
        }
        dVar7 = (double)fVar1;
        dVar9 = (double)(param_4[2] - FLOAT_803df9ac);
        fVar1 = ABS((float)(dVar9 - param_2));
        if ((fVar1 < fVar3) && (fVar3 = fVar1, dVar9 < param_2)) {
          dVar7 = (double)(float)(param_2 - dVar9);
        }
        dVar9 = (double)(fVar2 * fVar2 + fVar3 * fVar3);
        if ((double)FLOAT_803df9a8 < dVar9) {
          dVar10 = 1.0 / SQRT(dVar9);
          dVar10 = DOUBLE_803df9d8 * dVar10 * -(dVar9 * dVar10 * dVar10 - DOUBLE_803df9e0);
          dVar10 = DOUBLE_803df9d8 * dVar10 * -(dVar9 * dVar10 * dVar10 - DOUBLE_803df9e0);
          dVar9 = (double)(float)(dVar9 * DOUBLE_803df9d8 * dVar10 *
                                          -(dVar9 * dVar10 * dVar10 - DOUBLE_803df9e0));
        }
        dVar10 = (double)(float)(param_3 / (double)*param_4);
        if ((double)FLOAT_803df9a8 < dVar10) {
          dVar11 = 1.0 / SQRT(dVar10);
          dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar10 * dVar11 * dVar11 - DOUBLE_803df9e0);
          dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar10 * dVar11 * dVar11 - DOUBLE_803df9e0);
          dVar10 = (double)(float)(dVar10 * DOUBLE_803df9d8 * dVar11 *
                                            -(dVar10 * dVar11 * dVar11 - DOUBLE_803df9e0));
        }
        dVar10 = -(double)(float)(dVar10 * (double)(float)((double)param_4[3] - (double)param_4[4])
                                 - (double)param_4[3]);
        if (dVar9 <= dVar10) {
          dVar9 = (double)(FLOAT_803df9ac - (float)(dVar9 / dVar10));
          if ((double)FLOAT_803df9a8 < dVar9) {
            dVar11 = 1.0 / SQRT(dVar9);
            dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar9 * dVar11 * dVar11 - DOUBLE_803df9e0);
            dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar9 * dVar11 * dVar11 - DOUBLE_803df9e0);
            dVar9 = (double)(float)(dVar9 * DOUBLE_803df9d8 * dVar11 *
                                            -(dVar9 * dVar11 * dVar11 - DOUBLE_803df9e0));
          }
          dVar5 = (double)(float)(dVar8 * dVar9 + dVar5);
          dVar6 = (double)(FLOAT_803df9b8 *
                           -(float)(param_3 * (double)FLOAT_803dfa50 - (double)FLOAT_803df9ac) +
                          (float)(dVar6 + (double)(float)(dVar7 / dVar10)));
        }
      }
      param_4 = param_4 + 5;
      param_5 = param_5 + -1;
    } while (param_5 != 0);
  }
  if ((double)FLOAT_803df9ac < dVar5) {
    dVar5 = (double)FLOAT_803df9ac;
  }
  if ((double)FLOAT_803df9ac < dVar6) {
    dVar6 = (double)FLOAT_803df9ac;
  }
  *param_6 = (float)((double)FLOAT_803df9c0 * dVar6 + (double)FLOAT_803dfa54);
  *param_7 = (float)dVar5;
  return;
}

