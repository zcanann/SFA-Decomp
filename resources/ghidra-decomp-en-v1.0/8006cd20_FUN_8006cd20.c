// Function: FUN_8006cd20
// Entry: 8006cd20
// Size: 768 bytes

void FUN_8006cd20(double param_1,double param_2,double param_3,float *param_4,int param_5,
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
  
  dVar5 = (double)FLOAT_803ded28;
  dVar6 = dVar5;
  if (0 < param_5) {
    do {
      dVar8 = (double)*param_4;
      if (param_3 < dVar8) {
        dVar8 = (double)(FLOAT_803ded3c + (float)((double)(float)(dVar8 - param_3) / dVar8));
        if ((double)FLOAT_803ded2c < dVar8) {
          dVar8 = (double)FLOAT_803ded2c;
        }
        if ((double)FLOAT_803ded28 < dVar8) {
          dVar7 = 1.0 / SQRT(dVar8);
          dVar7 = DOUBLE_803ded58 * dVar7 * -(dVar8 * dVar7 * dVar7 - DOUBLE_803ded60);
          dVar7 = DOUBLE_803ded58 * dVar7 * -(dVar8 * dVar7 * dVar7 - DOUBLE_803ded60);
          dVar8 = (double)(float)(dVar8 * DOUBLE_803ded58 * dVar7 *
                                          -(dVar8 * dVar7 * dVar7 - DOUBLE_803ded60));
        }
        fVar2 = ABS((float)((double)param_4[1] - param_1));
        fVar1 = ABS((float)((double)(float)((double)FLOAT_803ded2c + (double)param_4[1]) - param_1))
        ;
        if (fVar1 < fVar2) {
          fVar2 = fVar1;
        }
        fVar1 = ABS((float)((double)(param_4[1] - FLOAT_803ded2c) - param_1));
        if (fVar1 < fVar2) {
          fVar2 = fVar1;
        }
        dVar7 = (double)param_4[2];
        fVar1 = FLOAT_803ded28;
        if (dVar7 < param_2) {
          fVar1 = (float)(param_2 - dVar7);
        }
        fVar4 = ABS((float)((double)(float)((double)FLOAT_803ded2c + dVar7) - param_2));
        fVar3 = ABS((float)(dVar7 - param_2));
        if (fVar4 < ABS((float)(dVar7 - param_2))) {
          fVar3 = fVar4;
          fVar1 = FLOAT_803ded28;
        }
        dVar7 = (double)fVar1;
        dVar9 = (double)(param_4[2] - FLOAT_803ded2c);
        fVar1 = ABS((float)(dVar9 - param_2));
        if ((fVar1 < fVar3) && (fVar3 = fVar1, dVar9 < param_2)) {
          dVar7 = (double)(float)(param_2 - dVar9);
        }
        dVar9 = (double)(fVar2 * fVar2 + fVar3 * fVar3);
        if ((double)FLOAT_803ded28 < dVar9) {
          dVar10 = 1.0 / SQRT(dVar9);
          dVar10 = DOUBLE_803ded58 * dVar10 * -(dVar9 * dVar10 * dVar10 - DOUBLE_803ded60);
          dVar10 = DOUBLE_803ded58 * dVar10 * -(dVar9 * dVar10 * dVar10 - DOUBLE_803ded60);
          dVar9 = (double)(float)(dVar9 * DOUBLE_803ded58 * dVar10 *
                                          -(dVar9 * dVar10 * dVar10 - DOUBLE_803ded60));
        }
        dVar10 = (double)(float)(param_3 / (double)*param_4);
        if ((double)FLOAT_803ded28 < dVar10) {
          dVar11 = 1.0 / SQRT(dVar10);
          dVar11 = DOUBLE_803ded58 * dVar11 * -(dVar10 * dVar11 * dVar11 - DOUBLE_803ded60);
          dVar11 = DOUBLE_803ded58 * dVar11 * -(dVar10 * dVar11 * dVar11 - DOUBLE_803ded60);
          dVar10 = (double)(float)(dVar10 * DOUBLE_803ded58 * dVar11 *
                                            -(dVar10 * dVar11 * dVar11 - DOUBLE_803ded60));
        }
        dVar10 = -(double)(float)(dVar10 * (double)(float)((double)param_4[3] - (double)param_4[4])
                                 - (double)param_4[3]);
        if (dVar9 <= dVar10) {
          dVar9 = (double)(FLOAT_803ded2c - (float)(dVar9 / dVar10));
          if ((double)FLOAT_803ded28 < dVar9) {
            dVar11 = 1.0 / SQRT(dVar9);
            dVar11 = DOUBLE_803ded58 * dVar11 * -(dVar9 * dVar11 * dVar11 - DOUBLE_803ded60);
            dVar11 = DOUBLE_803ded58 * dVar11 * -(dVar9 * dVar11 * dVar11 - DOUBLE_803ded60);
            dVar9 = (double)(float)(dVar9 * DOUBLE_803ded58 * dVar11 *
                                            -(dVar9 * dVar11 * dVar11 - DOUBLE_803ded60));
          }
          dVar5 = (double)(float)(dVar8 * dVar9 + dVar5);
          dVar6 = (double)(FLOAT_803ded38 *
                           -(float)(param_3 * (double)FLOAT_803dedd0 - (double)FLOAT_803ded2c) +
                          (float)(dVar6 + (double)(float)(dVar7 / dVar10)));
        }
      }
      param_4 = param_4 + 5;
      param_5 = param_5 + -1;
    } while (param_5 != 0);
  }
  if ((double)FLOAT_803ded2c < dVar5) {
    dVar5 = (double)FLOAT_803ded2c;
  }
  if ((double)FLOAT_803ded2c < dVar6) {
    dVar6 = (double)FLOAT_803ded2c;
  }
  *param_6 = (float)((double)FLOAT_803ded40 * dVar6 + (double)FLOAT_803dedd4);
  *param_7 = (float)dVar5;
  return;
}

