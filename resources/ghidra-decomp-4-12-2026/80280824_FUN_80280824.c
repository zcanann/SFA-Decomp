// Function: FUN_80280824
// Entry: 80280824
// Size: 1252 bytes

void FUN_80280824(int param_1,float *param_2,float *param_3,float *param_4,float *param_5,
                 float *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 *puVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  float local_a0;
  float local_9c;
  float local_98;
  
  iVar4 = 0;
  dVar12 = (double)FLOAT_803e8518;
  *param_2 = FLOAT_803e8518;
  dVar14 = (double)FLOAT_803e853c;
  *param_3 = FLOAT_803e853c;
  dVar15 = (double)FLOAT_803e8548;
  dVar10 = dVar12;
  dVar11 = dVar12;
  dVar13 = dVar12;
  dVar16 = DOUBLE_803e8530;
  dVar17 = DOUBLE_803e8540;
  for (puVar5 = DAT_803defd8; dVar6 = DOUBLE_803e8520, puVar5 != (undefined4 *)0x0;
      puVar5 = (undefined4 *)*puVar5) {
    fVar1 = (float)puVar5[7];
    fVar2 = *(float *)(param_1 + 0x14) - ((float)puVar5[4] + (float)puVar5[0xb] * fVar1);
    fVar3 = *(float *)(param_1 + 0x18) - ((float)puVar5[5] + (float)puVar5[0xc] * fVar1);
    fVar1 = *(float *)(param_1 + 0x1c) - ((float)puVar5[6] + (float)puVar5[0xd] * fVar1);
    dVar6 = (double)(fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3);
    if (dVar13 < dVar6) {
      dVar7 = 1.0 / SQRT(dVar6);
      dVar7 = dVar16 * dVar7 * (dVar17 - dVar6 * dVar7 * dVar7);
      dVar7 = dVar16 * dVar7 * (dVar17 - dVar6 * dVar7 * dVar7);
      dVar6 = (double)(float)(dVar6 * dVar16 * dVar7 * (dVar17 - dVar6 * dVar7 * dVar7));
    }
    if (dVar6 <= (double)*(float *)(param_1 + 0x2c)) {
      dVar9 = (double)(float)(dVar6 / (double)*(float *)(param_1 + 0x2c));
      dVar7 = (double)*(float *)(param_1 + 0x38);
      if (dVar7 < dVar13) {
        *param_2 = *param_2 +
                   (float)puVar5[0x23] *
                   (*(float *)(param_1 + 0x34) +
                   (*(float *)(param_1 + 0x30) - *(float *)(param_1 + 0x34)) *
                   (float)(dVar14 - (double)((float)((double)(float)(dVar14 + dVar7) * dVar9) -
                                            (float)(dVar7 * (double)(float)(dVar14 - (double)((float
                                                  )(dVar14 - dVar9) * (float)(dVar14 - dVar9)))))));
      }
      else {
        *param_2 = *param_2 +
                   (float)puVar5[0x23] *
                   (*(float *)(param_1 + 0x34) +
                   (*(float *)(param_1 + 0x30) - *(float *)(param_1 + 0x34)) *
                   (float)(dVar14 - (double)((float)((double)(float)(dVar14 - dVar7) * dVar9) +
                                            (float)(dVar9 * (double)(float)(dVar7 * dVar9)))));
      }
      if ((*(uint *)(param_1 + 0x10) & 0x80000) == 0) {
        if (((*(uint *)(param_1 + 0x10) & 8) != 0) || ((puVar5[3] & 1) != 0)) {
          fVar1 = (float)puVar5[8] - *(float *)(param_1 + 0x20);
          fVar2 = (float)puVar5[9] - *(float *)(param_1 + 0x24);
          fVar3 = (float)puVar5[10] - *(float *)(param_1 + 0x28);
          dVar7 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2);
          if (dVar13 < dVar7) {
            dVar9 = 1.0 / SQRT(dVar7);
            dVar9 = dVar16 * dVar9 * (dVar17 - dVar7 * dVar9 * dVar9);
            dVar9 = dVar16 * dVar9 * (dVar17 - dVar7 * dVar9 * dVar9);
            dVar7 = (double)(float)(dVar7 * dVar16 * dVar9 * (dVar17 - dVar7 * dVar9 * dVar9));
          }
          if (dVar13 < dVar7) {
            fVar1 = (*(float *)(param_1 + 0x14) +
                    (float)((double)*(float *)(param_1 + 0x20) * dVar15)) -
                    ((float)puVar5[4] + (float)((double)(float)puVar5[8] * dVar15));
            fVar2 = (*(float *)(param_1 + 0x18) +
                    (float)((double)*(float *)(param_1 + 0x24) * dVar15)) -
                    ((float)puVar5[5] + (float)((double)(float)puVar5[9] * dVar15));
            fVar3 = (*(float *)(param_1 + 0x1c) +
                    (float)((double)*(float *)(param_1 + 0x28) * dVar15)) -
                    ((float)puVar5[6] + (float)((double)(float)puVar5[10] * dVar15));
            dVar9 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2);
            if (dVar13 < dVar9) {
              dVar8 = 1.0 / SQRT(dVar9);
              dVar8 = dVar16 * dVar8 * (dVar17 - dVar9 * dVar8 * dVar8);
              dVar8 = dVar16 * dVar8 * (dVar17 - dVar9 * dVar8 * dVar8);
              dVar9 = (double)(float)(dVar9 * dVar16 * dVar8 * (dVar17 - dVar9 * dVar8 * dVar8));
            }
            if (dVar6 <= dVar9) {
              *param_3 = (float)((double)(float)puVar5[0x22] /
                                (double)(float)((double)(float)puVar5[0x22] + dVar7));
            }
            else {
              *param_3 = (float)((double)(float)puVar5[0x22] /
                                (double)(float)((double)(float)puVar5[0x22] - dVar7));
            }
          }
        }
        if (dVar13 != dVar6) {
          FUN_80281914((float *)(puVar5 + 0x14),(float *)(param_1 + 0x14),&local_a0);
          dVar6 = (double)local_98;
          if (dVar13 < dVar6) {
            fVar1 = FLOAT_803e8528;
            if (dVar6 < (double)(float)puVar5[0x21]) {
              fVar1 = (float)(-dVar6 / (double)(float)puVar5[0x21]);
            }
          }
          else {
            fVar1 = FLOAT_803e853c;
            if (-(double)(float)puVar5[0x20] < dVar6) {
              fVar1 = (float)(-dVar6 / (double)(float)puVar5[0x20]);
            }
          }
          dVar11 = (double)(float)(dVar11 + (double)fVar1);
          if (((dVar13 != (double)local_a0) || (dVar13 != (double)local_9c)) || (dVar13 != dVar6)) {
            FUN_802819c0(&local_a0);
          }
          dVar12 = (double)(float)(dVar12 + (double)local_a0);
          dVar10 = (double)(float)(dVar10 - (double)local_9c);
        }
      }
    }
    iVar4 = iVar4 + 1;
  }
  if (iVar4 != 0) {
    dVar13 = (double)CONCAT44(0x43300000,iVar4) - DOUBLE_803e8520;
    *param_4 = (float)(dVar12 / (double)(float)((double)CONCAT44(0x43300000,iVar4) - DOUBLE_803e8520
                                               ));
    *param_5 = (float)(dVar10 / (double)(float)dVar13);
    *param_6 = (float)(dVar11 / (double)(float)((double)CONCAT44(0x43300000,iVar4) - dVar6));
  }
  return;
}

