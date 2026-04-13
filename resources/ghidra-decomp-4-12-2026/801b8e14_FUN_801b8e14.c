// Function: FUN_801b8e14
// Entry: 801b8e14
// Size: 744 bytes

/* WARNING: Removing unreachable block (ram,0x801b90dc) */
/* WARNING: Removing unreachable block (ram,0x801b90d4) */
/* WARNING: Removing unreachable block (ram,0x801b90cc) */
/* WARNING: Removing unreachable block (ram,0x801b8e34) */
/* WARNING: Removing unreachable block (ram,0x801b8e2c) */
/* WARNING: Removing unreachable block (ram,0x801b8e24) */

void FUN_801b8e14(int *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined4 *local_90;
  int aiStack_8c [7];
  float local_70;
  float local_6c;
  float local_68;
  
  fVar2 = FLOAT_803e577c;
  fVar1 = FLOAT_803e5778;
  pfVar6 = (float *)param_1[0x2e];
  if (*(char *)(pfVar6 + 1) == '\0') {
    param_1[9] = (int)((float)param_1[9] * FLOAT_803e577c);
    param_1[0xb] = (int)((float)param_1[0xb] * fVar2);
  }
  else {
    param_1[9] = (int)((float)param_1[9] * FLOAT_803e5778);
    param_1[0xb] = (int)((float)param_1[0xb] * fVar1);
  }
  fVar1 = FLOAT_803e5788;
  if (((((float)param_1[9] < FLOAT_803e5780) && (FLOAT_803e5784 < (float)param_1[9])) &&
      ((float)param_1[0xb] < FLOAT_803e5780)) && (FLOAT_803e5784 < (float)param_1[0xb])) {
    param_1[9] = (int)FLOAT_803e5788;
    param_1[0xb] = (int)fVar1;
  }
  FUN_8002ba34((double)((float)param_1[9] * FLOAT_803dc074),(double)FLOAT_803e5788,
               (double)((float)param_1[0xb] * FLOAT_803dc074),(int)param_1);
  iVar3 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x1,aiStack_8c,param_1,8,0xffffffff,0xff,
                       0);
  if (iVar3 != 0) {
    dVar11 = -(double)(float)param_1[9];
    dVar10 = -(double)(float)param_1[10];
    dVar9 = -(double)(float)param_1[0xb];
    dVar8 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                        (double)(float)(dVar11 * dVar11 +
                                                       (double)(float)(dVar10 * dVar10))));
    if ((double)FLOAT_803e5788 != dVar8) {
      dVar7 = (double)(float)((double)FLOAT_803e5770 / dVar8);
      dVar11 = (double)(float)(dVar11 * dVar7);
      dVar10 = (double)(float)(dVar10 * dVar7);
      dVar9 = (double)(float)(dVar9 * dVar7);
    }
    dVar7 = (double)(FLOAT_803e5790 *
                    (float)(dVar9 * (double)local_68 +
                           (double)(float)(dVar11 * (double)local_70 +
                                          (double)(float)(dVar10 * (double)local_6c))));
    param_1[9] = (int)(float)((double)local_70 * dVar7);
    param_1[10] = (int)(float)((double)local_6c * dVar7);
    param_1[0xb] = (int)(float)((double)local_68 * dVar7);
    param_1[9] = (int)(float)((double)(float)param_1[9] - dVar11);
    param_1[10] = (int)(float)((double)(float)param_1[10] - dVar10);
    param_1[0xb] = (int)(float)((double)(float)param_1[0xb] - dVar9);
    dVar9 = (double)FLOAT_803e5794;
    param_1[9] = (int)((float)param_1[9] * (float)(dVar9 * dVar8));
    param_1[10] = (int)((float)param_1[10] * (float)((double)FLOAT_803e5774 * dVar8));
    param_1[0xb] = (int)((float)param_1[0xb] * (float)(dVar9 * dVar8));
  }
  param_1[4] = (int)-(FLOAT_803e5798 * FLOAT_803dc074 - (float)param_1[4]);
  iVar3 = FUN_80065fcc((double)(float)param_1[3],(double)(float)param_1[4],(double)(float)param_1[5]
                       ,param_1,&local_90,0,0x11);
  *(undefined *)(pfVar6 + 1) = 0;
  iVar5 = 0;
  puVar4 = local_90;
  if (0 < iVar3) {
    do {
      if ((float)param_1[4] < FLOAT_803e579c + *(float *)*puVar4) {
        param_1[4] = *(int *)local_90[iVar5];
        FUN_80036800(*(int *)(local_90[iVar5] + 0x10),(int)param_1);
        *(undefined *)(pfVar6 + 1) = 1;
        break;
      }
      puVar4 = puVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if ((float)param_1[4] < *pfVar6) {
    param_1[4] = (int)*pfVar6;
  }
  FUN_800e85f4((int)param_1);
  return;
}

