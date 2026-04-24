// Function: FUN_801b8860
// Entry: 801b8860
// Size: 744 bytes

/* WARNING: Removing unreachable block (ram,0x801b8b20) */
/* WARNING: Removing unreachable block (ram,0x801b8b18) */
/* WARNING: Removing unreachable block (ram,0x801b8b28) */

void FUN_801b8860(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  float **ppfVar4;
  int iVar5;
  float *pfVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  float **local_90;
  undefined auStack140 [28];
  float local_70;
  float local_6c;
  float local_68;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  fVar2 = FLOAT_803e4ae4;
  fVar1 = FLOAT_803e4ae0;
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  pfVar6 = *(float **)(param_1 + 0xb8);
  if (*(char *)(pfVar6 + 1) == '\0') {
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e4ae4;
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar2;
  }
  else {
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e4ae0;
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  }
  fVar1 = FLOAT_803e4af0;
  if ((((*(float *)(param_1 + 0x24) < FLOAT_803e4ae8) &&
       (FLOAT_803e4aec < *(float *)(param_1 + 0x24))) &&
      (*(float *)(param_1 + 0x2c) < FLOAT_803e4ae8)) &&
     (FLOAT_803e4aec < *(float *)(param_1 + 0x2c))) {
    *(float *)(param_1 + 0x24) = FLOAT_803e4af0;
    *(float *)(param_1 + 0x2c) = fVar1;
  }
  FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),(double)FLOAT_803e4af0,
               (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
  iVar3 = FUN_800640cc((double)FLOAT_803e4af4,param_1 + 0x80,param_1 + 0xc,1,auStack140,param_1,8,
                       0xffffffff,0xff,0);
  if (iVar3 != 0) {
    dVar12 = -(double)*(float *)(param_1 + 0x24);
    dVar11 = -(double)*(float *)(param_1 + 0x28);
    dVar10 = -(double)*(float *)(param_1 + 0x2c);
    dVar9 = (double)FUN_802931a0((double)(float)(dVar10 * dVar10 +
                                                (double)(float)(dVar12 * dVar12 +
                                                               (double)(float)(dVar11 * dVar11))));
    if ((double)FLOAT_803e4af0 != dVar9) {
      dVar8 = (double)(float)((double)FLOAT_803e4ad8 / dVar9);
      dVar12 = (double)(float)(dVar12 * dVar8);
      dVar11 = (double)(float)(dVar11 * dVar8);
      dVar10 = (double)(float)(dVar10 * dVar8);
    }
    dVar8 = (double)(FLOAT_803e4af8 *
                    (float)(dVar10 * (double)local_68 +
                           (double)(float)(dVar12 * (double)local_70 +
                                          (double)(float)(dVar11 * (double)local_6c))));
    *(float *)(param_1 + 0x24) = (float)((double)local_70 * dVar8);
    *(float *)(param_1 + 0x28) = (float)((double)local_6c * dVar8);
    *(float *)(param_1 + 0x2c) = (float)((double)local_68 * dVar8);
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) - dVar12);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) - dVar11);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) - dVar10);
    dVar10 = (double)FLOAT_803e4afc;
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * (float)(dVar10 * dVar9);
    *(float *)(param_1 + 0x28) =
         *(float *)(param_1 + 0x28) * (float)((double)FLOAT_803e4adc * dVar9);
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * (float)(dVar10 * dVar9);
  }
  *(float *)(param_1 + 0x10) = -(FLOAT_803e4b00 * FLOAT_803db414 - *(float *)(param_1 + 0x10));
  iVar3 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,&local_90,0,0x11);
  *(undefined *)(pfVar6 + 1) = 0;
  iVar5 = 0;
  ppfVar4 = local_90;
  if (0 < iVar3) {
    do {
      if (*(float *)(param_1 + 0x10) < FLOAT_803e4b04 + **ppfVar4) {
        *(float *)(param_1 + 0x10) = *local_90[iVar5];
        FUN_80036708(local_90[iVar5][4],param_1);
        *(undefined *)(pfVar6 + 1) = 1;
        break;
      }
      ppfVar4 = ppfVar4 + 1;
      iVar5 = iVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (*(float *)(param_1 + 0x10) < *pfVar6) {
    *(float *)(param_1 + 0x10) = *pfVar6;
  }
  FUN_800e8370(param_1);
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  return;
}

