// Function: FUN_80179a2c
// Entry: 80179a2c
// Size: 1156 bytes

/* WARNING: Removing unreachable block (ram,0x80179e80) */
/* WARNING: Removing unreachable block (ram,0x80179e70) */
/* WARNING: Removing unreachable block (ram,0x80179e60) */
/* WARNING: Removing unreachable block (ram,0x80179e68) */
/* WARNING: Removing unreachable block (ram,0x80179e78) */
/* WARNING: Removing unreachable block (ram,0x80179e88) */

undefined4 FUN_80179a2c(int param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  int iVar6;
  bool bVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f26;
  double dVar11;
  undefined8 in_f27;
  double dVar12;
  undefined8 in_f28;
  double dVar13;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  float local_88;
  float local_84;
  float local_80;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
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
  iVar6 = *(int *)(param_1 + 0xb8);
  dVar12 = (double)FLOAT_803e36b0;
  FUN_80035f20();
  fVar2 = *(float *)(iVar6 + 0x2b4) - *(float *)(param_1 + 0x10);
  if (fVar2 < FLOAT_803e369c) {
    fVar2 = -fVar2;
  }
  fVar3 = *(float *)(iVar6 + 0x2b0) - *(float *)(param_1 + 0xc);
  if (fVar3 < FLOAT_803e369c) {
    fVar3 = -fVar3;
  }
  fVar4 = *(float *)(iVar6 + 0x2b8) - *(float *)(param_1 + 0x14);
  if (fVar4 < FLOAT_803e369c) {
    fVar4 = -fVar4;
  }
  bVar7 = fVar4 + fVar3 + fVar2 < FLOAT_803e36b4;
  if (!bVar7) {
    FUN_80247754(param_1 + 0xc,iVar6 + 0x2b0,&local_88);
    dVar12 = (double)FLOAT_803e36b0;
  }
  if (*(float *)(iVar6 + 0x1b4) <= FLOAT_803e369c) {
    fVar2 = *(float *)(iVar6 + 0x2c0);
    if (fVar2 != FLOAT_803e369c) {
      if (*(float *)(param_1 + 0x10) <= fVar2) {
        *(float *)(iVar6 + 0x2c4) = fVar2 - *(float *)(param_1 + 0x10);
        bVar1 = true;
        goto LAB_80179b88;
      }
      *(float *)(iVar6 + 0x2c0) = FLOAT_803e369c;
    }
    bVar1 = false;
  }
  else {
    *(undefined4 *)(iVar6 + 0x2c0) = *(undefined4 *)(iVar6 + 0x1bc);
    *(undefined4 *)(iVar6 + 0x2c4) = *(undefined4 *)(iVar6 + 0x1b4);
    bVar1 = true;
  }
LAB_80179b88:
  fVar2 = FLOAT_803e36b8;
  if (bVar1) {
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e36b8;
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar2;
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar2;
    *(float *)(param_1 + 0x28) = FLOAT_803e36bc * FLOAT_803db414 + *(float *)(param_1 + 0x28);
    FUN_8007d6dc((double)*(float *)(param_1 + 0x28),(double)*(float *)(iVar6 + 0x2c4),
                 s_8yvel__f__depth__f_80320f73 + 1);
    if (((*(float *)(param_1 + 0x28) < FLOAT_803e36c0) &&
        (FLOAT_803e36c4 < *(float *)(param_1 + 0x28))) &&
       (*(float *)(iVar6 + 0x2c4) < FLOAT_803e36a0)) {
      uVar5 = 1;
      goto LAB_80179e60;
    }
  }
  else if (bVar7) {
    *(float *)(param_1 + 0x28) = -(FLOAT_803e36c8 * FLOAT_803db414 - *(float *)(param_1 + 0x28));
  }
  FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar6);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar6);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar6);
  bVar1 = *(char *)(iVar6 + 0x261) != '\0';
  if (bVar1) {
    local_88 = *(float *)(iVar6 + 0x68);
    local_84 = *(float *)(iVar6 + 0x6c);
    local_80 = *(float *)(iVar6 + 0x70);
  }
  if (bVar1 || !bVar7) {
    FUN_80247794(&local_88,&local_88);
    dVar15 = -(double)*(float *)(param_1 + 0x24);
    dVar14 = -(double)*(float *)(param_1 + 0x28);
    dVar13 = -(double)*(float *)(param_1 + 0x2c);
    dVar10 = (double)FUN_802931a0((double)(float)(dVar13 * dVar13 +
                                                 (double)(float)(dVar15 * dVar15 +
                                                                (double)(float)(dVar14 * dVar14))));
    if ((double)FLOAT_803e36cc < dVar10) {
      FUN_8000bb18(param_1,0x16c);
    }
    if ((double)FLOAT_803e369c != dVar10) {
      dVar9 = (double)(float)((double)FLOAT_803e36a0 / dVar10);
      dVar15 = (double)(float)(dVar15 * dVar9);
      dVar14 = (double)(float)(dVar14 * dVar9);
      dVar13 = (double)(float)(dVar13 * dVar9);
    }
    dVar11 = (double)(FLOAT_803e36d0 *
                     (float)(dVar13 * (double)local_80 +
                            (double)(float)(dVar15 * (double)local_88 +
                                           (double)(float)(dVar14 * (double)local_84))));
    FUN_80137948(dVar11,s__dot__f_80320f88);
    dVar9 = (double)FLOAT_803e369c;
    if (dVar9 < dVar11) {
      *(float *)(param_1 + 0x24) = (float)((double)local_88 * dVar11);
      *(float *)(param_1 + 0x28) = (float)((double)local_84 * dVar11);
      *(float *)(param_1 + 0x2c) = (float)((double)local_80 * dVar11);
      *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) - dVar15);
      *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) - dVar14);
      *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) - dVar13);
      if ((((double)*(float *)(iVar6 + 0x2c0) == dVar9) && (dVar10 < (double)FLOAT_803e36d4)) &&
         (*(char *)(iVar6 + 0x261) != '\0')) {
        uVar5 = 2;
        goto LAB_80179e60;
      }
      FUN_80247778((double)(float)(dVar10 * dVar12),param_1 + 0x24,param_1 + 0x24);
    }
  }
  if (!bVar7) {
    *(float *)(param_1 + 0x28) = -(FLOAT_803e36c8 * FLOAT_803db414 - *(float *)(param_1 + 0x28));
  }
  FUN_8002a5dc(param_1);
  *(undefined4 *)(iVar6 + 0x2b0) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar6 + 0x2b4) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar6 + 0x2b8) = *(undefined4 *)(param_1 + 0x14);
  uVar5 = 3;
LAB_80179e60:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  __psq_l0(auStack88,uVar8);
  __psq_l1(auStack88,uVar8);
  return uVar5;
}

