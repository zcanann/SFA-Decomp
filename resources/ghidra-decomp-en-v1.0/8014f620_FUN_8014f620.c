// Function: FUN_8014f620
// Entry: 8014f620
// Size: 864 bytes

void FUN_8014f620(int param_1,int *param_2)

{
  float fVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *param_2;
  *(short *)((int)param_2 + 0x26) =
       *(short *)((int)param_2 + 0x26) + (short)(int)(FLOAT_803e26d0 * FLOAT_803db414);
  *(short *)(param_2 + 10) =
       *(short *)(param_2 + 10) + (short)(int)(FLOAT_803e26d4 * FLOAT_803db414);
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e26dc *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)((int)param_2 + 0x26
                                                                                ) ^ 0x80000000) -
                                               DOUBLE_803e2700)) / FLOAT_803e26e0));
  iVar2 = FUN_80010320((double)((float)param_2[2] * (float)((double)FLOAT_803e26d8 + dVar5)),iVar4);
  if ((((iVar2 != 0) || (*(int *)(iVar4 + 0x10) != DAT_803dda68)) &&
      (cVar3 = (**(code **)(*DAT_803dca9c + 0x90))(iVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e26e4,*param_2,param_1,&DAT_803dbc80,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 9) = *(byte *)(param_2 + 9) & 0xfe;
  }
  DAT_803dda68 = *(undefined4 *)(iVar4 + 0x10);
  if ((*(byte *)(param_2 + 9) & 2) == 0) {
    *(float *)(param_1 + 0x24) =
         FLOAT_803e26e8 * (*(float *)(iVar4 + 0x68) - *(float *)(param_1 + 0xc)) +
         *(float *)(param_1 + 0x24);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e26dc *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_2 + 10) ^
                                                                   0x80000000) - DOUBLE_803e2700)) /
                                         FLOAT_803e26e0));
    fVar1 = FLOAT_803e26e8;
    *(float *)(param_1 + 0x28) =
         FLOAT_803e26e8 *
         ((float)((double)FLOAT_803e26f0 * dVar5 + (double)*(float *)(iVar4 + 0x6c)) -
         *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x2c) =
         fVar1 * (*(float *)(iVar4 + 0x70) - *(float *)(param_1 + 0x14)) +
         *(float *)(param_1 + 0x2c);
  }
  else {
    *(float *)(param_1 + 0x24) =
         FLOAT_803e26e8 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 0xc)) +
         *(float *)(param_1 + 0x24);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e26dc *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_2 + 10) ^
                                                                   0x80000000) - DOUBLE_803e2700)) /
                                         FLOAT_803e26e0));
    fVar1 = FLOAT_803e26e8;
    *(float *)(param_1 + 0x28) =
         FLOAT_803e26e8 *
         ((float)((double)FLOAT_803e26f0 * dVar5 +
                 (double)(FLOAT_803e26ec + *(float *)(param_2[1] + 0x10))) -
         *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x2c) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 0x14)) +
         *(float *)(param_1 + 0x2c);
  }
  fVar1 = FLOAT_803e26f4;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e26f4;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  if (FLOAT_803e26f8 < *(float *)(param_1 + 0x24)) {
    *(float *)(param_1 + 0x24) = FLOAT_803e26f8;
  }
  if (FLOAT_803e26f8 < *(float *)(param_1 + 0x28)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e26f8;
  }
  if (FLOAT_803e26f8 < *(float *)(param_1 + 0x2c)) {
    *(float *)(param_1 + 0x2c) = FLOAT_803e26f8;
  }
  if (*(float *)(param_1 + 0x24) < FLOAT_803e26fc) {
    *(float *)(param_1 + 0x24) = FLOAT_803e26fc;
  }
  if (*(float *)(param_1 + 0x28) < FLOAT_803e26fc) {
    *(float *)(param_1 + 0x28) = FLOAT_803e26fc;
  }
  if (*(float *)(param_1 + 0x2c) < FLOAT_803e26fc) {
    *(float *)(param_1 + 0x2c) = FLOAT_803e26fc;
  }
  FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
  return;
}

