// Function: FUN_8014ee8c
// Entry: 8014ee8c
// Size: 856 bytes

void FUN_8014ee8c(short *param_1,int *param_2)

{
  float fVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *param_2;
  iVar2 = FUN_80010320((double)(float)param_2[2],iVar4);
  if ((((iVar2 != 0) || (*(int *)(iVar4 + 0x10) != DAT_803dda60)) &&
      (cVar3 = (**(code **)(*DAT_803dca9c + 0x90))(iVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e2678,*param_2,param_1,&DAT_803dbc78,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 7) = *(byte *)(param_2 + 7) & 0xfe;
  }
  fVar1 = FLOAT_803e267c;
  DAT_803dda60 = *(undefined4 *)(iVar4 + 0x10);
  if ((*(byte *)(param_2 + 7) & 2) == 0) {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e267c * (*(float *)(iVar4 + 0x68) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * (*(float *)(iVar4 + 0x6c) - *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(iVar4 + 0x70) - *(float *)(param_1 + 10)) + *(float *)(param_1 + 0x16);
  }
  else {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e267c * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * ((FLOAT_803e2680 + *(float *)(param_2[1] + 0x10)) - *(float *)(param_1 + 8)) +
         *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 10)) +
         *(float *)(param_1 + 0x16);
  }
  fVar1 = FLOAT_803e2684;
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e2684;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar1;
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar1;
  if (FLOAT_803e2688 < *(float *)(param_1 + 0x12)) {
    *(float *)(param_1 + 0x12) = FLOAT_803e2688;
  }
  if (FLOAT_803e2688 < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = FLOAT_803e2688;
  }
  if (FLOAT_803e2688 < *(float *)(param_1 + 0x16)) {
    *(float *)(param_1 + 0x16) = FLOAT_803e2688;
  }
  if (*(float *)(param_1 + 0x12) < FLOAT_803e268c) {
    *(float *)(param_1 + 0x12) = FLOAT_803e268c;
  }
  if (*(float *)(param_1 + 0x14) < FLOAT_803e268c) {
    *(float *)(param_1 + 0x14) = FLOAT_803e268c;
  }
  if (*(float *)(param_1 + 0x16) < FLOAT_803e268c) {
    *(float *)(param_1 + 0x16) = FLOAT_803e268c;
  }
  FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
  *(short *)((int)param_2 + 0x1e) =
       *(short *)((int)param_2 + 0x1e) + (short)(int)(FLOAT_803e2690 * FLOAT_803db414);
  *(short *)(param_2 + 8) = *(short *)(param_2 + 8) + (short)(int)(FLOAT_803e2694 * FLOAT_803db414);
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e26a0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)((int)param_2 + 0x1e
                                                                                ) ^ 0x80000000) -
                                               DOUBLE_803e26a8)) / FLOAT_803e26a4));
  *param_1 = *param_1 + (short)(int)(FLOAT_803e2698 * (float)((double)FLOAT_803e269c * dVar5));
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e26a0 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 8) ^
                                                                 0x80000000) - DOUBLE_803e26a8)) /
                                       FLOAT_803e26a4));
  param_1[2] = param_1[2] + (short)(int)(FLOAT_803e2698 * (float)((double)FLOAT_803e269c * dVar5));
  return;
}

