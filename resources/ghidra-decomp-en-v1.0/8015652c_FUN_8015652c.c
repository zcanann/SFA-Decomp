// Function: FUN_8015652c
// Entry: 8015652c
// Size: 892 bytes

void FUN_8015652c(int param_1,int *param_2)

{
  float fVar1;
  uint uVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *param_2;
  iVar4 = *(int *)(param_1 + 0x4c);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
  FUN_80035df4(param_1,10,1,0);
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    FUN_8000bb18(param_1,0x261);
  }
  param_2[0xca] = (int)((float)param_2[0xca] - FLOAT_803db414);
  if ((float)param_2[0xca] <= FLOAT_803e2a98) {
    if ((param_2[0xb7] & 0x600U) == 0) {
      uVar2 = FUN_800221a0(600,0x352);
      param_2[0xca] =
           (int)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2aa0);
    }
    else {
      uVar2 = FUN_800221a0(0x96,0xfa);
      param_2[0xca] =
           (int)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2aa0);
    }
    FUN_8000bb18(param_1,0x262);
  }
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    FUN_80030334((double)FLOAT_803e2a98,param_1,0,*(undefined *)((int)param_2 + 0x323));
  }
  fVar1 = FLOAT_803e2a98;
  if ((float)param_2[0xc9] <= FLOAT_803e2a98) {
    param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
  }
  else {
    param_2[0xc9] = (int)((float)param_2[0xc9] - FLOAT_803db414);
    if ((float)param_2[0xc9] <= fVar1) {
      param_2[0xc9] = (int)fVar1;
    }
  }
  if ((param_2[0xb7] & 0x2000U) == 0) {
    if ((param_2[0xb7] & 0x8000000U) == 0) {
      dVar6 = (double)FUN_8014cb54((double)*(float *)(iVar4 + 8),(double)*(float *)(iVar4 + 0xc),
                                   (double)*(float *)(iVar4 + 0x10),(double)FLOAT_803e2abc,
                                   (double)FLOAT_803e2ac0,(double)FLOAT_803e2ac4,
                                   (double)(float)param_2[0xc1],param_1);
    }
    else {
      dVar6 = (double)FLOAT_803e2abc;
    }
  }
  else {
    iVar4 = FUN_80010320((double)(float)param_2[0xbf],iVar5);
    if ((((iVar4 != 0) || (*(int *)(iVar5 + 0x10) != 0)) &&
        (cVar3 = (**(code **)(*DAT_803dca9c + 0x90))(iVar5), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e2ae4,*param_2,param_1,&DAT_803dbcd8,0xffffffff),
       cVar3 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    if ((param_2[0xb7] & 0x8000000U) == 0) {
      dVar6 = (double)FUN_8014cb54((double)*(float *)(iVar5 + 0x68),(double)*(float *)(iVar5 + 0x6c)
                                   ,(double)*(float *)(iVar5 + 0x70),(double)FLOAT_803e2abc,
                                   (double)FLOAT_803e2ac0,(double)FLOAT_803e2ac4,
                                   (double)(float)param_2[0xc1],param_1);
    }
    else {
      dVar6 = (double)FLOAT_803e2abc;
    }
  }
  if ((((double)FLOAT_803e2a98 < dVar6) && (*(float *)(param_1 + 0x28) < FLOAT_803e2ac8)) ||
     ((param_2[0xb7] & 0x8000000U) != 0)) {
    *(undefined *)((int)param_2 + 0x33a) = 1;
  }
  if ((*(char *)((int)param_2 + 0x33a) == '\0') || (dVar6 <= (double)FLOAT_803e2a98)) {
    *(undefined *)((int)param_2 + 0x33a) = 0;
    if (FLOAT_803e2adc < (float)param_2[0xc2]) {
      param_2[0xc2] = (int)-(FLOAT_803e2ae0 * FLOAT_803db414 - (float)param_2[0xc2]);
    }
  }
  else {
    param_2[0xc2] = (int)FLOAT_803e2acc;
    if (*(short *)(param_2 + 0xac) != 0) {
      *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) + FLOAT_803e2ad0;
    }
    if (FLOAT_803e2ad4 <= *(float *)(param_1 + 0x28)) {
      if (FLOAT_803e2ad8 < *(float *)(param_1 + 0x28)) {
        *(float *)(param_1 + 0x28) = FLOAT_803e2ad8;
      }
    }
    else {
      *(float *)(param_1 + 0x28) = FLOAT_803e2ad4;
    }
  }
  FUN_8014cd1c((double)FLOAT_803e2a98,(double)FLOAT_803e2a98,param_1,param_2,0x2d,0);
  return;
}

