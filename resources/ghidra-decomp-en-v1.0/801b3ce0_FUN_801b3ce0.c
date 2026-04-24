// Function: FUN_801b3ce0
// Entry: 801b3ce0
// Size: 252 bytes

void FUN_801b3ce0(short *param_1,int param_2)

{
  float *pfVar1;
  double dVar2;
  
  FUN_80037200(param_1,0x13);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803e4914 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e4920)) / FLOAT_803e4918));
  *pfVar1 = (float)dVar2;
  pfVar1[1] = FLOAT_803e4908;
  dVar2 = (double)FUN_80294204((double)((FLOAT_803e4914 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e4920)) / FLOAT_803e4918));
  pfVar1[2] = (float)dVar2;
  pfVar1[3] = -(pfVar1[2] * *(float *)(param_1 + 10) +
               *pfVar1 * *(float *)(param_1 + 6) + pfVar1[1] * *(float *)(param_1 + 8));
  *(undefined4 *)(param_1 + 0x7c) = 1;
  return;
}

