// Function: FUN_80110cb0
// Entry: 80110cb0
// Size: 268 bytes

void FUN_80110cb0(undefined2 *param_1)

{
  short *psVar1;
  double dVar2;
  
  psVar1 = *(short **)(param_1 + 0x52);
  *DAT_803dd5c8 = -(FLOAT_803e1b78 * FLOAT_803db414 - *DAT_803dd5c8);
  if (*DAT_803dd5c8 < FLOAT_803e1b7c) {
    *DAT_803dd5c8 = FLOAT_803e1b7c;
  }
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803e1b84 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*psVar1 ^ 0x80000000) -
                                               DOUBLE_803e1b90)) / FLOAT_803e1b88));
  *(float *)(param_1 + 6) =
       -(float)((double)FLOAT_803e1b80 * dVar2 - (double)*(float *)(psVar1 + 0xc));
  *(float *)(param_1 + 8) = DAT_803dd5c8[1];
  dVar2 = (double)FUN_80294204((double)((FLOAT_803e1b84 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*psVar1 ^ 0x80000000) -
                                               DOUBLE_803e1b90)) / FLOAT_803e1b88));
  *(float *)(param_1 + 10) =
       -(float)((double)FLOAT_803e1b80 * dVar2 - (double)*(float *)(psVar1 + 0x10));
  *param_1 = 0;
  param_1[1] = 0xc000;
  param_1[2] = 0;
  return;
}

