// Function: FUN_8010fa84
// Entry: 8010fa84
// Size: 360 bytes

void FUN_8010fa84(short *param_1)

{
  int iVar1;
  double dVar2;
  
  iVar1 = FUN_800395d8(*DAT_803dd5a0,0);
  dVar2 = DOUBLE_803e1af8;
  if (*DAT_803dd5a0 != (short *)0x0) {
    *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                   DOUBLE_803e1af8) +
                           (float)((double)CONCAT44(0x43300000,
                                                    (int)(short)(((-0x8000 - **DAT_803dd5a0) -
                                                                 *(short *)(iVar1 + 2)) - *param_1)
                                                    ^ 0x80000000) - DOUBLE_803e1af8) /
                           FLOAT_803e1ae0);
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e1ae8 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   -(int)*param_1 ^ 0x80000000) -
                                                 dVar2)) / FLOAT_803e1aec));
    *(float *)(param_1 + 6) =
         -(float)((double)FLOAT_803e1ae4 * dVar2 - (double)*(float *)(*DAT_803dd5a0 + 6));
    *(float *)(param_1 + 8) = FLOAT_803e1af0 + *(float *)(*DAT_803dd5a0 + 8);
    dVar2 = (double)FUN_80294204((double)((FLOAT_803e1ae8 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   -(int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e1af8)) / FLOAT_803e1aec));
    *(float *)(param_1 + 10) =
         -(float)((double)FLOAT_803e1ae4 * dVar2 - (double)*(float *)(*DAT_803dd5a0 + 10));
  }
  return;
}

