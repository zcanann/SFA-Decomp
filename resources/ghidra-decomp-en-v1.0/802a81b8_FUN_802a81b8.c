// Function: FUN_802a81b8
// Entry: 802a81b8
// Size: 408 bytes

void FUN_802a81b8(int param_1,int param_2,float *param_3)

{
  double dVar1;
  
  if (((*(byte *)(param_2 + 0x3f1) >> 5 & 1) == 0) && (*(int *)(param_2 + 0x2d0) == 0)) {
    dVar1 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_2 + 0x478)
                                                                   ^ 0x80000000) - DOUBLE_803e7ec0))
                                         / FLOAT_803e7f98));
    *param_3 = (float)-dVar1;
    param_3[1] = FLOAT_803e7ea4;
    dVar1 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)(param_2 + 0x478)
                                                                   ^ 0x80000000) - DOUBLE_803e7ec0))
                                         / FLOAT_803e7f98));
    param_3[2] = (float)-dVar1;
  }
  else {
    *param_3 = *(float *)(param_1 + 0x24);
    param_3[1] = FLOAT_803e7ea4;
    param_3[2] = *(float *)(param_1 + 0x2c);
    dVar1 = (double)FUN_802477f0(param_3);
    if (dVar1 <= (double)FLOAT_803e7ea4) {
      dVar1 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(short *)(param_2 + 0x478
                                                                                    ) ^ 0x80000000)
                                                   - DOUBLE_803e7ec0)) / FLOAT_803e7f98));
      *param_3 = (float)-dVar1;
      param_3[1] = FLOAT_803e7ea4;
      dVar1 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*(short *)(param_2 + 0x478
                                                                                    ) ^ 0x80000000)
                                                   - DOUBLE_803e7ec0)) / FLOAT_803e7f98));
      param_3[2] = (float)-dVar1;
    }
    else {
      FUN_80247778((double)(float)((double)FLOAT_803e7ee0 / dVar1),param_3,param_3);
    }
  }
  return;
}

