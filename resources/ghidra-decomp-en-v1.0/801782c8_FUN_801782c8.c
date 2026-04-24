// Function: FUN_801782c8
// Entry: 801782c8
// Size: 112 bytes

void FUN_801782c8(int param_1,int param_2)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  FUN_8017805c(param_1,pfVar1);
  *pfVar1 = FLOAT_803e3638 *
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e3640);
  *(undefined *)((int)pfVar1 + 0x11) = 2;
  return;
}

