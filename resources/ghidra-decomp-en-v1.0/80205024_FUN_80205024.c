// Function: FUN_80205024
// Entry: 80205024
// Size: 152 bytes

void FUN_80205024(undefined2 *param_1,int param_2)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_80204b54;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(pfVar1 + 1) = 0;
  *(undefined2 *)((int)pfVar1 + 6) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar1 + 2) = *(undefined2 *)(param_2 + 0x1e);
  *pfVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e63b0);
  *(char *)(pfVar1 + 3) = (char)*(undefined2 *)(param_2 + 0x1c);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - FLOAT_803e63a8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

