// Function: FUN_8020565c
// Entry: 8020565c
// Size: 152 bytes

void FUN_8020565c(undefined2 *param_1,int param_2)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_8020518c;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(pfVar1 + 1) = 0;
  *(undefined2 *)((int)pfVar1 + 6) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar1 + 2) = *(undefined2 *)(param_2 + 0x1e);
  *pfVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e7048);
  *(char *)(pfVar1 + 3) = (char)*(undefined2 *)(param_2 + 0x1c);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - FLOAT_803e7040;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

