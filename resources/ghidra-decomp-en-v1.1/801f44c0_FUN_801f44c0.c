// Function: FUN_801f44c0
// Entry: 801f44c0
// Size: 136 bytes

void FUN_801f44c0(undefined2 *param_1,int param_2)

{
  float *pfVar1;
  
  *param_1 = 0;
  pfVar1 = *(float **)(param_1 + 0x5c);
  *pfVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x18) << 2 ^ 0x80000000) -
                   DOUBLE_803e6b00);
  *(undefined2 *)(pfVar1 + 1) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(pfVar1 + 2) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(pfVar1 + 3) = 0;
  if (*(short *)(pfVar1 + 2) < 1) {
    *(int *)(param_1 + 0x7a) = (int)*(short *)(pfVar1 + 2);
  }
  else {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  pfVar1[4] = *(float *)(param_1 + 6);
  pfVar1[5] = *(float *)(param_1 + 8);
  pfVar1[6] = *(float *)(param_1 + 10);
  return;
}

