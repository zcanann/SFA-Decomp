// Function: FUN_801a5cb4
// Entry: 801a5cb4
// Size: 224 bytes

void FUN_801a5cb4(int param_1,int param_2,int param_3)

{
  float *pfVar1;
  
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  pfVar1 = *(float **)(param_1 + 0xb8);
  *(float *)(param_1 + 8) =
       (*(float *)(*(int *)(param_1 + 0x50) + 4) *
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x3d) ^ 0x80000000) -
              DOUBLE_803e50a8)) / FLOAT_803e50c0;
  FUN_801a536c(param_1,param_2,param_3,pfVar1);
  if ((((*(short *)(param_2 + 0x20) == 0) && (*(short *)(param_2 + 0x22) == 0)) &&
      (*(short *)(param_2 + 0x24) == 0)) &&
     (((*(short *)(param_2 + 0x26) == 0 && (*(short *)(param_2 + 0x28) == 0)) &&
      (*(short *)(param_2 + 0x2a) == 0)))) {
    *(undefined *)((int)pfVar1 + 0x69) = 0;
  }
  else {
    *(undefined *)((int)pfVar1 + 0x69) = 1;
  }
  return;
}

