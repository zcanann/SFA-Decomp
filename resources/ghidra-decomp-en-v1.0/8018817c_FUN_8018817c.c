// Function: FUN_8018817c
// Entry: 8018817c
// Size: 200 bytes

void FUN_8018817c(undefined2 *param_1,int param_2)

{
  int iVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)((int)pfVar2 + 6) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar2 + 1) = *(undefined2 *)(param_2 + 0x1e);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e3b60);
  param_1[0x58] = param_1[0x58] | 0x6000;
  *(undefined **)(param_1 + 0x5e) = &LAB_80187f30;
  *(float *)(param_1 + 8) = *(float *)(param_2 + 0xc) + *pfVar2;
  FUN_8002b884(param_1,(int)*(char *)(param_2 + 0x19));
  *(undefined *)(pfVar2 + 2) = 0;
  iVar1 = FUN_8001ffb4((int)*(short *)((int)pfVar2 + 6));
  if (iVar1 == 0) {
    *(undefined *)((int)pfVar2 + 9) = 1;
  }
  return;
}

