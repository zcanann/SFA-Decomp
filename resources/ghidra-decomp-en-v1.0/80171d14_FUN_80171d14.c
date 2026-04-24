// Function: FUN_80171d14
// Entry: 80171d14
// Size: 92 bytes

void FUN_80171d14(double param_1,double param_2,double param_3,int param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(iVar1 + 0x24) = (float)param_1;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(iVar1 + 0x28) = (float)param_2;
  *(float *)(param_4 + 0x14) = (float)param_3;
  *(float *)(iVar1 + 0x2c) = (float)param_3;
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar1 + 0x10));
  if (iVar1 == 0) {
    FUN_800e8370(param_4);
  }
  return;
}

