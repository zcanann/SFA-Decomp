// Function: FUN_801721c0
// Entry: 801721c0
// Size: 92 bytes

void FUN_801721c0(double param_1,double param_2,double param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(iVar1 + 0x24) = (float)param_1;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(iVar1 + 0x28) = (float)param_2;
  *(float *)(param_4 + 0x14) = (float)param_3;
  *(float *)(iVar1 + 0x2c) = (float)param_3;
  uVar2 = FUN_80020078((int)*(short *)(iVar1 + 0x10));
  if (uVar2 == 0) {
    FUN_800e85f4(param_4);
  }
  return;
}

