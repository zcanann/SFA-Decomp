// Function: FUN_801796bc
// Entry: 801796bc
// Size: 124 bytes

void FUN_801796bc(double param_1,double param_2,double param_3,int param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(undefined *)(iVar1 + 0x274) = 3;
  *(float *)(iVar1 + 0x26c) = FLOAT_803e369c;
  *(float *)(param_4 + 0x24) = (float)param_1;
  *(float *)(param_4 + 0x28) = (float)param_2;
  *(float *)(param_4 + 0x2c) = (float)param_3;
  FUN_80035f20();
  FUN_80035ea4(param_4);
  *(undefined *)(iVar1 + 0x25b) = 1;
  *(undefined4 *)(iVar1 + 0x2b0) = *(undefined4 *)(param_4 + 0xc);
  *(undefined4 *)(iVar1 + 0x2b4) = *(undefined4 *)(param_4 + 0x10);
  *(undefined4 *)(iVar1 + 0x2b8) = *(undefined4 *)(param_4 + 0x14);
  return;
}

