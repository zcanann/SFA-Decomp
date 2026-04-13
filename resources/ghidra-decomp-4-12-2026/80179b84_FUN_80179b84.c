// Function: FUN_80179b84
// Entry: 80179b84
// Size: 152 bytes

void FUN_80179b84(double param_1,double param_2,double param_3,int param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(undefined *)(iVar1 + 0x274) = 3;
  *(float *)(iVar1 + 0x26c) = FLOAT_803e4334;
  *(float *)(param_4 + 0x24) = (float)param_1;
  *(float *)(param_4 + 0x28) = (float)param_2;
  *(float *)(param_4 + 0x2c) = (float)param_3;
  FUN_80036018(param_4);
  FUN_80035f9c(param_4);
  *(undefined *)(iVar1 + 0x25b) = 1;
  *(undefined4 *)(iVar1 + 0x2b0) = *(undefined4 *)(param_4 + 0xc);
  *(undefined4 *)(iVar1 + 0x2b4) = *(undefined4 *)(param_4 + 0x10);
  *(undefined4 *)(iVar1 + 0x2b8) = *(undefined4 *)(param_4 + 0x14);
  (**(code **)(*DAT_803dd728 + 0x20))(param_4,iVar1);
  return;
}

