// Function: FUN_801ecbd4
// Entry: 801ecbd4
// Size: 100 bytes

double FUN_801ecbd4(int param_1,float *param_2)

{
  int iVar1;
  double dVar2;
  double dVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = FLOAT_803e5bb8;
  dVar2 = (double)FUN_802931a0((double)(*(float *)(iVar1 + 0x49c) * *(float *)(iVar1 + 0x49c) +
                                       *(float *)(iVar1 + 0x494) * *(float *)(iVar1 + 0x494) +
                                       *(float *)(iVar1 + 0x498) * *(float *)(iVar1 + 0x498)));
  dVar3 = (double)(float)(dVar2 * (double)FLOAT_803e5ba8);
  if ((double)FLOAT_803e5aec < (double)(float)(dVar2 * (double)FLOAT_803e5ba8)) {
    dVar3 = (double)FLOAT_803e5aec;
  }
  return dVar3;
}

