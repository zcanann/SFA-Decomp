// Function: FUN_801ed20c
// Entry: 801ed20c
// Size: 100 bytes

double FUN_801ed20c(int param_1,undefined4 *param_2)

{
  int iVar1;
  double dVar2;
  double dVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = FLOAT_803e6850;
  dVar2 = FUN_80293900((double)(*(float *)(iVar1 + 0x49c) * *(float *)(iVar1 + 0x49c) +
                               *(float *)(iVar1 + 0x494) * *(float *)(iVar1 + 0x494) +
                               *(float *)(iVar1 + 0x498) * *(float *)(iVar1 + 0x498)));
  dVar3 = (double)(float)(dVar2 * (double)FLOAT_803e6840);
  if ((double)FLOAT_803e6784 < (double)(float)(dVar2 * (double)FLOAT_803e6840)) {
    dVar3 = (double)FLOAT_803e6784;
  }
  return dVar3;
}

