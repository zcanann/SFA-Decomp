// Function: FUN_801b4294
// Entry: 801b4294
// Size: 252 bytes

void FUN_801b4294(undefined2 *param_1,int param_2)

{
  float *pfVar1;
  double dVar2;
  
  FUN_800372f8((int)param_1,0x13);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar2 = (double)FUN_802945e0();
  *pfVar1 = (float)dVar2;
  pfVar1[1] = FLOAT_803e55a0;
  dVar2 = (double)FUN_80294964();
  pfVar1[2] = (float)dVar2;
  pfVar1[3] = -(pfVar1[2] * *(float *)(param_1 + 10) +
               *pfVar1 * *(float *)(param_1 + 6) + pfVar1[1] * *(float *)(param_1 + 8));
  *(undefined4 *)(param_1 + 0x7c) = 1;
  return;
}

